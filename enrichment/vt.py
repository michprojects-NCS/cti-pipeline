"""Enrich the highest-priority indicators with VirusTotal reputation (free Public API).

The free API allows 4 requests per minute and 500 per day, so this script is slow on
purpose and picks the most important indicators first.

Usage: python enrichment/vt.py [limit]      (default limit: 20)
"""
import base64
import os
import sys
import time
from datetime import datetime, timezone

import requests
from psycopg2.extras import Json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "feeds"))
from common import _conn

PROVIDER = "virustotal"
BASE = "https://www.virustotal.com/api/v3/"
TTL_DAYS = 30         # reputation changes, but the quota is tiny
DELAY = 16            # 4 requests per minute = one per 15 seconds; 16 leaves a margin
MAX_FAILURES = 3

# Spend the scarce quota wisely: skip dead domains, then rank by (seen by 2+ feeds),
# highest source confidence, newest sighting.
PENDING = """
SELECT r.indicator_type, r.value
FROM indicators_raw r
WHERE r.indicator_type IN ('IP','DOMAIN','URL','HASH_MD5','HASH_SHA1','HASH_SHA256')
  AND NOT EXISTS (
      SELECT 1 FROM enrichment e
      WHERE e.indicator_type = r.indicator_type AND e.value = r.value
        AND e.provider = %s AND e.enriched_at > now() - make_interval(days => %s))
  AND NOT EXISTS (
      SELECT 1 FROM enrichment d
      WHERE r.indicator_type = 'DOMAIN' AND d.indicator_type = 'DOMAIN' AND d.value = r.value
        AND d.provider = 'dns_whois' AND d.data->>'nxdomain' = 'true')
GROUP BY r.indicator_type, r.value
ORDER BY (count(DISTINCT r.source) > 1) DESC, max(r.confidence) DESC NULLS LAST, max(r.timestamp) DESC
LIMIT %s
"""


class QuotaExceeded(Exception):
    pass


class BadKey(Exception):
    pass


def vt_path(kind, value):
    if kind == "IP":
        return f"ip_addresses/{value}"
    if kind == "DOMAIN":
        return f"domains/{value}"
    if kind.startswith("HASH_"):
        return f"files/{value}"
    if kind == "URL":                                  # URLs are looked up by URL-safe base64, no padding
        return "urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    raise ValueError(f"unsupported type {kind}")


def lookup(kind, value, key):
    r = requests.get(BASE + vt_path(kind, value), headers={"x-apikey": key}, timeout=30)
    if r.status_code == 200:
        attrs = r.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "tags": (attrs.get("tags") or [])[:10],
        }
    if r.status_code == 404:
        return {"found": False}                        # VirusTotal has never seen it
    if r.status_code == 429:
        raise QuotaExceeded()
    if r.status_code in (401, 403):
        raise BadKey(f"VirusTotal rejected the key (HTTP {r.status_code})")
    raise RuntimeError(f"HTTP {r.status_code}")


def main():
    key = os.environ.get("VT_KEY")
    if not key:
        raise SystemExit("VT_KEY is not set in .env")
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    started = datetime.now(timezone.utc)
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(PENDING, (PROVIDER, TTL_DAYS, limit))
            items = cur.fetchall()

        stored = flagged = failed = 0
        for kind, value in items:
            try:
                data = lookup(kind, value, key)
            except QuotaExceeded:
                print("[stop] VirusTotal quota reached (4 per minute or 500 per day). Try again later.")
                break
            except BadKey as exc:
                failed += 1
                print(f"[stop] {exc}")
                break
            except Exception as exc:
                failed += 1
                print(f"[skip] {kind} {value[:40]}: {type(exc).__name__}: {str(exc)[:80]}")
                if failed >= MAX_FAILURES:
                    print("Too many failures, stopping.")
                    break
                continue
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO enrichment (indicator_type, value, provider, data)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (indicator_type, value, provider)
                       DO UPDATE SET data = EXCLUDED.data, enriched_at = now()""",
                    (kind, value, PROVIDER, Json(data)),
                )
            conn.commit()
            stored += 1
            flagged += data.get("malicious", 0) > 0
            time.sleep(DELAY)

        print(f"VirusTotal: {len(items)} selected, {stored} stored, {flagged} flagged by 1+ engines, {failed} failed")
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
                   VALUES (%s, %s, now(), %s, %s, %s, %s)""",
                ("enrich:virustotal", started, "error" if failed else "ok", len(items), stored,
                 f"{failed} failed" if failed else None),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
