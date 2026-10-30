"""Enrich IPs with ownership data (ASN, network, country) using RDAP via ipwhois.

Usage: python enrichment/rdap.py [limit]      (default limit: 30)
"""
import os
import sys
import time
from datetime import datetime, timezone

from ipwhois import IPWhois
from psycopg2.extras import Json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "feeds"))
from common import _conn

PROVIDER = "rdap"
TTL_DAYS = 30         # ownership changes slowly
DELAY = 1.0           # RDAP servers rate-limit, so go slowly
MAX_FAILURES = 5

PENDING = """
SELECT value FROM indicators_raw r
WHERE indicator_type = 'IP'
  AND NOT EXISTS (
      SELECT 1 FROM enrichment e
      WHERE e.indicator_type = r.indicator_type AND e.value = r.value
        AND e.provider = %s AND e.enriched_at > now() - make_interval(days => %s))
GROUP BY value
ORDER BY max(timestamp) DESC
LIMIT %s
"""


def lookup(ip):
    """Return the ownership fields we keep. Raises on failure (retry next run)."""
    r = IPWhois(ip).lookup_rdap(inc_nir=False)
    net = r.get("network") or {}
    return {
        "asn": r.get("asn"),
        "asn_description": r.get("asn_description"),
        "asn_country_code": r.get("asn_country_code"),
        "asn_cidr": r.get("asn_cidr"),
        "asn_registry": r.get("asn_registry"),
        "network_name": net.get("name"),
        "network_country": net.get("country"),
    }


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    started = datetime.now(timezone.utc)
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(PENDING, (PROVIDER, TTL_DAYS, limit))
            ips = [row[0] for row in cur.fetchall()]

        done = failed = 0
        for ip in ips:
            try:
                data = lookup(ip)
            except Exception as exc:
                failed += 1
                print(f"[skip] {ip}: {type(exc).__name__}: {str(exc)[:100]}")
                if failed >= MAX_FAILURES:
                    print("Too many failures, stopping.")
                    break
                continue
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO enrichment (indicator_type, value, provider, data)
                       VALUES ('IP', %s, %s, %s)
                       ON CONFLICT (indicator_type, value, provider)
                       DO UPDATE SET data = EXCLUDED.data, enriched_at = now()""",
                    (ip, PROVIDER, Json(data)),
                )
            conn.commit()
            done += 1
            time.sleep(DELAY)

        print(f"RDAP: {len(ips)} IPs checked, {done} stored, {failed} failed")
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
                   VALUES (%s, %s, now(), %s, %s, %s, %s)""",
                ("enrich:rdap", started, "error" if failed else "ok", len(ips), done,
                 f"{failed} lookups failed" if failed else None),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
