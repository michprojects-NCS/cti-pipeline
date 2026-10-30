"""Enrich IPs with Shodan InternetDB (free, no key).

Usage: python enrichment/internetdb.py [limit]      (default limit: 50)
"""
import os
import sys
import time
from datetime import datetime, timezone

import requests
from psycopg2.extras import Json

# reuse the database connection and .env loading from feeds/common.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "feeds"))
from common import _conn

PROVIDER = "internetdb"
URL = "https://internetdb.shodan.io/{ip}"
TTL_DAYS = 7          # InternetDB data refreshes weekly, so asking sooner is pointless
DELAY = 0.3           # be polite between calls
MAX_FAILURES = 5      # stop early if something is clearly wrong

# distinct IPs with no fresh enrichment, newest sightings first
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
    """Return the data to store. Raises RuntimeError if the call failed (retry next run)."""
    r = requests.get(URL.format(ip=ip), timeout=15)
    if r.status_code == 200:
        return {"found": True, **r.json()}
    if r.status_code == 404:
        return {"found": False}              # Shodan has nothing on this IP: a valid answer
    raise RuntimeError(f"HTTP {r.status_code}")


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    started = datetime.now(timezone.utc)
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(PENDING, (PROVIDER, TTL_DAYS, limit))
            ips = [row[0] for row in cur.fetchall()]

        found = missing = failed = 0
        for ip in ips:
            try:
                data = lookup(ip)
            except Exception as exc:          # skip this IP; it will be retried next run
                failed += 1
                print(f"[skip] {ip}: {exc}")
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
            conn.commit()                     # keep progress if interrupted
            found += data["found"]
            missing += not data["found"]
            time.sleep(DELAY)

        print(f"InternetDB: {len(ips)} IPs checked, {found} with data, {missing} not found, {failed} failed")
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
                   VALUES (%s, %s, now(), %s, %s, %s, %s)""",
                ("enrich:internetdb", started, "error" if failed else "ok", len(ips), found + missing,
                 f"{failed} lookups failed" if failed else None),
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
