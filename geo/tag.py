"""Rebuild indicator_geo from indicators_raw.  Run from /opt/cti (with .env loaded):  python -m geo.tag"""
import os
import sys
from collections import Counter
from datetime import datetime

import psycopg2
from psycopg2.extras import execute_values

from geo import rir, tagging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RIR_FILE = os.path.join(ROOT, "data", "rir", "delegated-afrinic-extended-latest")
REGION_FILE = os.path.join(ROOT, "regions", "east_africa.json")


def main():
    if not os.path.exists(RIR_FILE):
        sys.exit("RIR file missing: run  python -m geo.fetch_rir  first")
    region = tagging.load_region(REGION_FILE)
    with open(RIR_FILE) as f:
        serial, ranges = rir.parse_delegation(f)
    if not ranges:
        sys.exit("No IPv4 ranges parsed from the RIR file; leaving indicator_geo unchanged")
    index = rir.RangeIndex(ranges)
    try:
        rir_date = datetime.strptime(serial, "%Y%m%d").date()
    except (TypeError, ValueError):
        rir_date = None

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT DISTINCT indicator_type, value FROM indicators_raw")
            rows = []
            for itype, value in cur.fetchall():
                for cc, key, method, matched in tagging.tag(itype, value, index, region):
                    rows.append((itype, value, cc, key, method, matched, rir_date))
            cur.execute("DELETE FROM indicator_geo")
            if rows:
                execute_values(
                    cur,
                    "INSERT INTO indicator_geo (indicator_type, value, country_code, region, method, matched, rir_date) VALUES %s",
                    rows,
                )
    finally:
        conn.close()
    summary = Counter((r[3], r[4]) for r in rows)
    print(f"Tagged {len(rows)} indicators using RIR file dated {rir_date}")
    for (key, method), n in sorted(summary.items()):
        print(f"  {key:14} {method:6} {n}")


if __name__ == "__main__":
    main()
