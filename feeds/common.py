import os
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json
from dotenv import load_dotenv

load_dotenv("/opt/cti/.env")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize(indicator_type, value, source, timestamp=None, raw=None):
    """Return one indicator in the common format."""
    return {
        "indicator_type": indicator_type,
        "value": str(value).strip(),
        "source": source,
        "timestamp": timestamp or now_iso(),
        "raw": raw,
    }


def _conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def save(records):
    # Remove duplicates inside the batch; Postgres rejects the same
    # conflict target twice in one INSERT.
    unique = {}
    for r in records:
        unique[(r["indicator_type"], r["value"], r["source"])] = r
    if not unique:
        print("No records to save.")
        return 0
    rows = [
        (r["indicator_type"], r["value"], r["source"], r["timestamp"], Json(r.get("raw")))
        for r in unique.values()
    ]
    with _conn() as conn, conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO indicators_raw (indicator_type, value, source, timestamp, raw)
            VALUES %s
            ON CONFLICT (indicator_type, value, source)
            DO UPDATE SET timestamp = EXCLUDED.timestamp, raw = EXCLUDED.raw
        """, rows)
    print(f"Saved {len(rows)} records.")
    return len(rows)


def query(sql, params=None):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()
