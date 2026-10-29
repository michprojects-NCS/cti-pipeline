import ipaddress
import os
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json
from dotenv import load_dotenv

load_dotenv("/opt/cti/.env")

# Known-good indicators that must never be stored as threats.
ALLOWLIST = {
    ("IP", "8.8.8.8"), ("IP", "8.8.4.4"),
    ("IP", "1.1.1.1"), ("IP", "1.0.0.1"), ("IP", "9.9.9.9"),
    ("DOMAIN", "google.com"), ("DOMAIN", "microsoft.com"), ("DOMAIN", "cloudflare.com"),
}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(indicator_type, value):
    """Return the cleaned value, or None if this indicator should be dropped."""
    v = str(value).strip()
    if not v:
        return None
    if indicator_type == "IP":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None                      # not a real IP address
        if not ip.is_global:
            return None                      # private, loopback, reserved ranges
        v = str(ip)                          # canonical spelling
        return None if ("IP", v) in ALLOWLIST else v
    if indicator_type == "DOMAIN":
        v = v.lower().rstrip(".")
        parts = v.split(".")
        for i in range(len(parts) - 1):      # mail.google.com is covered by google.com
            if ("DOMAIN", ".".join(parts[i:])) in ALLOWLIST:
                return None
        return v
    if indicator_type.startswith("HASH_"):
        return v.lower()
    return v                                 # URLs keep their case: paths are case-sensitive


def normalize(indicator_type, value, source, timestamp=None, raw=None, confidence=None):
    """Return one indicator in the common format, or None if it should be dropped."""
    value = clean(indicator_type, value)
    if value is None:
        return None
    return {
        "indicator_type": indicator_type,
        "value": value,
        "source": source,
        "timestamp": timestamp or now_iso(),
        "raw": raw,
        "confidence": confidence,
    }


def _conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def save(records):
    total = len(records)
    records = [r for r in records if r is not None]      # drop what clean() rejected
    dropped = total - len(records)
    # Remove duplicates inside the batch; Postgres rejects the same
    # conflict target twice in one INSERT.
    unique = {}
    for r in records:
        unique[(r["indicator_type"], r["value"], r["source"])] = r
    if not unique:
        print(f"No records to save ({dropped} dropped by cleaning).")
        return 0
    rows = [
        (r["indicator_type"], r["value"], r["source"], r["timestamp"],
         Json(r.get("raw")), r.get("confidence"))
        for r in unique.values()
    ]
    with _conn() as conn, conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO indicators_raw (indicator_type, value, source, timestamp, raw, confidence)
            VALUES %s
            ON CONFLICT (indicator_type, value, source)
            DO UPDATE SET timestamp = EXCLUDED.timestamp, raw = EXCLUDED.raw,
                          confidence = EXCLUDED.confidence
        """, rows)
    print(f"Saved {len(rows)} records ({dropped} dropped by cleaning).")
    return len(rows)


def query(sql, params=None):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()
