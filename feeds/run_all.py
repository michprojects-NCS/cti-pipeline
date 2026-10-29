"""Run every feed. One failing feed must not stop the others.
Every run is logged to the feed_runs table.

Usage:
    python feeds/run_all.py                    # all feeds
    python feeds/run_all.py --only otx         # just one
"""
import argparse
import sys
from datetime import datetime, timezone

import abuseipdb
import otx
import abusech
from common import save, _conn

FEEDS = {
    "abuseipdb": ("AbuseIPDB", abuseipdb.fetch),
    "otx": ("OTX", otx.fetch),
    "feodo": ("Feodo", abusech.fetch_feodo),
    "urlhaus": ("URLhaus", abusech.fetch_urlhaus),
}


def log_run(source, status, started_at, fetched=None, saved=None, error=None):
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
               VALUES (%s, %s, now(), %s, %s, %s, %s)""",
            (source, started_at, status, fetched, saved, error),
        )


def run_feed(key):
    name, fetch = FEEDS[key]
    started = datetime.now(timezone.utc)
    try:
        records = fetch()
        saved = save(records)
        log_run(name, "ok", started, fetched=len(records), saved=saved)
        print(f"[ok]    {name}: fetched {len(records)}, saved {saved}")
        return True
    except Exception as exc:                  # a failure here must not stop the other feeds
        message = f"{type(exc).__name__}: {str(exc)[:300]}"
        print(f"[ERROR] {name}: {message}")
        try:
            log_run(name, "error", started, error=message)
        except Exception as log_exc:          # e.g. the database itself is down
            print(f"        (could not write to feed_runs: {log_exc})")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", choices=list(FEEDS))
    args = ap.parse_args()
    keys = args.only or list(FEEDS)
    results = {k: run_feed(k) for k in keys}
    failed = [k for k, ok in results.items() if not ok]
    print(f"\nDone: {len(keys) - len(failed)} ok, {len(failed)} failed")
    return 1 if failed else 0                 # a non-zero exit code lets cron notice failures


if __name__ == "__main__":
    sys.exit(main())
