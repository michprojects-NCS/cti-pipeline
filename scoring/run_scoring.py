"""Score every indicator and store the result in indicator_scores.

Usage: python scoring/run_scoring.py
"""
import os
import sys
from datetime import datetime, timezone

from psycopg2.extras import Json, execute_values

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "feeds"))
sys.path.insert(0, HERE)
from common import _conn
from score import MODEL_VERSION, score_indicator

FACTS_SQL = """
WITH base AS (
    SELECT indicator_type, value,
           max(confidence)          AS max_confidence,
           count(DISTINCT source)   AS feed_count,
           max(timestamp)           AS last_seen
    FROM indicators_raw
    GROUP BY indicator_type, value
)
SELECT b.indicator_type, b.value, b.max_confidence, b.feed_count, b.last_seen,
       vt.data, dns.data, idb.data
FROM base b
LEFT JOIN enrichment vt  ON vt.indicator_type  = b.indicator_type AND vt.value  = b.value
                        AND vt.provider  = 'virustotal'
LEFT JOIN enrichment dns ON dns.indicator_type = b.indicator_type AND dns.value = b.value
                        AND dns.provider = 'dns_whois'
LEFT JOIN enrichment idb ON idb.indicator_type = b.indicator_type AND idb.value = b.value
                        AND idb.provider = 'internetdb'
"""

UPSERT_SQL = """
INSERT INTO indicator_scores (indicator_type, value, score, components, model_version)
VALUES %s
ON CONFLICT (indicator_type, value)
DO UPDATE SET score = EXCLUDED.score, components = EXCLUDED.components,
              model_version = EXCLUDED.model_version, scored_at = now()
"""


def main():
    started = datetime.now(timezone.utc)
    conn = _conn()
    fetched = saved = 0
    status, error = "ok", None
    try:
        with conn.cursor() as cur:
            cur.execute(FACTS_SQL)
            rows = cur.fetchall()
        fetched = len(rows)

        now = datetime.now(timezone.utc)
        out = []
        for kind, value, conf, feeds, last_seen, vt, dns, idb in rows:
            result = score_indicator({
                "indicator_type": kind, "value": value, "max_confidence": conf,
                "feed_count": feeds, "last_seen": last_seen,
                "vt": vt, "dns": dns, "idb": idb,
            }, now)
            out.append((kind, value, result["score"], Json(result["components"]), MODEL_VERSION))

        with conn.cursor() as cur:
            execute_values(cur, UPSERT_SQL, out, page_size=500)
        saved = len(out)
        conn.commit()
        print(f"Scored {saved} indicators (model {MODEL_VERSION}).")
    except Exception as exc:
        conn.rollback()
        status, error = "error", f"{type(exc).__name__}: {str(exc)[:300]}"
        print(f"[ERROR] scoring: {error}")

    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO feed_runs (source, started_at, finished_at, status, fetched, saved, error)
               VALUES (%s, %s, now(), %s, %s, %s, %s)""",
            ("score", started, status, fetched, saved, error),
        )
    conn.commit()
    conn.close()
    return 1 if status == "error" else 0


if __name__ == "__main__":
    sys.exit(main())

