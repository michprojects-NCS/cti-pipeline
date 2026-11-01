"""Score every indicator and store the result in indicator_scores.

Usage: python scoring/run_scoring.py [--model v1|v2]      (default: v1)
"""
import argparse
import os
import sys
from datetime import datetime, timezone

from psycopg2.extras import Json, execute_values

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "feeds"))
sys.path.insert(0, HERE)
from common import _conn
import score as model_v1
import score_v2 as model_v2

MODELS = {"v1": model_v1, "v2": model_v2}

FACTS_SQL = """
WITH per_source AS (
    SELECT indicator_type, value, source,
           max(confidence) AS conf, max(timestamp) AS last_seen
    FROM indicators_raw
    GROUP BY indicator_type, value, source
), base AS (
    SELECT indicator_type, value,
           max(conf)                      AS max_confidence,
           count(*)                       AS feed_count,
           max(last_seen)                 AS last_seen,
           jsonb_object_agg(source, conf) AS source_conf
    FROM per_source
    GROUP BY indicator_type, value
)
SELECT b.indicator_type, b.value, b.max_confidence, b.feed_count, b.last_seen, b.source_conf,
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


def load_facts(conn):
    """One dict per indicator, ready for score_indicator()."""
    with conn.cursor() as cur:
        cur.execute(FACTS_SQL)
        rows = cur.fetchall()
    return [
        {"indicator_type": kind, "value": value, "max_confidence": conf, "feed_count": feeds,
         "last_seen": last_seen, "source_conf": source_conf, "vt": vt, "dns": dns, "idb": idb}
        for kind, value, conf, feeds, last_seen, source_conf, vt, dns, idb in rows
    ]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(MODELS), default="v1")
    model = MODELS[ap.parse_args(argv).model]

    started = datetime.now(timezone.utc)
    conn = _conn()
    fetched = saved = 0
    status, error = "ok", None
    try:
        facts_list = load_facts(conn)
        fetched = len(facts_list)
        now = datetime.now(timezone.utc)
        out = []
        for facts in facts_list:
            result = model.score_indicator(facts, now)
            out.append((facts["indicator_type"], facts["value"], result["score"],
                        Json(result["components"]), model.MODEL_VERSION))
        with conn.cursor() as cur:
            execute_values(cur, UPSERT_SQL, out, page_size=500)
        saved = len(out)
        conn.commit()
        print(f"Scored {saved} indicators (model {model.MODEL_VERSION}).")
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
