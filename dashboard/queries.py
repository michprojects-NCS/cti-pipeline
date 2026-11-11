"""Read-only queries for the dashboard, one function per panel.

The dashboard connects as the cti_dash role, which can only SELECT from five
tables. It never uses the full-access DATABASE_URL.
"""
import os

import psycopg2
from dotenv import dotenv_values

ENV_FILE = "/opt/cti/.env"

KPI_SQL = """
SELECT count(*) AS scored,
       coalesce(max(score), 0) AS top_score,
       string_agg(DISTINCT model_version, ', ') AS model,
       max(scored_at) AS scored_at
FROM indicator_scores
"""

VT_SQL = """
SELECT count(*) AS checked
FROM enrichment
WHERE provider = 'virustotal' AND data->>'found' = 'true'
"""

# Every filter is optional: NULL means no filter. All values are passed as
# parameters, never pasted into the text.
TOP_SQL = """
SELECT s.indicator_type, s.value, s.score,
       g.region, g.country_code, g.method,
       o.sources, o.feed_count,
       s.components->'per_source_points' AS per_source,
       s.components->>'virustotal_state' AS vt_state,
       (v.data->>'malicious')::int AS vt_malicious,
       s.components->'multipliers' AS multipliers
FROM indicator_scores s
LEFT JOIN indicator_overlap o
       ON o.indicator_type = s.indicator_type AND o.value = s.value
LEFT JOIN enrichment v
       ON v.indicator_type = s.indicator_type AND v.value = s.value
      AND v.provider = 'virustotal'
LEFT JOIN LATERAL (
    SELECT region, country_code, method FROM indicator_geo
    WHERE indicator_type = s.indicator_type AND value = s.value
    ORDER BY (region = 'east_africa') DESC, method LIMIT 1
) g ON true
WHERE (%(kinds)s::text[] IS NULL OR s.indicator_type = ANY(%(kinds)s::text[]))
  AND s.score >= %(min_score)s
  AND (%(region)s::text IS NULL OR g.region = %(region)s::text)
  AND (%(source)s::text IS NULL OR %(source)s::text = ANY(o.sources))
  AND (%(search)s::text IS NULL OR s.value ILIKE '%%' || %(search)s::text || '%%')
ORDER BY s.score DESC, s.value
LIMIT %(limit)s
"""

DIST_SQL = """
SELECT (score / 10) * 10 AS bucket, count(*) AS n
FROM indicator_scores
GROUP BY 1
ORDER BY 1
"""

TYPES_SQL = """
SELECT indicator_type, count(*) AS n
FROM indicator_scores
GROUP BY 1
ORDER BY n DESC, indicator_type
"""

HEALTH_SQL = """
SELECT DISTINCT ON (source) source, status, started_at, finished_at,
       fetched, saved, left(error, 120) AS error
FROM feed_runs
ORDER BY source, started_at DESC
"""

SOURCES_SQL = """
SELECT DISTINCT unnest(sources) AS source
FROM indicator_overlap
ORDER BY 1
"""

ALL_SQL = [KPI_SQL, VT_SQL, TOP_SQL, DIST_SQL, TYPES_SQL, HEALTH_SQL, SOURCES_SQL]   # the tests check these are read-only


def get_url():
    """The dashboard login only. Reads the one key, so no other secret is loaded."""
    url = os.environ.get("DASH_DATABASE_URL") or dotenv_values(ENV_FILE).get("DASH_DATABASE_URL")
    if not url:
        raise RuntimeError("DASH_DATABASE_URL is not set in .env")
    return url


def connect():
    return psycopg2.connect(get_url())


def run(conn, sql, params=None):
    """Run a query and return a list of dicts."""
    with conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def why(per_source, vt_state, vt_malicious, multipliers):
    """One plain-English line explaining a score, built from the stored breakdown."""
    parts = []
    if per_source:
        best = max(per_source, key=per_source.get)
        parts.append(f"{best} {per_source[best]:g}")
    if vt_state == "flagged":
        parts.append(f"VirusTotal: {vt_malicious} engines" if vt_malicious else "VirusTotal: flagged")
    elif vt_state in ("known, no detections", "never seen by VirusTotal"):
        parts.append(f"VirusTotal: {vt_state}")
    multipliers = multipliers or {}
    fresh = multipliers.get("freshness")
    if fresh is not None and fresh < 1:
        parts.append(f"older sighting x{fresh:g}")
    if multipliers.get("inactive_domain", 1) < 1:
        parts.append("domain no longer resolves")
    return " · ".join(parts)


def like_escape(text):
    """Make user text safe inside an ILIKE pattern: %, _ and backslash lose their special meaning."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def fill_buckets(rows):
    """Score buckets 0-9 ... 90-99 and 100, with zeros where nothing scored."""
    counts = {r["bucket"]: r["n"] for r in rows}
    out = [(f"{b}-{b + 9}", counts.get(b, 0)) for b in range(0, 100, 10)]
    out.append(("100", counts.get(100, 0)))
    return out


def overall_status(health_rows):
    """'ok' only if the latest run of every source succeeded."""
    if not health_rows:
        return "no runs"
    return "ok" if all(r["status"] == "ok" for r in health_rows) else "attention"


def pipeline_health(conn):
    return run(conn, HEALTH_SQL)


def kpis(conn):
    k = run(conn, KPI_SQL)[0]
    k["vt_checked"] = run(conn, VT_SQL)[0]["checked"]
    k["pipeline_status"] = overall_status(pipeline_health(conn))
    return k


def top_indicators(conn, limit=20, kinds=None, min_score=0, source=None, search=None, region=None):
    """The highest-scored indicators, optionally filtered by type, feed, minimum score and text."""
    search = (search or "").strip()[:100]
    params = {
        "limit": max(1, min(int(limit), 200)),
        "kinds": list(kinds) if kinds else None,
        "min_score": max(0, min(int(min_score), 100)),
        "source": source or None,
        "search": like_escape(search) if search else None,
        "region": region or None,
    }
    rows = run(conn, TOP_SQL, params)
    for r in rows:
        r["why"] = why(r.pop("per_source"), r.pop("vt_state"), r.pop("vt_malicious"), r.pop("multipliers"))
    return rows


def source_names(conn):
    return [r["source"] for r in run(conn, SOURCES_SQL)]


def score_distribution(conn):
    return fill_buckets(run(conn, DIST_SQL))


def counts_by_type(conn):
    return run(conn, TYPES_SQL)
