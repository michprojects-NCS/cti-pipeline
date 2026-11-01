\pset pager off
SELECT source, count(*) AS rows FROM indicators_raw GROUP BY 1 ORDER BY 1;
SELECT provider, indicator_type, count(*) AS rows FROM enrichment GROUP BY 1, 2 ORDER BY 1, 2;
SELECT DISTINCT ON (source) source, status, to_char(started_at, 'MM-DD HH24:MI') AS last_run, fetched, saved
FROM feed_runs ORDER BY source, started_at DESC;
