-- How many different feeds reported each indicator.
CREATE OR REPLACE VIEW indicator_overlap AS
SELECT
    indicator_type,
    value,
    count(DISTINCT source)                AS feed_count,
    array_agg(DISTINCT source ORDER BY source) AS sources,
    max(confidence)                       AS max_confidence
FROM indicators_raw
GROUP BY indicator_type, value;
