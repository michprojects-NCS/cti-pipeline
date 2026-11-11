-- Regional tags. method 'rir' = IP registered in that country (RIR delegation file);
-- method 'cctld' = domain under that country's national TLD. Neither says where a host physically is.
-- Rebuilt in full by geo/tag.py, so a missing row means "no match".
CREATE TABLE IF NOT EXISTS indicator_geo (
    indicator_type text NOT NULL,
    value          text NOT NULL,
    country_code   char(2) NOT NULL,
    region         text NOT NULL,
    method         text NOT NULL,
    matched        text NOT NULL,
    rir_date       date,
    tagged_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (indicator_type, value, method)
);
CREATE INDEX IF NOT EXISTS idx_geo_region ON indicator_geo (region);
