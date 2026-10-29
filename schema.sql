CREATE TABLE IF NOT EXISTS indicators_raw (
    id             BIGSERIAL PRIMARY KEY,
    indicator_type TEXT        NOT NULL,   -- IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256
    value          TEXT        NOT NULL,
    source         TEXT        NOT NULL,
    timestamp      TIMESTAMPTZ NOT NULL,
    raw            JSONB,
    confidence     INT,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (indicator_type, value, source)
);
CREATE INDEX IF NOT EXISTS idx_ind_value  ON indicators_raw (value);
CREATE INDEX IF NOT EXISTS idx_ind_source ON indicators_raw (source);
