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

CREATE TABLE IF NOT EXISTS feed_runs (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status      TEXT        NOT NULL,     -- ok | error
    fetched     INT,                      -- records the feed returned
    saved       INT,                      -- records that reached the table
    error       TEXT
);

CREATE TABLE IF NOT EXISTS enrichment (
    id             BIGSERIAL PRIMARY KEY,
    indicator_type TEXT        NOT NULL,
    value          TEXT        NOT NULL,
    provider       TEXT        NOT NULL,     -- internetdb, rdap, virustotal, ...
    data           JSONB       NOT NULL,
    enriched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (indicator_type, value, provider)
);
