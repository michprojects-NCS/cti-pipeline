-- One row per indicator: the final score plus how it was built.
CREATE TABLE IF NOT EXISTS indicator_scores (
    indicator_type text        NOT NULL,
    value          text        NOT NULL,
    score          integer     NOT NULL CHECK (score BETWEEN 0 AND 100),
    components     jsonb       NOT NULL,
    model_version  text        NOT NULL,
    scored_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (indicator_type, value)
);

CREATE INDEX IF NOT EXISTS idx_scores_score ON indicator_scores (score DESC);
