-- Adds a last-seen time set by the pipeline itself (the feed's own timestamp is kept separately).
-- Existing rows are backfilled with ingested_at; real values accumulate from the next run.
ALTER TABLE indicators_raw ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
UPDATE indicators_raw SET last_seen_at = ingested_at WHERE last_seen_at IS NULL;
ALTER TABLE indicators_raw ALTER COLUMN last_seen_at SET DEFAULT now();
ALTER TABLE indicators_raw ALTER COLUMN last_seen_at SET NOT NULL;
