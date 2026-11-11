-- Read-only role for the dashboard. The password is passed in as the psql
-- variable pw and is never stored in this file:
--   psql -d cti -v pw="..." < sql/dashboard_role.sql
CREATE ROLE cti_dash LOGIN PASSWORD :'pw';
ALTER ROLE cti_dash SET default_transaction_read_only = on;
ALTER ROLE cti_dash SET statement_timeout = '15s';
GRANT CONNECT ON DATABASE cti TO cti_dash;
GRANT USAGE ON SCHEMA public TO cti_dash;
GRANT SELECT ON indicators_raw, enrichment, indicator_scores, feed_runs, indicator_overlap, indicator_geo TO cti_dash;
