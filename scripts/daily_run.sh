#!/usr/bin/env bash
# Run all feeds unless AbuseIPDB already succeeded in the last 20 hours.
# Safe to call from both the @reboot and the daily cron entries.
cd /opt/cti || exit 1
set -a; . ./.env; set +a
recent=$(psql "$DATABASE_URL" -X -q -t -A -c "SELECT count(*) FROM feed_runs WHERE source='AbuseIPDB' AND status='ok' AND started_at > now() - interval '20 hours'") \
  || { echo "$(date -Is) database not reachable, giving up"; exit 1; }
if [ "${recent:-0}" -gt 0 ]; then
  echo "$(date -Is) skip: feeds already ran in the last 20 hours"
  exit 0
fi
echo "$(date -Is) running feeds"
/opt/cti/venv/bin/python /opt/cti/feeds/run_all.py
