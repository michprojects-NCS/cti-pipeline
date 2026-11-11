#!/usr/bin/env bash
# Daily pipeline: feeds -> enrichment -> regional tagging -> scoring.
# Safe to call from both the @reboot and the daily cron entries:
#  - a lock stops two runs from overlapping
#  - feeds are skipped if AbuseIPDB already succeeded in the last 20 hours
#  - each enrichment script skips indicators enriched within its own cache period
cd /opt/cti || exit 1
exec 9>/opt/cti/logs/daily_run.lock
flock -n 9 || { echo "$(date -Is) skip: another run is in progress"; exit 0; }
set -a; . ./.env; set +a
PY=/opt/cti/venv/bin/python

recent=$(psql "$DATABASE_URL" -X -q -t -A -c "SELECT count(*) FROM feed_runs WHERE source='AbuseIPDB' AND status='ok' AND started_at > now() - interval '20 hours'") \
  || { echo "$(date -Is) database not reachable, giving up"; exit 1; }

if [ "${recent:-0}" -gt 0 ]; then
  echo "$(date -Is) skip feeds: already ran in the last 20 hours"
else
  echo "$(date -Is) running feeds"
  $PY /opt/cti/feeds/run_all.py || echo "$(date -Is) some feeds failed (see feed_runs)"
fi

echo "$(date -Is) running enrichment"
$PY /opt/cti/enrichment/internetdb.py 200 || echo "$(date -Is) internetdb step failed"
$PY /opt/cti/enrichment/rdap.py 100       || echo "$(date -Is) rdap step failed"
$PY /opt/cti/enrichment/domains.py 30     || echo "$(date -Is) domains step failed"
$PY /opt/cti/enrichment/vt.py 20          || echo "$(date -Is) virustotal step failed"

echo "$(date -Is) running regional tagging"
if ! find /opt/cti/data/rir -name 'delegated-afrinic-extended-latest' -mmin -1200 2>/dev/null | grep -q .; then
  $PY -m geo.fetch_rir                  || echo "$(date -Is) RIR download failed, using the previous copy"
fi
$PY -m geo.tag                          || echo "$(date -Is) regional tagging failed"

echo "$(date -Is) running scoring"
$PY /opt/cti/scoring/run_scoring.py       || echo "$(date -Is) scoring failed"
echo "$(date -Is) done"
