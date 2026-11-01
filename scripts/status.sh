#!/usr/bin/env bash
# One-screen project status. Prints no secrets. Run:  bash /opt/cti/scripts/status.sh
cd "$(dirname "$0")/.." || exit 1
[ -f .env ] && { set -a; . ./.env; set +a; }
echo "== git"
git status -sb | head -5
echo "local: $(git rev-parse --short HEAD)   remote: $(git rev-parse --short origin/main)"
git log --oneline -3
echo ".env tracked by git: $(git ls-files | grep -cE '(^|/)\.env$') (must be 0)"
echo "== secrets in git history (must all be 0)"
for k in ABUSEIPDB_KEY OTX_KEY VT_KEY ABUSECH_AUTH_KEY; do
  v="${!k:-}"
  [ -n "$v" ] && echo "$k: $(git grep -lF -- "$v" $(git rev-list --all) 2>/dev/null | wc -l)"
done
PW=$(grep '^DATABASE_URL=' .env | sed -E 's#^[^:]*://[^:]*:([^@]*)@.*#\1#')
[ -n "$PW" ] && echo "DB password: $(git grep -lF -- "$PW" $(git rev-list --all) 2>/dev/null | wc -l)"
unset PW
echo "== database"
psql "$DATABASE_URL" -X -q -f scripts/status.sql
echo "== cron"
crontab -l 2>/dev/null | grep -v '^#' | cut -c1-70
echo "== tests"
/opt/cti/venv/bin/python -m pytest -q 2>&1 | tail -2
