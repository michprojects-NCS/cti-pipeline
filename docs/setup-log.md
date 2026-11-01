# Setup log

## 2026-10-07: Base system
- Ubuntu Server in VMware, OpenSSH server running
- UFW enabled: default deny incoming, allow outgoing, only OpenSSH (22/tcp) allowed in
- Installed: Git, Python 3, PostgreSQL, Docker
- Git configured with GitHub noreply email; repo initialized at /opt/cti
- GitHub SSH key created and tested (`ssh -T git@github.com` succeeded)
## SSH hardening
- Created ed25519 login key on the host; public key added to ~/.ssh/authorized_keys
- Password login and root login disabled via /etc/ssh/sshd_config.d/00-hardening.conf
- Verified with `sshd -T` and by confirming password login is refused
- fail2ban installed and enabled
## Python and database
- Python virtual environment at /opt/cti/venv; dependencies pinned in requirements.txt
- PostgreSQL database `cti` owned by user `cti_user`; connection string stored only in .env
- .env created with mode 600 and confirmed ignored by Git
- Verified Python-to-PostgreSQL connection

## Troubleshooting: lost IP after reboot
- Symptom: VM had no IP after reboot, SSH unreachable
- Cause: static netplan config was in a `.yaml.dpkg-backup` file, which netplan ignores
- Fix: copied it to /etc/netplan/01-static.yaml (mode 600), ran `netplan generate` and `netplan apply`
- Verified: IP persisted across a second reboot; UFW, PostgreSQL, fail2ban and Docker active

## 2026-10-29: Feed ingestion (Phase 2)
- Feeds written as functions that return normalized records; `feeds/run_all.py` runs them with failure isolation and logs each run to `feed_runs`
- Cleaning in `feeds/common.py`: public IPs only, allowlist for known-good IPs and domains, canonical casing per indicator type
- Added abuse.ch feeds: Feodo Tracker (botnet C2 IPs) and URLhaus (malware URLs), both using an Auth-Key stored only in `.env`
- Added SQL view `indicator_overlap` (how many feeds reported each indicator); result with 949 indicators: all seen by one feed only
- Added 25 offline pytest tests (cleaning rules, abuse.ch parsers); all pass
- Details, limits and confidence mappings: `docs/feeds.md`

## Troubleshooting: URLhaus HTTP 410
- Symptom: URLhaus feed failed with `HTTP 410 Gone`; Feodo from the same provider worked
- Cause: the old plain-text download address had been retired
- Fix: switched to the authenticated URLhaus API (`/v1/urls/recent/`) using the same Auth-Key
- Verified: `URLhaus: fetched 500, saved 500` and an `ok` row in `feed_runs`

## 2026-10-30: Enrichment (Phase 3)
- Added `enrichment` table keyed by (type, value, provider) with JSONB data and a cache period per provider
- IPs: Shodan InternetDB (ports, vulns) and RDAP ownership (ASN, organisation, country)
- Domains: DNS records and WHOIS registration age; 71 of 80 domains no longer resolve
- VirusTotal enrichment for priority indicators, paced for the free 4 per minute and 500 per day limits
- Added `scripts/status.sh` for a one-screen health check
- Details, limits and findings: `docs/enrichment.md`
## 2026-11-01: Enrichment tests, scoring v1 and the daily job
- Added 32 offline tests for the enrichment lookups (InternetDB, RDAP, DNS, WHOIS, VirusTotal), using fake responses; 75 tests pass in total
- Added scoring v1: `scoring/score.py` (pure function, weights at the top), `scoring/run_scoring.py` and the `indicator_scores` table; 1796 indicators scored
- Rewrote `scripts/daily_run.sh` to run feeds, then enrichment, then scoring, with a lock so the @reboot and daily runs cannot overlap
- Tested the schedule by moving the cron time a few minutes ahead; cron started the job without me
- Findings: scores range from the 10s up to 75 with many ties; VirusTotal flagged 20 of 20 priority indicators because the highest-confidence indicators are checked first

## Troubleshooting: one RDAP lookup failed
- Symptom: `enrich:rdap` logged `error` although 85 of 86 IPs were stored
- Cause: one APNIC RDAP request failed (server error)
- Result: the failed IP was not stored, so the next run picked it up again and stored it; failed lookups are retried automatically
