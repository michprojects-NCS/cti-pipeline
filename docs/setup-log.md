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
