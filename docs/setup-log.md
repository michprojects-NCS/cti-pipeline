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
