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
