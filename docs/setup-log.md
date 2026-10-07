# Setup log

## 2026-10-07: Base system
- Ubuntu Server in VMware, OpenSSH server running
- UFW enabled: default deny incoming, allow outgoing, only OpenSSH (22/tcp) allowed in
- Installed: Git, Python 3, PostgreSQL, Docker
- Git configured with GitHub noreply email; repo initialized at /opt/cti
- GitHub SSH key created and tested (`ssh -T git@github.com` succeeded)
