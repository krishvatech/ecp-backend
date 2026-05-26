#!/bin/bash
set -euo pipefail

exec > >(tee -a /var/log/ecp-user-data.log | logger -t ecp-user-data -s 2>/dev/console) 2>&1

echo "[ecp-user-data] Started: $(date)"

install -d -m 0755 /usr/local/bin /etc/systemd/system

cat > /usr/local/bin/ecp-startup.sh <<'SCRIPT'
__ECP_STARTUP_SH__
SCRIPT

chmod 0755 /usr/local/bin/ecp-startup.sh

cat > /etc/systemd/system/ecp-startup.service <<'UNIT'
__ECP_STARTUP_SERVICE__
UNIT

chmod 0644 /etc/systemd/system/ecp-startup.service

echo "[ecp-user-data] Reload systemd and start startup service"
systemctl daemon-reload
systemctl reset-failed ecp-startup.service || true
systemctl enable ecp-startup.service
systemctl start ecp-startup.service

echo "[ecp-user-data] Finished: $(date)"
