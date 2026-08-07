#!/bin/bash
set -euo pipefail

exec > >(tee -a /var/log/ecp-user-data.log | logger -t ecp-user-data -s 2>/dev/console) 2>&1

echo "[ecp-user-data] Started: $(date)"

install -d -m 0755 /usr/local/bin /etc/systemd/system

# Stop the unit inherited from the AMI BEFORE replacing its files. The baked
# unit can still be active (or mid auto-restart), in which case systemd keeps
# executing the OLD script even after the new one is written to disk -- that is
# why deployed changes to ecp-startup.sh appeared to never run.
systemctl stop ecp-startup.service 2>/dev/null || true
systemctl kill --kill-who=all --signal=SIGKILL ecp-startup.service 2>/dev/null || true
systemctl reset-failed ecp-startup.service 2>/dev/null || true

cat > /tmp/ecp-startup.sh <<'SCRIPT'
__ECP_STARTUP_SH__
SCRIPT

cat > /tmp/ecp-startup.service <<'UNIT'
__ECP_STARTUP_SERVICE__
UNIT

# install(1) replaces atomically, so a concurrent reader never sees a half file.
install -m 0755 /tmp/ecp-startup.sh /usr/local/bin/ecp-startup.sh
install -m 0644 /tmp/ecp-startup.service /etc/systemd/system/ecp-startup.service
rm -f /tmp/ecp-startup.sh /tmp/ecp-startup.service

echo "[ecp-user-data] Reload systemd and start startup service"
systemctl daemon-reload
systemctl enable ecp-startup.service

# restart, never start: "start" is a no-op when an inherited unit is still
# considered active (RemainAfterExit=yes made that the normal case).
systemctl restart ecp-startup.service

SERVICE_RESULT=$(systemctl show -p Result --value ecp-startup.service 2>/dev/null || echo unknown)
EXEC_STATUS=$(systemctl show -p ExecMainStatus --value ecp-startup.service 2>/dev/null || echo unknown)
echo "[ecp-user-data] ecp-startup.service SERVICE_RESULT=$SERVICE_RESULT EXEC_STATUS=$EXEC_STATUS"

if [ "$SERVICE_RESULT" != "success" ] || [ "$EXEC_STATUS" != "0" ]; then
  echo "[ecp-user-data] WARNING: ecp-startup.service did not complete cleanly"
  systemctl status ecp-startup.service --no-pager 2>/dev/null || true
fi

echo "[ecp-user-data] Finished: $(date)"
