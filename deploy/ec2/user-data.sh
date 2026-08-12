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

# The AMI was snapshotted from a running machine, so containers are frozen into
# the disk image -- an old ecp-backend plus the saleor-platform-* stack, all
# carrying restart=unless-stopped. Docker revives them the moment the daemon
# starts, and the old backend seizes 0.0.0.0:8000 before the real one can bind.
# That is the root cause of "Address already in use" and every orphaned-daphne
# failure that followed.
#
# Remove everything inherited before anything can compete for the port. Nothing
# of value is lost: ecp-backend and ecp-celery-worker are recreated from their
# ECR image by ecp-startup.sh below, and celery-beat is assigned by the deploy.
# cloud-init runs user-data once per instance, so this never touches a reboot --
# on reboot Docker revives the real containers exactly as it does today.
if command -v docker >/dev/null 2>&1; then
  echo "[ecp-user-data] Waiting for Docker, then removing AMI-inherited containers"
  for _ in $(seq 1 30); do
    docker info >/dev/null 2>&1 && break
    sleep 2
  done

  # Clear restart policies first so Docker cannot revive one mid-removal.
  for c in $(docker ps -aq 2>/dev/null); do
    docker update --restart=no "$c" >/dev/null 2>&1 || true
  done
  for c in $(docker ps -aq 2>/dev/null); do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done

  echo "[ecp-user-data] Containers after cleanup:"
  docker ps -a --format '  {{.Names}} {{.Status}}' 2>/dev/null || true
fi

# Removing Docker containers is not sufficient. A task whose shim was orphaned
# no longer appears in "docker ps -a" -- dockerd has forgotten it -- yet
# containerd still runs it and it keeps 0.0.0.0:8000 bound. That is exactly what
# this log showed: zero containers, port still held. Clear the containerd layer
# too. Safe here because this runs once per instance and every container is
# recreated from ECR immediately below.
if command -v ctr >/dev/null 2>&1; then
  echo "[ecp-user-data] Removing orphaned containerd tasks"
  for t in $(ctr -n moby tasks ls 2>/dev/null | awk 'NR>1 {print $1}'); do
    echo "[ecp-user-data]   task $t"
    ctr -n moby tasks kill -s SIGKILL "$t" >/dev/null 2>&1 || true
    ctr -n moby tasks rm -f "$t" >/dev/null 2>&1 || true
  done
  for c in $(ctr -n moby containers ls 2>/dev/null | awk 'NR>1 {print $1}'); do
    ctr -n moby containers rm "$c" >/dev/null 2>&1 || true
  done
fi

# Do not merely warn if port 8000 is still taken -- the next step starts the
# backend and it will fail to bind. Escalate until the port is genuinely free.
for attempt in 1 2 3 4 5; do
  PORT_PID=$(ss -lntpH 2>/dev/null | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  if [ -z "$PORT_PID" ]; then
    echo "[ecp-user-data] port 8000 free"
    break
  fi

  echo "[ecp-user-data] port 8000 held by PID=$PORT_PID (attempt $attempt): $(ps -p "$PORT_PID" -o args= 2>/dev/null || true)"

  # A frozen cgroup queues SIGKILL forever, so thaw before killing the group.
  #
  # ONLY ever mass-kill a container scope. This cgroup path is whatever the PID
  # happens to live in, and for a process dockerd owns directly that is
  # system.slice/docker.service -- writing cgroup.kill there kills the Docker
  # daemon and every container on the box. That is not hypothetical: it took
  # out an instance.
  REL=$(awk -F: '$1=="0"{print $3}' "/proc/$PORT_PID/cgroup" 2>/dev/null || true)
  case "$REL" in
    */docker-*.scope|*/cri-containerd-*.scope|*/libpod-*.scope) ;;
    *)
      [ -n "$REL" ] && echo "[ecp-user-data] not a container scope, refusing cgroup.kill on $REL"
      REL=""
      ;;
  esac
  if [ -n "$REL" ] && [ -d "/sys/fs/cgroup$REL" ]; then
    [ -f "/sys/fs/cgroup$REL/cgroup.freeze" ] && echo 0 > "/sys/fs/cgroup$REL/cgroup.freeze" 2>/dev/null || true
    [ -f "/sys/fs/cgroup$REL/cgroup.kill" ] && echo 1 > "/sys/fs/cgroup$REL/cgroup.kill" 2>/dev/null || true
  fi
  kill -9 "$PORT_PID" 2>/dev/null || true
  sleep 3
done

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
#
# Must not abort user-data. Under "set -e" a non-zero restart killed the whole
# script, so cloud-init reported a scripts_user failure and the diagnostics
# below never ran -- which is why this took so long to see. The deploy's
# "Ensure backend" step recovers a failed start; losing the log does not help.
if systemctl restart ecp-startup.service; then
  echo "[ecp-user-data] ecp-startup.service restart returned success"
else
  echo "[ecp-user-data] WARNING: ecp-startup.service restart reported failure"
fi

SERVICE_RESULT=$(systemctl show -p Result --value ecp-startup.service 2>/dev/null || echo unknown)
EXEC_STATUS=$(systemctl show -p ExecMainStatus --value ecp-startup.service 2>/dev/null || echo unknown)
echo "[ecp-user-data] ecp-startup.service SERVICE_RESULT=$SERVICE_RESULT EXEC_STATUS=$EXEC_STATUS"

if [ "$SERVICE_RESULT" != "success" ] || [ "$EXEC_STATUS" != "0" ]; then
  echo "[ecp-user-data] WARNING: ecp-startup.service did not complete cleanly"
  systemctl status ecp-startup.service --no-pager 2>/dev/null || true
fi

echo "[ecp-user-data] Finished: $(date)"
