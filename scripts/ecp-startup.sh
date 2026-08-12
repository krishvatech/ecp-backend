#!/bin/bash
set -euo pipefail

REGION="eu-central-1"
AWS_ACCOUNT_ID="776850212338"
ECP_ENV="/etc/ecp/ecp.env"
NGINX_CONF="/etc/nginx/conf.d/ecp-backend.conf"
LEGACY_NGINX_SITE="/etc/nginx/sites-enabled/colligatus"
DISABLED_NGINX_SITE_DIR="/etc/nginx/disabled-sites"

echo "===== ECP startup started: $(date) ====="

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

mkdir -p /etc/ecp

echo "===== Fetching ECP env from SSM ====="
aws ssm get-parameters-by-path \
  --path /ecp/prod/ \
  --recursive \
  --with-decryption \
  --region "$REGION" \
  --query "Parameters[*].[Name,Value]" \
  --output text \
  | awk '{
      name=$1;
      sub("^/ecp/prod/","",name);
      $1="";
      sub(/^ /,"");
      print name "=" $0
    }' > "$ECP_ENV"

chmod 600 "$ECP_ENV"

echo "===== Forcing production backend settings ====="
sed -i '/^DJANGO_SETTINGS_MODULE=/d' "$ECP_ENV"
echo 'DJANGO_SETTINGS_MODULE=ecp_backend.settings.prod' >> "$ECP_ENV"

sed -i '/^DEBUG=/d' "$ECP_ENV"
echo 'DEBUG=False' >> "$ECP_ENV"

sed -i '/^DJANGO_DEBUG=/d' "$ECP_ENV"
echo 'DJANGO_DEBUG=False' >> "$ECP_ENV"

sed -i '/^WAGTAILADMIN_BASE_URL=/d' "$ECP_ENV"
echo 'WAGTAILADMIN_BASE_URL=https://api.colligatus.com/cms' >> "$ECP_ENV"

IMAGE_URI=$(aws ssm get-parameter \
  --name /ecp/prod/BACKEND_IMAGE_URI \
  --region "$REGION" \
  --query "Parameter.Value" \
  --output text)

echo "Expected backend image: $IMAGE_URI"

echo "===== Disable old non-Docker backend service ====="

retire_legacy_backend_unit() {
  local unit="$1"
  local unit_path="/etc/systemd/system/$unit"
  local retired_path="${unit_path}.legacy-disabled"

  systemctl stop "$unit" 2>/dev/null || true
  systemctl disable "$unit" 2>/dev/null || true

  # Some AMIs contain a real unit file at /etc/systemd/system/<unit>.
  # systemctl mask cannot replace that regular file with /dev/null, so the
  # old service remains available and can reclaim port 8000 later. Move the
  # obsolete unit aside first, then persistently mask the unit name.
  if [ -f "$unit_path" ] && [ ! -L "$unit_path" ]; then
    echo "Retiring legacy unit file $unit_path -> $retired_path"
    mv -f "$unit_path" "$retired_path"
  fi

  systemctl daemon-reload 2>/dev/null || true
  systemctl mask "$unit" 2>/dev/null || true
}

retire_legacy_backend_unit ecp-backend.service
retire_legacy_backend_unit daphne.service
systemctl daemon-reload || true

echo "===== Stop old backend containers and stale Daphne safely ====="

CURRENT_IMAGE=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || echo NO_CONTAINER)
CURRENT_STATUS=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || echo missing)
CURRENT_RESTARTING=$(docker inspect -f '{{.State.Restarting}}' ecp-backend 2>/dev/null || echo true)

echo "CURRENT_IMAGE=$CURRENT_IMAGE"
echo "CURRENT_STATUS=$CURRENT_STATUS"
echo "CURRENT_RESTARTING=$CURRENT_RESTARTING"

if [ "$CURRENT_IMAGE" = "$IMAGE_URI" ] && [ "$CURRENT_STATUS" = "running" ] && [ "$CURRENT_RESTARTING" = "false" ]; then
  echo "Expected backend container is already running. Keeping it."
else
  echo "Backend is missing, old, stopped, or restarting. Replacing container."

  docker update --restart=no ecp-backend 2>/dev/null || true
  docker stop -t 0 ecp-backend 2>/dev/null || true
  docker rm -f ecp-backend 2>/dev/null || true

  OLD_BACKEND_CONTAINERS=$(docker ps -a --format '{{.ID}} {{.Image}} {{.Names}}' | awk '$2 ~ /ecp-backend/ || $3 ~ /ecp-backend/ {print $1}' || true)
  for CID in $OLD_BACKEND_CONTAINERS; do
    echo "Removing old backend container $CID"
    docker update --restart=no "$CID" 2>/dev/null || true
    docker stop -t 0 "$CID" 2>/dev/null || true
    docker rm -f "$CID" 2>/dev/null || true
  done
fi

# A stale listener can be backed by a Docker/containerd runtime whose process
# PID changes after every kill. Production showed exactly that: multiple daphne
# PIDs were recreated inside the same docker-<container-id>.scope. Track the
# stable runtime identity and define success as port 8000 staying free, not as
# one historical PID disappearing.
port_8000_is_free_stably() {
  local checks="${1:-3}"
  local i

  for i in $(seq 1 "$checks"); do
    if ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -q ':8000'; then
      return 1
    fi
    if [ "$i" -lt "$checks" ]; then
      sleep 1
    fi
  done

  return 0
}

remove_rogue_container_runtime() {
  local rogue_pid="$1"
  local scope=""
  local rel=""
  local runtime_id=""
  local rogue_cid=""
  local expected_cid=""
  local expected_image=""
  local expected_status=""
  local self_scope=""
  local task=""
  local new_pid=""
  local new_scope=""

  [ -n "$rogue_pid" ] || return 0

  # Capture cgroup/scope identity BEFORE sending any signal. The original PID
  # may disappear immediately while the same stale task respawns a new daphne.
  if [ -r "/proc/$rogue_pid/cgroup" ]; then
    rel=$(awk -F: '$1=="0"{print $3}' "/proc/$rogue_pid/cgroup" 2>/dev/null || true)
    scope=$(awk -F: '{print $3}' "/proc/$rogue_pid/cgroup" 2>/dev/null \
      | grep -oE '[^/]+\.scope' | head -1 || true)
  fi

  case "$scope" in
    docker-*.scope)
      runtime_id="${scope#docker-}"
      runtime_id="${runtime_id%.scope}"
      if ! printf '%s' "$runtime_id" | grep -Eq '^[0-9a-f]{12,64}$'; then
        runtime_id=""
      fi
      ;;
  esac

  expected_cid=$(docker inspect -f '{{.Id}}' ecp-backend 2>/dev/null || true)
  expected_image=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || true)
  expected_status=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || true)

  # Never destroy the expected healthy backend even if this helper is called
  # from a future code path by mistake.
  if [ -n "$runtime_id" ] && [ -n "$expected_cid" ]; then
    case "$expected_cid" in
      "$runtime_id"*)
        if [ "$expected_image" = "$IMAGE_URI" ] && [ "$expected_status" = "running" ]; then
          echo "Refusing rogue-runtime cleanup: scope $scope belongs to the expected healthy ecp-backend container."
          return 1
        fi
        ;;
    esac
  fi

  # Prefer the stable container ID encoded in docker-<id>.scope. PID matching
  # alone is unreliable when the task respawns between checks.
  if [ -n "$runtime_id" ] && docker inspect "$runtime_id" >/dev/null 2>&1; then
    rogue_cid="$runtime_id"
  elif ps -p "$rogue_pid" >/dev/null 2>&1; then
    rogue_cid=$(docker ps -aq 2>/dev/null | while read -r c; do
      p=$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null || echo "")
      [ -n "$p" ] && [ "$p" = "$rogue_pid" ] && echo "$c"
    done | head -1 || true)
  fi

  if [ -n "$rogue_cid" ]; then
    if [ -n "$expected_cid" ]; then
      case "$expected_cid" in
        "$rogue_cid"*)
          if [ "$expected_image" = "$IMAGE_URI" ] && [ "$expected_status" = "running" ]; then
            echo "Refusing to remove container $rogue_cid because it is the expected healthy backend."
            return 1
          fi
          ;;
      esac
    fi

    echo "Removing stale Docker container $rogue_cid associated with PID=$rogue_pid scope=${scope:-unknown}"
    docker update --restart=no "$rogue_cid" >/dev/null 2>&1 || true
    docker stop -t 0 "$rogue_cid" >/dev/null 2>&1 || true
    docker rm -f "$rogue_cid" >/dev/null 2>&1 || true
  fi

  # Stop the current process, but DO NOT return merely because this PID dies.
  # The production failure recreated a new PID in the same scope seconds later.
  kill -TERM "$rogue_pid" 2>/dev/null || true
  sleep 1
  kill -KILL "$rogue_pid" 2>/dev/null || true

  self_scope=$(awk -F: '{print $3}' "/proc/$$/cgroup" 2>/dev/null \
    | grep -oE '[^/]+\.scope' | head -1 || true)
  if [ -n "$scope" ] && [ "$scope" = "$self_scope" ]; then
    echo "Refusing to kill scope $scope: it also contains this script"
  elif [ -n "$scope" ]; then
    echo "Killing systemd scope $scope for PID=$rogue_pid"
    systemctl kill --kill-who=all --signal=SIGKILL "$scope" 2>/dev/null || true
  fi

  # If systemd killed the old PID but the same scope immediately recreated a
  # listener, continue to the destructive runtime cleanup instead of returning.
  sleep 1
  new_pid=$(ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  if [ -n "$new_pid" ] && [ -r "/proc/$new_pid/cgroup" ]; then
    new_scope=$(awk -F: '{print $3}' "/proc/$new_pid/cgroup" 2>/dev/null \
      | grep -oE '[^/]+\.scope' | head -1 || true)
    if [ -n "$scope" ] && [ "$new_scope" = "$scope" ] && [ "$new_pid" != "$rogue_pid" ]; then
      echo "Same rogue runtime scope $scope respawned port 8000 as PID=$new_pid; escalating to cgroup/containerd cleanup."
    fi
  fi

  # cgroup v2: thaw first, then kill every task in the saved cgroup. Use the
  # path captured before the PID changed.
  #
  # Restrict this to container scopes. $rel is whatever cgroup the PID lives in,
  # and for a process dockerd owns directly that is system.slice/docker.service
  # -- writing cgroup.kill there kills the Docker daemon and every container on
  # the host.
  case "$rel" in
    */docker-*.scope|*/cri-containerd-*.scope|*/libpod-*.scope) ;;
    *)
      [ -n "$rel" ] && echo "Not a container scope, refusing cgroup.kill on $rel"
      rel=""
      ;;
  esac

  if [ -n "$rel" ] && [ -d "/sys/fs/cgroup$rel" ]; then
    if [ -f "/sys/fs/cgroup$rel/cgroup.freeze" ]; then
      echo "Thawing cgroup /sys/fs/cgroup$rel"
      echo 0 > "/sys/fs/cgroup$rel/cgroup.freeze" 2>/dev/null || true
    fi
    if [ -f "/sys/fs/cgroup$rel/cgroup.kill" ]; then
      echo "Using cgroup.kill on /sys/fs/cgroup$rel"
      echo 1 > "/sys/fs/cgroup$rel/cgroup.kill" 2>/dev/null || true
    fi
  fi

  # Destroy the task itself using the stable container ID. This is the missing
  # step for a runtime that keeps respawning daphne after its individual PID is
  # killed. Do not key this only by PID: the PID is intentionally unstable.
  if command -v ctr >/dev/null 2>&1; then
    task="$runtime_id"
    if [ -z "$task" ]; then
      task=$(ctr -n moby tasks ls 2>/dev/null | awk -v p="$rogue_pid" '$2==p {print $1}' | head -1 || true)
    fi

    if [ -n "$task" ]; then
      echo "Killing orphaned containerd shim task $task (stable runtime identity for scope=${scope:-unknown})"
      ctr -n moby tasks kill -s SIGKILL "$task" 2>/dev/null || true
      ctr -n moby tasks rm -f "$task" 2>/dev/null || true
      ctr -n moby containers rm "$task" 2>/dev/null || true
    fi
  fi

  # Success means the host port remains free across multiple checks. A dead old
  # PID is not sufficient because the same task can spawn another PID.
  if port_8000_is_free_stably 3; then
    echo "Rogue runtime cleanup succeeded; port 8000 stayed free."
    return 0
  fi

  echo "Rogue runtime cleanup did not make port 8000 stably free; diagnostic state:"
  ss -lntp | grep ':8000' || true
  if [ -n "$runtime_id" ] && command -v ctr >/dev/null 2>&1; then
    ctr -n moby tasks ls 2>/dev/null | grep -F "$runtime_id" || true
    ctr -n moby containers ls 2>/dev/null | grep -F "$runtime_id" || true
  fi
  return 1
}

echo "===== Free port 8000 safely if needed ====="

for attempt in $(seq 1 30); do
  BUSY=$(ss -lntpH | awk '$4 ~ /:8000$/ {print}' || true)

  if [ -z "$BUSY" ]; then
    if port_8000_is_free_stably 3; then
      echo "Port 8000 is free and stayed free"
      break
    fi
    echo "Port 8000 was momentarily free but was re-occupied; continuing cleanup"
    continue
  fi

  CURRENT_PID=$(docker inspect -f '{{.State.Pid}}' ecp-backend 2>/dev/null || echo "")
  CURRENT_IMAGE_NOW=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || echo NO_CONTAINER)
  CURRENT_STATUS_NOW=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || echo missing)

  PORT_PIDS=$(echo "$BUSY" | grep -oP 'pid=\K[0-9]+' | sort -u || true)

  echo "Port 8000 busy attempt $attempt"
  echo "$BUSY"
  echo "CURRENT_PID=$CURRENT_PID CURRENT_IMAGE_NOW=$CURRENT_IMAGE_NOW CURRENT_STATUS_NOW=$CURRENT_STATUS_NOW"

  KEEP_EXPECTED_BACKEND=false

  for PID in $PORT_PIDS; do
    if [ -n "$CURRENT_PID" ] \
      && [ "$PID" = "$CURRENT_PID" ] \
      && [ "$CURRENT_IMAGE_NOW" = "$IMAGE_URI" ] \
      && [ "$CURRENT_STATUS_NOW" = "running" ]; then
      echo "Port 8000 is owned by expected ecp-backend container PID=$PID. Keeping it."
      KEEP_EXPECTED_BACKEND=true
    else
      CMD=$(ps -p "$PID" -o args= || true)
      echo "Killing stale process on 8000 PID=$PID CMD=$CMD"
      # Capture and destroy the stable runtime identity before this PID can
      # disappear and be replaced by another one in the same Docker scope.
      remove_rogue_container_runtime "$PID" || true
    fi
  done

  if [ "$KEEP_EXPECTED_BACKEND" = true ]; then
    break
  fi

  sleep 2
done

if ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -q ':8000'; then
  CURRENT_PID=$(docker inspect -f '{{.State.Pid}}' ecp-backend 2>/dev/null || echo "")
  CURRENT_IMAGE_NOW=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || echo NO_CONTAINER)
  CURRENT_STATUS_NOW=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || echo missing)

  PORT_PID=$(ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | head -1 || true)

  if [ -n "$CURRENT_PID" ] \
    && [ "$PORT_PID" = "$CURRENT_PID" ] \
    && [ "$CURRENT_IMAGE_NOW" = "$IMAGE_URI" ] \
    && [ "$CURRENT_STATUS_NOW" = "running" ]; then
    echo "Port 8000 is owned by expected backend. Continuing."
  else
    echo "ERROR: port 8000 is still busy before backend start"
    ss -lntp | grep ':8000' || true
    exit 1
  fi
fi

echo "===== Login to ECR and pull backend image ====="
ACTUAL_IMAGE=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || echo NO_CONTAINER)
ACTUAL_STATUS=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || echo missing)
ACTUAL_RESTARTING=$(docker inspect -f '{{.State.Restarting}}' ecp-backend 2>/dev/null || echo true)

if [ "$ACTUAL_IMAGE" = "$IMAGE_URI" ] && [ "$ACTUAL_STATUS" = "running" ] && [ "$ACTUAL_RESTARTING" = "false" ]; then
  echo "Backend already running expected image. Skipping docker run."
else
  aws ecr get-login-password --region "$REGION" \
    | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

  docker pull "$IMAGE_URI"

  echo "===== Final port 8000 cleanup immediately before backend start ====="
  for prestart_attempt in $(seq 1 5); do
    if port_8000_is_free_stably 2; then
      break
    fi

    for PID in $(ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | sort -u || true); do
      CMD=$(ps -p "$PID" -o args= || true)
      echo "Pre-start stale port owner PID=$PID CMD=$CMD"
      remove_rogue_container_runtime "$PID" || true
    done
  done

  if ! port_8000_is_free_stably 2; then
    echo "ERROR: port 8000 is not stably free immediately before backend start"
    ss -lntp | grep ':8000' || true
    exit 1
  fi

  echo "===== Starting ECP backend Docker container ====="
  BACKEND_CID=$(docker run -d \
    --name ecp-backend \
    --label app=ecp-backend \
    --restart no \
    --network host \
    --env-file "$ECP_ENV" \
    "$IMAGE_URI")
fi

if [ "${BACKEND_CID:-}" != "" ]; then
  echo "Started backend container: $BACKEND_CID"
else
  echo "Backend container was already running; no new container was started."
fi

echo "===== Waiting for backend ====="
BACKEND_READY=false

for i in {1..40}; do
  ACTUAL_IMAGE=$(docker inspect -f '{{.Config.Image}}' ecp-backend 2>/dev/null || echo NO_CONTAINER)
  STATUS=$(docker inspect -f '{{.State.Status}}' ecp-backend 2>/dev/null || echo missing)
  RESTARTING=$(docker inspect -f '{{.State.Restarting}}' ecp-backend 2>/dev/null || echo true)
  CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ecp-backend 2>/dev/null || echo "")
  PORT_PID=$(ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | head -1 || true)

  echo "Backend wait attempt $i: image=$ACTUAL_IMAGE status=$STATUS restarting=$RESTARTING container_pid=$CONTAINER_PID port_pid=$PORT_PID"

  if [ "$ACTUAL_IMAGE" != "$IMAGE_URI" ]; then
    echo "ERROR: backend image mismatch"
    docker logs --tail=150 ecp-backend || true
    exit 1
  fi

  if [ "$STATUS" = "running" ] && [ "$RESTARTING" = "false" ]; then
    if [ -n "$CONTAINER_PID" ] && [ -n "$PORT_PID" ] && [ "$CONTAINER_PID" != "$PORT_PID" ]; then
      echo "Port 8000 is owned by wrong process. Removing rogue runtime for port_pid=$PORT_PID"
      remove_rogue_container_runtime "$PORT_PID" || true
      sleep 1
      continue
    fi

    if curl -fsSI --max-time 10 \
      -H "Host: api.colligatus.com" \
      -H "X-Forwarded-Proto: https" \
      http://127.0.0.1:8000/api/health/ >/dev/null; then
      BACKEND_READY=true
      break
    fi
  fi

  if [ "$STATUS" = "exited" ] || [ "$STATUS" = "dead" ] || [ "$RESTARTING" = "true" ]; then
    echo "ERROR: backend container is unstable"
    docker logs --tail=150 ecp-backend || true
    docker update --restart=no ecp-backend 2>/dev/null || true
    exit 1
  fi

  docker logs --tail=40 ecp-backend || true
  sleep 5
done

if [ "$BACKEND_READY" != true ]; then
  echo "ERROR: backend failed to become ready"
  docker logs --tail=200 ecp-backend || true
  docker update --restart=no ecp-backend 2>/dev/null || true
  exit 1
fi

echo "Backend started successfully with expected image: $IMAGE_URI"
docker update --restart=unless-stopped ecp-backend || true

# The deploy creates the Celery worker, but an instance can also come up from a
# scale-out or a health-check replacement with no deploy behind it. Those
# instances previously ran whatever worker the AMI had baked in (months-old
# code) or none at all. One worker per instance is correct: workers share the
# Redis queue and each task is consumed exactly once, so more workers only add
# throughput.
#
# Celery BEAT is deliberately NOT started here. Beat is the scheduler, and a
# second one means every scheduled job is queued twice -- duplicate reminder
# emails, duplicate syncs. It must stay on a single instance, which the deploy
# assigns.
echo "===== Ensuring Celery worker container ====="
CELERY_IMAGE=$(docker inspect -f '{{.Config.Image}}' ecp-celery-worker 2>/dev/null || echo NO_CONTAINER)
CELERY_STATUS=$(docker inspect -f '{{.State.Status}}' ecp-celery-worker 2>/dev/null || echo missing)
echo "CELERY_IMAGE=$CELERY_IMAGE CELERY_STATUS=$CELERY_STATUS"

if [ "$CELERY_IMAGE" = "$IMAGE_URI" ] && [ "$CELERY_STATUS" = "running" ]; then
  echo "Celery worker already running expected image."
else
  docker update --restart=no ecp-celery-worker 2>/dev/null || true
  docker rm -f ecp-celery-worker 2>/dev/null || true

  # A failed worker must not fail the boot: the backend is what serves traffic,
  # and other instances' workers still drain the queue.
  if docker run -d \
    --name ecp-celery-worker \
    --label app=ecp-celery-worker \
    --restart unless-stopped \
    --network host \
    --env-file "$ECP_ENV" \
    "$IMAGE_URI" \
    sh -lc "cd /app && celery -A ecp_backend worker -l info --concurrency=2 -n ecp-celery@%h" >/dev/null 2>&1; then
    echo "Celery worker started on $IMAGE_URI"
  else
    echo "WARNING: Celery worker failed to start; continuing without it"
    docker logs --tail=50 ecp-celery-worker 2>/dev/null || true
  fi
fi

echo "===== Collecting CMS static ====="
docker exec ecp-backend sh -lc "mkdir -p /app/staticfiles && python manage.py collectstatic --noinput" || true

mkdir -p /var/www/ecp-static

TMP_STATIC="/tmp/ecp-static-new"
rm -rf "$TMP_STATIC"
mkdir -p "$TMP_STATIC"

if docker cp ecp-backend:/app/staticfiles/. "$TMP_STATIC/"; then
  rm -rf /var/www/ecp-static/*
  cp -a "$TMP_STATIC/." /var/www/ecp-static/
  chown -R www-data:www-data /var/www/ecp-static || true
  echo "Static files copied successfully to /var/www/ecp-static"
else
  echo "WARNING: docker cp staticfiles failed. Keeping existing /var/www/ecp-static unchanged."
fi

rm -rf "$TMP_STATIC"

echo "===== Disabling duplicate legacy Nginx sites-enabled config ====="
mkdir -p "$DISABLED_NGINX_SITE_DIR"

if [ -e "$LEGACY_NGINX_SITE" ] || [ -L "$LEGACY_NGINX_SITE" ]; then
  DISABLED_TARGET="$DISABLED_NGINX_SITE_DIR/colligatus.$(date +%Y%m%d-%H%M%S)"
  if mv "$LEGACY_NGINX_SITE" "$DISABLED_TARGET" 2>/dev/null; then
    echo "Disabled duplicate $LEGACY_NGINX_SITE -> $DISABLED_TARGET"
  else
    echo "WARNING: Could not move $LEGACY_NGINX_SITE, it may have already been moved by another process."
  fi
else
  echo "No duplicate $LEGACY_NGINX_SITE found"
fi

echo "===== Ensuring active Nginx config serves Django/Wagtail static files ====="

ensure_nginx_static_routes() {
  local conf="${NGINX_CONF:-/etc/nginx/conf.d/ecp-backend.conf}"

  if [ ! -f "$conf" ]; then
    echo "WARNING: $conf not found. Skipping Nginx static route patch."
    return 0
  fi

  local backup="${conf}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$conf" "$backup"
  echo "Backup created: $backup"

  ECP_NGINX_CONF="$conf" python3 - <<'PY'
import os
import re
from pathlib import Path

conf_path = Path(os.environ["ECP_NGINX_CONF"])
text = conf_path.read_text()
lines = text.splitlines(True)

server_blocks = []
i = 0

while i < len(lines):
    if re.match(r"^\s*server\s*\{", lines[i]):
        start = i
        depth = 0

        while i < len(lines):
            depth += lines[i].count("{") - lines[i].count("}")

            if depth == 0:
                server_blocks.append((start, i + 1))
                break

            i += 1

    i += 1

changed = False

for start, end in reversed(server_blocks):
    block = "".join(lines[start:end])

    if "alias /var/www/ecp-static/" in block:
        continue

    insert_at = None
    indent = None

    for idx in range(start, end):
        match = re.match(r"^(\s*)location\s+/\s*\{", lines[idx])
        if match:
            insert_at = idx
            indent = match.group(1)
            break

    if insert_at is None:
        continue

    static_block = f"""
{indent}location /static/ {{
{indent}    alias /var/www/ecp-static/;
{indent}    access_log off;
{indent}    expires 365d;
{indent}    add_header Cache-Control "public, max-age=31536000";
{indent}}}

{indent}location /media/ {{
{indent}    alias /home/ubuntu/Event-Community-Platform/events-n-comm-platform/media/;
{indent}    access_log off;
{indent}    expires 30d;
{indent}}}

"""

    lines[insert_at:insert_at] = [static_block]
    changed = True

if changed:
    conf_path.write_text("".join(lines))
    print(f"Added /static/ and /media/ routes to missing server block(s) in {conf_path}")
else:
    print(f"Static/media routes already present in all matching server blocks, or no catch-all location found in {conf_path}")
PY

  if nginx -t; then
    echo "Nginx config test passed after static route patch."
  else
    echo "ERROR: Nginx config test failed. Restoring backup."
    cp "$backup" "$conf"
    nginx -t || true
    return 0
  fi
}

ensure_nginx_static_routes

echo "===== Reloading nginx ====="
nginx -t
systemctl reload nginx

echo "===== Saleor runs on separate infrastructure; no local Saleor runtime is started here ====="

echo "===== Final backend verification ====="
docker inspect -f 'image={{.Config.Image}} status={{.State.Status}} restarting={{.State.Restarting}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} pid={{.State.Pid}}' ecp-backend

# Confirm the process holding port 8000 really is this instance's ecp-backend
# container, not a leftover daphne from an earlier boot.
pid_belongs_to_backend_container() {
  candidate="$1"
  [ -n "$candidate" ] || return 1
  backend_pid=$(docker inspect -f '{{.State.Pid}}' ecp-backend 2>/dev/null || echo "")
  [ -n "$backend_pid" ] && [ "$candidate" = "$backend_pid" ]
}

assert_backend_owns_port_8000() {
  port_pid=$(ss -lntpH 2>/dev/null | awk '$4 ~ /:8000$/ {print}' | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  if [ -z "$port_pid" ]; then
    echo "ERROR: nothing is listening on port 8000"
    return 1
  fi
  if ! pid_belongs_to_backend_container "$port_pid"; then
    echo "ERROR: port 8000 is held by PID=$port_pid which is not the ecp-backend container"
    ps -p "$port_pid" -o args= || true
    return 1
  fi
  echo "Port 8000 is owned by the expected ecp-backend container (PID=$port_pid)"
}

assert_backend_owns_port_8000

# Docker reports "starting" until the first healthcheck interval elapses (30s
# per the Dockerfile), so it is the normal state for a container that has just
# been launched -- NOT a failure. Treating it as one failed every boot even
# though daphne was already serving 200s. Wait for the state to settle.
HEALTH=missing
for _ in $(seq 1 24); do
  HEALTH=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' ecp-backend 2>/dev/null || echo missing)
  case "$HEALTH" in
    healthy|none|unhealthy) break ;;
  esac
  sleep 5
done

if [ "$HEALTH" = "healthy" ] || [ "$HEALTH" = "none" ]; then
  echo "Container health: $HEALTH"
else
  echo "ERROR: ecp-backend container health is $HEALTH"
  docker logs --tail=100 ecp-backend || true
  exit 1
fi

# Local endpoint is the authoritative check for this instance. The public URL
# goes through the ALB and can be answered by a DIFFERENT healthy instance,
# which made a broken instance look fine.
curl -fsS --max-time 10 \
  -H "Host: api.colligatus.com" \
  -H "X-Forwarded-Proto: https" \
  http://127.0.0.1:8000/api/health/

echo "===== ECP startup finished successfully: $(date) ====="