#!/bin/bash
set -euo pipefail

REGION="eu-central-1"
AWS_ACCOUNT_ID="776850212338"
ECP_ENV="/etc/ecp/ecp.env"
SALEOR_DIR="/home/ubuntu/Event-Community-Platform/saleor-platform"
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

START_SALEOR="$(awk -F= '$1=="START_SALEOR"{print $2}' "$ECP_ENV" | tail -1 | tr -d '\r' || true)"
START_SALEOR="${START_SALEOR:-false}"
START_SALEOR="$(echo "$START_SALEOR" | tr '[:upper:]' '[:lower:]')"

echo "START_SALEOR=$START_SALEOR"

IMAGE_URI=$(aws ssm get-parameter \
  --name /ecp/prod/BACKEND_IMAGE_URI \
  --region "$REGION" \
  --query "Parameter.Value" \
  --output text)

echo "Expected backend image: $IMAGE_URI"

echo "===== Disable old non-Docker backend service ====="
systemctl stop ecp-backend.service 2>/dev/null || true
systemctl disable ecp-backend.service 2>/dev/null || true
systemctl mask ecp-backend.service 2>/dev/null || true
systemctl stop daphne.service 2>/dev/null || true
systemctl disable daphne.service 2>/dev/null || true
systemctl mask daphne.service 2>/dev/null || true
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

# "kill -9 <pid>" cannot remove a process whose cgroup is frozen (SIGKILL is
# queued but never delivered) and cannot remove a task whose containerd shim was
# orphaned (dockerd forgot the container, so "docker rm" is a no-op while the
# task keeps the listening socket). Both look identical from ps/ss: the PID is
# visible, kill returns success, the process never dies. That is the state that
# leaves an orphaned daphne on 0.0.0.0:8000, which makes the real --network host
# container fail to bind and crash-loop. Escalate instead of retrying kill.
remove_rogue_container_runtime() {
  rogue_pid="$1"
  [ -n "$rogue_pid" ] || return 0
  ps -p "$rogue_pid" >/dev/null 2>&1 || return 0

  # 1. Let docker remove it while docker still tracks the container.
  rogue_cid=$(docker ps -aq 2>/dev/null | while read -r c; do
    p=$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null || echo "")
    [ -n "$p" ] && [ "$p" = "$rogue_pid" ] && echo "$c"
  done | head -1 || true)
  if [ -n "$rogue_cid" ]; then
    echo "Removing container $rogue_cid holding PID=$rogue_pid"
    docker update --restart=no "$rogue_cid" >/dev/null 2>&1 || true
    docker rm -f "$rogue_cid" >/dev/null 2>&1 || true
    sleep 2
    ps -p "$rogue_pid" >/dev/null 2>&1 || return 0
  fi

  # 2. Kill the whole systemd scope (docker-<id>.scope) owning the PID.
  scope=$(awk -F: '{print $3}' "/proc/$rogue_pid/cgroup" 2>/dev/null \
    | grep -oE '[^/]+\.scope' | head -1 || true)
  self_scope=$(awk -F: '{print $3}' "/proc/$$/cgroup" 2>/dev/null \
    | grep -oE '[^/]+\.scope' | head -1 || true)
  if [ -n "$scope" ] && [ "$scope" = "$self_scope" ]; then
    echo "Refusing to kill scope $scope: it also contains this script"
  elif [ -n "$scope" ]; then
    echo "Killing systemd scope $scope for PID=$rogue_pid"
    systemctl kill --kill-who=all --signal=SIGKILL "$scope" 2>/dev/null || true
    sleep 2
    ps -p "$rogue_pid" >/dev/null 2>&1 || return 0
  fi

  # 3. cgroup v2: thaw first, then mass-kill every task in the cgroup.
  rel=$(awk -F: '$1=="0"{print $3}' "/proc/$rogue_pid/cgroup" 2>/dev/null || true)
  if [ -n "$rel" ] && [ -d "/sys/fs/cgroup$rel" ]; then
    if [ -f "/sys/fs/cgroup$rel/cgroup.freeze" ]; then
      echo "Thawing cgroup /sys/fs/cgroup$rel"
      echo 0 > "/sys/fs/cgroup$rel/cgroup.freeze" 2>/dev/null || true
    fi
    if [ -f "/sys/fs/cgroup$rel/cgroup.kill" ]; then
      echo "Using cgroup.kill on /sys/fs/cgroup$rel"
      echo 1 > "/sys/fs/cgroup$rel/cgroup.kill" 2>/dev/null || true
      sleep 2
      ps -p "$rogue_pid" >/dev/null 2>&1 || return 0
    fi
  fi

  # 4. Ask containerd directly; dockerd has lost track of this task.
  if command -v ctr >/dev/null 2>&1; then
    task=$(ctr -n moby tasks ls 2>/dev/null | awk -v p="$rogue_pid" '$2==p {print $1}' | head -1 || true)
    if [ -n "$task" ]; then
      echo "Killing orphaned containerd shim task $task for PID=$rogue_pid"
      ctr -n moby tasks kill -s SIGKILL "$task" 2>/dev/null || true
      ctr -n moby tasks rm -f "$task" 2>/dev/null || true
      sleep 2
      ps -p "$rogue_pid" >/dev/null 2>&1 || return 0
    fi
  fi

  echo "PID=$rogue_pid survived every escalation step; diagnostic state:"
  grep -E '^(Name|State):' "/proc/$rogue_pid/status" 2>/dev/null || true
  return 1
}

echo "===== Free port 8000 safely if needed ====="

for attempt in $(seq 1 30); do
  BUSY=$(ss -lntpH | awk '$4 ~ /:8000$/ {print}' || true)

  if [ -z "$BUSY" ]; then
    echo "Port 8000 is free"
    break
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
      kill -TERM "$PID" 2>/dev/null || true
      sleep 1
      kill -KILL "$PID" 2>/dev/null || true
      # Plain signals are not enough for a frozen cgroup or an orphaned
      # containerd task, which is how this loop used to spin 30 times against
      # the same PID and then fail the whole deploy.
      if ps -p "$PID" >/dev/null 2>&1; then
        remove_rogue_container_runtime "$PID" || true
      fi
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
      echo "Port 8000 is owned by wrong process. Killing port_pid=$PORT_PID"
      kill -9 "$PORT_PID" || true
      sleep 2
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

if [ "$START_SALEOR" = "true" ]; then
  echo "===== Starting Saleor best-effort, non-blocking ====="

  if [ -d "$SALEOR_DIR" ]; then
    cd "$SALEOR_DIR"
    docker-compose -f docker-compose.rds.yml up -d cache api dashboard worker || true

    SALEOR_READY=false

    for i in {1..20}; do
      API_OK=false
      DASHBOARD_OK=false

      if curl -fsS --max-time 10 http://127.0.0.1:8001/graphql/ \
        -H "Content-Type: application/json" \
        --data '{"query":"query { shop { name } }"}' | grep -q "Saleor e-commerce"; then
        API_OK=true
      fi

      if curl -fsSI --max-time 10 http://127.0.0.1:9000/ >/dev/null; then
        DASHBOARD_OK=true
      fi

      echo "Saleor wait attempt $i: API_OK=$API_OK DASHBOARD_OK=$DASHBOARD_OK"

      if [ "$API_OK" = true ] && [ "$DASHBOARD_OK" = true ]; then
        SALEOR_READY=true
        break
      fi

      sleep 10
    done

    if [ "$SALEOR_READY" = true ]; then
      echo "Running Saleor migrations..."
      docker-compose -f docker-compose.rds.yml exec -T api python manage.py migrate || echo "WARNING: Saleor migrations failed"
    else
      echo "WARNING: Saleor failed to become ready. Backend is already running, so startup will continue."
      docker-compose -f docker-compose.rds.yml logs --tail=100 api dashboard worker || true
    fi
  else
    echo "WARNING: Saleor directory not found: $SALEOR_DIR"
  fi
else
  echo "===== Saleor startup disabled by START_SALEOR=$START_SALEOR ====="
fi

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

HEALTH=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' ecp-backend 2>/dev/null || echo missing)
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