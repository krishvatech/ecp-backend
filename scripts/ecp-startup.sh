#!/bin/bash
set -euo pipefail

REGION="eu-central-1"
AWS_ACCOUNT_ID="776850212338"
ECP_ENV="/etc/ecp/ecp.env"
SALEOR_DIR="/home/ubuntu/Event-Community-Platform/saleor-platform"
NGINX_CONF="/etc/nginx/conf.d/ecp-backend.conf"

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
rm -rf /var/www/ecp-static/*
docker cp ecp-backend:/app/staticfiles/. /var/www/ecp-static/ || true
chown -R www-data:www-data /var/www/ecp-static || true

echo "===== Ensuring active Nginx config serves Django/Wagtail static files ====="

ensure_nginx_static_routes() {
  local conf="${NGINX_CONF:-/etc/nginx/conf.d/ecp-backend.conf}"

  if [ ! -f "$conf" ]; then
    echo "WARNING: $conf not found. Skipping Nginx static route patch."
    return 0
  fi

  if grep -q "alias /var/www/ecp-static/" "$conf"; then
    echo "Nginx static route already exists in $conf"
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

if "alias /var/www/ecp-static/" in text:
    print("Static route already present.")
    raise SystemExit(0)

match = re.search(r"(?m)^(\s*)location\s+/\s*\{", text)
if not match:
    print("WARNING: Could not find catch-all location / block. No change made.")
    raise SystemExit(0)

indent = match.group(1)

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

text = text[:match.start()] + static_block + text[match.start():]
conf_path.write_text(text)
print(f"Added /static/ and /media/ routes to {conf_path}")
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
curl -fsS https://api.colligatus.com/api/health/

echo "===== ECP startup finished successfully: $(date) ====="
