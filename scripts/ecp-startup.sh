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

echo "===== Stop old backend containers and stale Daphne ====="
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

pkill -9 -f 'daphne .*ecp_backend.asgi:application' 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
sleep 5

if ss -lntpH | awk '$4 ~ /:8000$/ {print}' | grep -q ':8000'; then
  echo "ERROR: port 8000 is still busy before backend start"
  ss -lntp | grep ':8000' || true
  exit 1
fi

echo "===== Login to ECR and pull backend image ====="
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

echo "Started backend container: $BACKEND_CID"

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
docker update --restart unless-stopped ecp-backend || true

echo "===== Collecting CMS static ====="
docker exec ecp-backend sh -lc "mkdir -p /app/staticfiles && python manage.py collectstatic --noinput" || true

mkdir -p /var/www/ecp-static
rm -rf /var/www/ecp-static/*
docker cp ecp-backend:/app/staticfiles/. /var/www/ecp-static/ || true
chown -R www-data:www-data /var/www/ecp-static || true

echo "===== Reloading nginx ====="
nginx -t
systemctl reload nginx

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

echo "===== Final backend verification ====="
docker inspect -f 'image={{.Config.Image}} status={{.State.Status}} restarting={{.State.Restarting}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} pid={{.State.Pid}}' ecp-backend
curl -fsS https://api.colligatus.com/api/health/

echo "===== ECP startup finished successfully: $(date) ====="
