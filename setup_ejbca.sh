#!/usr/bin/env bash
###############################################################################
# setup_ejbca.sh — Reproducible EJBCA CE + Postgres + Nginx (TLS+mTLS) on Debian 13
#
# This script is rebuilt to match the *working* deployment state captured in
# ejbca_config_dump_20260204_140017.txt, including the fixes discovered:
#   - Postgres container UID/GID is 70:70 (postgres:16-alpine), not 999:999
#   - EJBCA listens on 8080 (not 8081/8082 in this image/config)
#   - EJBCA persistence is mounted at /mnt/persistent (volume ejbca_data)
#   - EJBCA works with: TLS_SETUP_ENABLED=true, PROXY_HTTP_BIND="" (unset/blank),
#     HTTPSERVER_HOSTNAME=<host>
#   - Nginx reverse proxy terminates TLS and enforces mTLS on:
#       /ejbca/adminweb/ and /ejbca/ejbca-rest-api/
#   - DO NOT cap_drop ALL for nginx (it breaks entrypoint chown/init); keep it simple
#
# Usage:
#   sudo ./setup_ejbca.sh
#   sudo ./setup_ejbca.sh --force --yes
#   sudo ./setup_ejbca.sh --hostname pki.example.com
#   sudo ./setup_ejbca.sh --image-tag latest
#
# Flags:
#   --force     Regenerate generated artifacts (.env, certs, nginx configs, p12),
#               and recreate named volumes (DATA LOSS) after backing up artifacts.
#   --yes       Skip the 10-second confirmation delay when using --force.
#   --hostname  Override HTTPSERVER_HOSTNAME + server cert CN/SAN (DNS only).
#               Default: hostname -f (fallback hostname)
#   --image-tag EJBCA image tag (default: latest)
#
# Outputs:
#   - /opt/ejbca/* (compose, nginx configs, certs, data dirs)
#   - /var/log/ejbca-setup.log
#
###############################################################################

set -euo pipefail

# --------------------------- args / defaults ---------------------------
BASE_DIR="/opt/ejbca"
LOG_FILE="/var/log/ejbca-setup.log"

EJBCA_USER="ejbca"
EJBCA_HOME="/home/ejbca"
DOCKER_CONFIG_DIR="${EJBCA_HOME}/.docker"

OPT_FORCE=false
OPT_YES=false
OPT_HOSTNAME=""
OPT_IMAGE_TAG="latest"

usage() {
  cat <<EOF
Usage: sudo $0 [--force] [--yes] [--hostname <fqdn>] [--image-tag <tag>]

Options:
  --force             Regenerate artifacts + recreate volumes (DATA LOSS)
  --yes               Skip confirmation delay for --force
  --hostname <fqdn>   Set HTTPSERVER_HOSTNAME and server cert CN/SAN
  --image-tag <tag>   EJBCA image tag (default: latest)
  --help              Show this help
EOF
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) OPT_FORCE=true; shift ;;
    --yes) OPT_YES=true; shift ;;
    --hostname)
      shift
      [[ -n "${1:-}" ]] || { echo "ERROR: --hostname requires a value"; usage 1; }
      OPT_HOSTNAME="$1"
      shift
      ;;
    --image-tag)
      shift
      [[ -n "${1:-}" ]] || { echo "ERROR: --image-tag requires a value"; usage 1; }
      OPT_IMAGE_TAG="$1"
      shift
      ;;
    --help|-h) usage 0 ;;
    *) echo "ERROR: Unknown argument: $1"; usage 1 ;;
  esac
done

# --------------------------- root check ---------------------------
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: Run as root (or via sudo): sudo $0 ..." >&2
  exit 1
fi

# --------------------------- logging ---------------------------
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
exec > >(while IFS= read -r line; do printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$line"; done | tee -a "$LOG_FILE") 2>&1

log() { echo "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

ts_suffix() { date +'%Y%m%d_%H%M%S'; }

backup_if_exists() {
  local p="$1"
  [[ -e "$p" ]] || return 0
  local b="${p}.bak.$(ts_suffix)"
  cp -a "$p" "$b"
  log "Backed up: $p -> $b"
}

retry_backoff() {
  local attempts="$1"; shift
  local n=1 delay=2
  until "$@"; do
    if (( n >= attempts )); then
      return 1
    fi
    log "Retry $n/$attempts failed; sleeping ${delay}s."
    log "Hints: check DNS (/etc/resolv.conf), proxy env (http_proxy/https_proxy), outbound HTTPS, apt mirrors."
    sleep "$delay"
    n=$((n+1))
    delay=$((delay*2))
  done
}

port_in_use() {
  local p="$1"
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${p}$"
}

default_fqdn() {
  local h=""
  h="$(hostname -f 2>/dev/null || true)"
  [[ -n "$h" && "$h" != "(none)" ]] || h="$(hostname)"
  echo "$h"
}

rand_b64_32() {
  openssl rand -base64 32 | tr -d '\n'
}

# --------------------------- preflight ---------------------------
log "===== EJBCA setup starting ====="
log "Base dir: ${BASE_DIR}"
log "Force: ${OPT_FORCE}"
log "Image tag: ${OPT_IMAGE_TAG}"

if port_in_use 80 || port_in_use 443; then
  die "Ports 80/443 are already in use. Stop the service using them and re-run."
fi

if "${OPT_FORCE}"; then
  log "WARNING: --force will recreate volumes (DATA LOSS) and regenerate secrets/certs."
  if ! "${OPT_YES}"; then
    log "Press Ctrl-C within 10 seconds to abort..."
    sleep 10
  fi
fi

# --------------------------- step 1: packages + docker ---------------------------
log ">>> [1/10] Installing prerequisites + Docker (official repo)..."
retry_backoff 3 apt-get update -y || die "apt-get update failed"
retry_backoff 3 apt-get install -y ca-certificates curl gnupg lsb-release openssl jq || die "Failed installing base prerequisites"

install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  retry_backoff 3 bash -lc 'curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg' \
    || die "Failed to fetch/import Docker GPG key"
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
[[ -n "$CODENAME" ]] || die "Could not determine VERSION_CODENAME from /etc/os-release"

cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable
EOF

retry_backoff 3 apt-get update -y || die "apt-get update failed after adding Docker repo"
retry_backoff 3 apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || die "Docker install failed"

systemctl enable --now docker || die "Failed to enable/start docker"
docker version >/dev/null 2>&1 || die "Docker is not functional"
docker compose version >/dev/null 2>&1 || die "Docker compose plugin not functional"

log "Docker: $(docker --version)"
log "Compose: $(docker compose version)"

# --------------------------- step 2: create service user (real home) ---------------------------
log ">>> [2/10] Ensuring service user '${EJBCA_USER}' exists with real HOME..."
if ! id "${EJBCA_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "${EJBCA_HOME}" --shell /usr/sbin/nologin "${EJBCA_USER}"
  log "Created user ${EJBCA_USER}"
else
  usermod -d "${EJBCA_HOME}" "${EJBCA_USER}" >/dev/null 2>&1 || true
fi

getent group docker >/dev/null 2>&1 || groupadd docker
usermod -aG docker "${EJBCA_USER}" >/dev/null 2>&1 || true

mkdir -p "${DOCKER_CONFIG_DIR}"
chown -R "${EJBCA_USER}:${EJBCA_USER}" "${EJBCA_HOME}"
chmod 750 "${EJBCA_HOME}"

# --------------------------- step 3: directory layout ---------------------------
log ">>> [3/10] Creating directory structure..."
mkdir -p \
  "${BASE_DIR}/config" \
  "${BASE_DIR}/plugins" \
  "${BASE_DIR}/secrets" \
  "${BASE_DIR}/logs" \
  "${BASE_DIR}/backups" \
  "${BASE_DIR}/data/postgres" \
  "${BASE_DIR}/data/ejbca" \
  "${BASE_DIR}/nginx/conf.d" \
  "${BASE_DIR}/nginx/tls" \
  "${BASE_DIR}/nginx/mtls-ca" \
  "${BASE_DIR}/nginx/clients"

# ownerships (match working state)
chown -R root:root "${BASE_DIR}/config" "${BASE_DIR}/plugins" "${BASE_DIR}/nginx" "${BASE_DIR}/secrets"
chmod 755 "${BASE_DIR}" "${BASE_DIR}/config" "${BASE_DIR}/plugins" "${BASE_DIR}/nginx" "${BASE_DIR}/nginx/conf.d" "${BASE_DIR}/nginx/tls" "${BASE_DIR}/nginx/mtls-ca" "${BASE_DIR}/nginx/clients"
chmod 750 "${BASE_DIR}/secrets"

# operational dirs owned by ejbca user (matches observed ejbca user uid/gid 999:987 in your dump)
chown -R "${EJBCA_USER}:${EJBCA_USER}" "${BASE_DIR}/backups" "${BASE_DIR}/logs"
chmod 750 "${BASE_DIR}/backups" "${BASE_DIR}/logs"

# data roots: keep as root-owned but writable as needed
# postgres will be chowned to container's postgres uid/gid (detected below)
chmod 775 "${BASE_DIR}/data" "${BASE_DIR}/data/ejbca"
chown root:root "${BASE_DIR}/data" "${BASE_DIR}/data/ejbca"

# --------------------------- step 4: .env generation ---------------------------
log ">>> [4/10] Writing ${BASE_DIR}/.env (idempotent)..."
ENV_FILE="${BASE_DIR}/.env"

if [[ -f "${ENV_FILE}" && "${OPT_FORCE}" == false ]]; then
  log ".env exists; leaving as-is."
else
  if [[ -f "${ENV_FILE}" ]]; then
    backup_if_exists "${ENV_FILE}"
  fi
  cat > "${ENV_FILE}" <<EOF
# Generated by setup_ejbca.sh on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
DATABASE_PASSWORD=$(rand_b64_32)
PASSWORD_ENCRYPTION_KEY=$(rand_b64_32)
CA_KEYSTOREPASS=$(rand_b64_32)
EJBCA_CLI_DEFAULTPASSWORD=$(rand_b64_32)
ADMIN_CLIENT_P12_PASSWORD=$(rand_b64_32)
EJBCA_IMAGE_TAG=${OPT_IMAGE_TAG}
EOF
  log "Wrote .env"
fi

chown "root:${EJBCA_USER}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

# load env (for p12 password)
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

# --------------------------- step 5: detect container UIDs (critical) ---------------------------
log ">>> [5/10] Detecting container runtime UIDs/GIDs (to avoid permission failures)..."
# Postgres UID/GID inside postgres:16-alpine is 70:70 (observed), but detect to be safe:
PG_UID="$(docker run --rm postgres:16-alpine sh -lc 'id -u postgres' 2>/dev/null || true)"
PG_GID="$(docker run --rm postgres:16-alpine sh -lc 'id -g postgres' 2>/dev/null || true)"
[[ -n "${PG_UID}" && -n "${PG_GID}" ]] || die "Unable to detect postgres UID/GID from postgres:16-alpine"
log "Detected Postgres UID:GID = ${PG_UID}:${PG_GID}"

# EJBCA user inside keyfactor/ejbca-ce runs as UID 10001 (observed), detect:
EJBCA_UID="$(docker run --rm keyfactor/ejbca-ce:${OPT_IMAGE_TAG} sh -lc 'id -u 2>/dev/null || true' 2>/dev/null || true)"
if [[ -z "${EJBCA_UID}" ]]; then
  # fallback to observed
  EJBCA_UID="10001"
fi
log "Detected/assumed EJBCA UID = ${EJBCA_UID}"

# --------------------------- step 6: create named bind volumes (idempotent) ---------------------------
log ">>> [6/10] Creating named Docker volumes with host-path binds..."
create_bind_volume() {
  local vol="$1" host_path="$2"
  if docker volume inspect "${vol}" >/dev/null 2>&1; then
    if "${OPT_FORCE}"; then
      log "--force: removing volume ${vol}"
      docker volume rm -f "${vol}" >/dev/null 2>&1 || true
    else
      log "Volume exists: ${vol}"
      return 0
    fi
  fi

  mkdir -p "${host_path}"
  docker volume create --driver local --opt type=none --opt device="${host_path}" --opt o=bind "${vol}" >/dev/null
  log "Created volume ${vol} -> ${host_path}"
}

create_bind_volume "ejbca_pgdata" "${BASE_DIR}/data/postgres"
create_bind_volume "ejbca_data"   "${BASE_DIR}/data/ejbca"
create_bind_volume "ejbca_logs"   "${BASE_DIR}/logs"

# apply correct perms for postgres data dir (MUST be owned by postgres UID/GID; must be 700)
chown -R "${PG_UID}:${PG_GID}" "${BASE_DIR}/data/postgres"
chmod 700 "${BASE_DIR}/data/postgres"

# ejbca persistent dir: match working permissive root:root 0775; container creates subdirs as 10001:root
chown root:root "${BASE_DIR}/data/ejbca"
chmod 775 "${BASE_DIR}/data/ejbca"

# nginx logs: allow nginx to write; safest is keep owned by service user (ejbca) since docker-managed;
# but if you want strict match to your bind volume device, use writable by container.
chmod 750 "${BASE_DIR}/logs"
chown -R "${EJBCA_USER}:${EJBCA_USER}" "${BASE_DIR}/logs"

# --------------------------- step 7: generate TLS + mTLS artifacts ---------------------------
log ">>> [7/10] Generating TLS + mTLS assets (no private contents printed)..."
TLS_DIR="${BASE_DIR}/nginx/tls"
MTLS_DIR="${BASE_DIR}/nginx/mtls-ca"
CLIENT_DIR="${BASE_DIR}/nginx/clients"

SERVER_KEY="${TLS_DIR}/server.key"
SERVER_CRT="${TLS_DIR}/server.crt"
CA_KEY="${MTLS_DIR}/ca.key"
CA_CRT="${MTLS_DIR}/ca.crt"
SUPERADMIN_P12="${CLIENT_DIR}/superadmin.p12"
SUPERADMIN_KEY="${CLIENT_DIR}/superadmin.key"
SUPERADMIN_CSR="${CLIENT_DIR}/superadmin.csr"
SUPERADMIN_CRT="${CLIENT_DIR}/superadmin.crt"

CERT_HOST="${OPT_HOSTNAME:-$(default_fqdn)}"

gen_server_cert() {
  backup_if_exists "${SERVER_KEY}"
  backup_if_exists "${SERVER_CRT}"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
    -keyout "${SERVER_KEY}" \
    -out "${SERVER_CRT}" \
    -subj "/CN=${CERT_HOST}" \
    -addext "subjectAltName=DNS:${CERT_HOST}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
}

gen_mtls_ca() {
  backup_if_exists "${CA_KEY}"
  backup_if_exists "${CA_CRT}"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "${CA_KEY}" \
    -out "${CA_CRT}" \
    -subj "/CN=EJBCA mTLS CA/O=EJBCA/OU=Operators" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}

gen_superadmin_p12() {
  backup_if_exists "${SUPERADMIN_P12}"
  backup_if_exists "${SUPERADMIN_KEY}"
  backup_if_exists "${SUPERADMIN_CRT}"

  openssl req -newkey rsa:4096 -sha256 -nodes \
    -keyout "${SUPERADMIN_KEY}" \
    -out "${SUPERADMIN_CSR}" \
    -subj "/CN=SuperAdmin" >/dev/null 2>&1

  openssl x509 -req -sha256 -days 825 \
    -in "${SUPERADMIN_CSR}" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SUPERADMIN_CRT}" \
    -extfile <(printf '%s\n' \
      "basicConstraints=CA:FALSE" \
      "keyUsage=digitalSignature" \
      "extendedKeyUsage=clientAuth") >/dev/null 2>&1

  openssl pkcs12 -export \
    -inkey "${SUPERADMIN_KEY}" \
    -in "${SUPERADMIN_CRT}" \
    -certfile "${CA_CRT}" \
    -name "SuperAdmin" \
    -out "${SUPERADMIN_P12}" \
    -passout "pass:${ADMIN_CLIENT_P12_PASSWORD}" >/dev/null 2>&1

  rm -f "${SUPERADMIN_CSR}" >/dev/null 2>&1 || true
}

if [[ -f "${SERVER_KEY}" && -f "${SERVER_CRT}" && "${OPT_FORCE}" == false ]]; then
  log "Server TLS cert exists; skipping."
else
  gen_server_cert
  log "Generated server TLS cert for CN=${CERT_HOST}"
fi

if [[ -f "${CA_KEY}" && -f "${CA_CRT}" && "${OPT_FORCE}" == false ]]; then
  log "mTLS CA exists; skipping."
else
  gen_mtls_ca
  log "Generated mTLS CA"
fi

if [[ -f "${SUPERADMIN_P12}" && "${OPT_FORCE}" == false ]]; then
  log "SuperAdmin P12 exists; skipping."
else
  gen_superadmin_p12
  log "Generated SuperAdmin P12: ${SUPERADMIN_P12}"
fi

# permissions (match observed: ca.key/server.key private, certs world-readable, p12 private)
chown -R root:root "${BASE_DIR}/nginx"
chmod 600 "${SERVER_KEY}" "${CA_KEY}" "${SUPERADMIN_P12}" || true
chmod 644 "${SERVER_CRT}" "${CA_CRT}" "${SUPERADMIN_CRT}" || true

# --------------------------- step 8: write nginx configs + dockerfile ---------------------------
log ">>> [8/10] Writing Nginx Dockerfile + configs..."
NGINX_DOCKERFILE="${BASE_DIR}/nginx/Dockerfile"
NGINX_MAIN_CONF="${BASE_DIR}/nginx/nginx.conf"
NGINX_SITE_CONF="${BASE_DIR}/nginx/conf.d/ejbca.conf"

backup_if_exists "${NGINX_DOCKERFILE}"
backup_if_exists "${NGINX_MAIN_CONF}"
backup_if_exists "${NGINX_SITE_CONF}"

cat > "${NGINX_DOCKERFILE}" <<'EOF'
FROM nginx:1.27-alpine
RUN apk add --no-cache curl
EOF

cat > "${NGINX_MAIN_CONF}" <<'EOF'
user  nginx;
worker_processes auto;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events { worker_connections 1024; }

http {
  include       /etc/nginx/mime.types;
  default_type  application/octet-stream;

  server_tokens off;

  log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" "$http_x_forwarded_for" ssl_dn="$ssl_client_s_dn"';
  access_log /var/log/nginx/access.log main;

  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;

  # Rate limiting
  limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=10r/s;
  limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

  include /etc/nginx/conf.d/*.conf;
}
EOF

# IMPORTANT: do NOT strip /ejbca prefix (that broke RA navigation). Proxy /ejbca/* as-is.
cat > "${NGINX_SITE_CONF}" <<'EOF'
upstream ejbca_public { server ejbca:8080; keepalive 32; }
upstream ejbca_admin  { server ejbca:8080; keepalive 32; }

server {
  listen 80 default_server;
  server_name _;
  location = /healthz { return 200 "OK\n"; add_header Content-Type text/plain; }
  location / { return 301 https://$host$request_uri; }
}

server {
  listen 443 ssl http2 default_server;
  server_name _;

  ssl_certificate     /etc/nginx/tls/server.crt;
  ssl_certificate_key /etc/nginx/tls/server.key;

  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

  ssl_client_certificate /etc/nginx/mtls-ca/ca.crt;
  ssl_verify_client optional;
  ssl_verify_depth 2;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header Referrer-Policy "no-referrer" always;

  limit_conn conn_per_ip 30;
  limit_req zone=req_per_ip burst=30 nodelay;

  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto https;

  proxy_http_version 1.1;
  proxy_buffering on;
  proxy_read_timeout 300s;

  location = /healthz { return 200 "OK\n"; add_header Content-Type text/plain; }

  # convenience redirect
  location = /ejbca { return 301 /ejbca/; }

  # Admin UI (mTLS required)
  location ^~ /ejbca/adminweb/ {
    if ($ssl_client_verify != "SUCCESS") { return 403; }
    proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
    proxy_pass http://ejbca_admin;
  }

  # REST API (mTLS required)
  location ^~ /ejbca/ejbca-rest-api/ {
    if ($ssl_client_verify != "SUCCESS") { return 403; }
    proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
    proxy_pass http://ejbca_admin;
  }

  # Public (RA, enrollment, etc.) - no rewrite
  location ^~ /ejbca/ {
    proxy_pass http://ejbca_public;
  }

  # Root forwards too (upstream typically 302s to /ejbca/adminweb)
  location / {
    proxy_pass http://ejbca_public;
  }
}
EOF

# --------------------------- step 9: write docker-compose.yml (match working) ---------------------------
log ">>> [9/10] Writing docker-compose.yml..."
COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
backup_if_exists "${COMPOSE_FILE}"

cat > "${COMPOSE_FILE}" <<EOF
services:
  postgres:
    image: postgres:16-alpine
    container_name: ejbca-postgres
    restart: unless-stopped
    user: "${PG_UID}:${PG_GID}"
    environment:
      POSTGRES_DB: ejbca
      POSTGRES_USER: ejbca
      POSTGRES_PASSWORD: "\${DATABASE_PASSWORD}"
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256 --auth-local=scram-sha-256"
    volumes:
      - ejbca_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ejbca -d ejbca -h 127.0.0.1 -p 5432"]
      interval: 10s
      timeout: 5s
      retries: 18
    security_opt:
      - no-new-privileges:true

  ejbca:
    image: keyfactor/ejbca-ce:\${EJBCA_IMAGE_TAG:-latest}
    container_name: ejbca-app
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    security_opt:
      - no-new-privileges:true
    environment:
      TLS_SETUP_ENABLED: "true"
      HTTPSERVER_HOSTNAME: "${CERT_HOST}"
      DATABASE_JDBC_URL: "jdbc:postgresql://postgres:5432/ejbca"
      DATABASE_USER: "ejbca"
      DATABASE_PASSWORD: "\${DATABASE_PASSWORD}"
      PASSWORD_ENCRYPTION_KEY: "\${PASSWORD_ENCRYPTION_KEY}"
      CA_KEYSTOREPASS: "\${CA_KEYSTOREPASS}"
      EJBCA_CLI_DEFAULTPASSWORD: "\${EJBCA_CLI_DEFAULTPASSWORD}"
      # Bootstrap only — REMOVE after initial admin role setup:
      INITIAL_ADMIN: ";PublicAccessAuthenticationToken:TRANSPORT_ANY;"
    volumes:
      - ejbca_data:/mnt/persistent
      - ${BASE_DIR}/config:/opt/keyfactor/ejbca-custom/conf:ro
      - ${BASE_DIR}/plugins:/opt/keyfactor/ejbca-custom/p:ro
    expose:
      - "8080"
    healthcheck:
      test: ["CMD-SHELL", "/bin/bash -c '</dev/tcp/127.0.0.1/8080'"]
      interval: 10s
      timeout: 5s
      retries: 30

  nginx:
    build:
      context: ${BASE_DIR}/nginx
      dockerfile: Dockerfile
    image: ejbca-nginx:local
    container_name: ejbca-nginx
    restart: unless-stopped
    depends_on:
      ejbca:
        condition: service_healthy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ${BASE_DIR}/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ${BASE_DIR}/nginx/conf.d:/etc/nginx/conf.d:ro
      - ${BASE_DIR}/nginx/tls:/etc/nginx/tls:ro
      - ${BASE_DIR}/nginx/mtls-ca:/etc/nginx/mtls-ca:ro
      - ejbca_logs:/var/log/nginx:rw
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1/healthz >/dev/null || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 18
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /var/cache/nginx
      - /var/run

volumes:
  ejbca_pgdata:
    external: true
  ejbca_data:
    external: true
  ejbca_logs:
    external: true
EOF

chmod 644 "${COMPOSE_FILE}"
chown root:root "${COMPOSE_FILE}"

# --------------------------- step 10: launch + verify (with rollback) ---------------------------
log ">>> [10/10] Launching stack and verifying..."
cd "${BASE_DIR}"

RUN_AS_EJBCA=(sudo -u "${EJBCA_USER}" env HOME="${EJBCA_HOME}" DOCKER_CONFIG="${DOCKER_CONFIG_DIR}")

rollback() {
  log "=== FAILURE: rolling back docker compose stack (best-effort) ==="
  "${RUN_AS_EJBCA[@]}" docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" down || true
  log "=== Recent logs (tail) ==="
  docker logs --tail 80 ejbca-postgres 2>/dev/null || true
  docker logs --tail 120 ejbca-app 2>/dev/null || true
  docker logs --tail 80 ejbca-nginx 2>/dev/null || true
}
trap 'rollback' ERR

# build/pull and start
"${RUN_AS_EJBCA[@]}" docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull || true
"${RUN_AS_EJBCA[@]}" docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d --build

# wait for nginx healthz
log "Waiting for https://localhost/healthz ..."
ok=false
for i in $(seq 1 90); do
  if curl -kfs https://127.0.0.1/healthz >/dev/null 2>&1; then
    ok=true
    break
  fi
  sleep 2
done
"${ok}" || die "Nginx healthz did not become ready"

# verify expected responses
log "Verifying endpoints..."
curl -kIs https://127.0.0.1/healthz | head -n 3 || true
curl -kIs https://127.0.0.1/ejbca/adminweb/ | head -n 8 || true   # expected 403 without client cert

# final: ensure containers healthy
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'ejbca-(postgres|app|nginx)' || true

trap - ERR

log ""
log "=================================================================="
log "EJBCA deployment complete."
log ""
log "URLs:"
log "  Public entry (often redirects): https://${CERT_HOST}/"
log "  AdminWeb (mTLS required):       https://${CERT_HOST}/ejbca/adminweb/"
log "  RA Web:                         https://${CERT_HOST}/ejbca/ra/"
log "  REST API (mTLS required):       https://${CERT_HOST}/ejbca/ejbca-rest-api/"
log ""
log "Client cert:"
log "  SuperAdmin P12: ${SUPERADMIN_P12}"
log "  P12 password:   (see ${ENV_FILE} -> ADMIN_CLIENT_P12_PASSWORD)"
log ""
log "SECURITY REQUIRED AFTER BOOTSTRAP:"
log "  Remove INITIAL_ADMIN from ${COMPOSE_FILE} and recreate only ejbca:"
log "    cd ${BASE_DIR} && docker compose --env-file .env up -d --force-recreate ejbca"
log ""
log "Log file: ${LOG_FILE}"
log "=================================================================="
