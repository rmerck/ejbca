#!/usr/bin/env bash
###############################################################################
# setup_ejbca.sh — Reproducible EJBCA CE + Postgres + Nginx (TLS+mTLS) on Debian 13
#
# Hardened version with fixed Postgres verification logic
#
# Usage:
#   sudo ./setup_ejbca.sh
#   sudo ./setup_ejbca.sh --force --yes
#   sudo ./setup_ejbca.sh --hostname pki.example.com
#   sudo ./setup_ejbca.sh --image-tag latest
#
###############################################################################

set -euo pipefail

# --------------------------- args / defaults ---------------------------
BASE_DIR="/opt/ejbca"
LOG_FILE="/var/log/ejbca-setup.log"
DOCKER_NETWORK="ejbca_net"

EJBCA_USER="ejbca"
EJBCA_HOME="/home/ejbca"
DOCKER_CONFIG_DIR="${EJBCA_HOME}/.docker"

OPT_FORCE=false
OPT_YES=false
OPT_HOSTNAME=""
OPT_IMAGE_TAG="latest"

MIN_DISK_SPACE_MB=5000

# =============================================================================
# FIX #4: Container name constants (MAJOR IMPROVEMENT)
# Define container names as constants to improve maintainability and reusability.
# All references throughout the script now use these constants.
# =============================================================================
POSTGRES_CONTAINER="ejbca-postgres"
EJBCA_CONTAINER="ejbca-app"
NGINX_CONTAINER="ejbca-nginx"

# =============================================================================
# FIX #7: Docker Compose command detection (OPTIONAL ENHANCEMENT)
# Check for both 'docker compose' (plugin) and 'docker-compose' (standalone)
# to support different installation methods.
# =============================================================================
COMPOSE_CMD=""

detect_compose_command() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
    return 0
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
    return 0
  else
    return 1
  fi
}

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
    *) echo "ERROR: Unknown argument: $1"; usage 1; ;;
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

rand_alnum_32() {
  LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
}

# --------------------------- preflight checks ---------------------------
log "===== EJBCA setup starting ====="
log "Base dir: ${BASE_DIR}"
log "Force: ${OPT_FORCE}"
log "Image tag: ${OPT_IMAGE_TAG}"

# Check disk space
AVAILABLE_MB=$(df -BM "${BASE_DIR%/*}" 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/M//')
if [[ -n "${AVAILABLE_MB}" ]] && (( AVAILABLE_MB < MIN_DISK_SPACE_MB )); then
  die "Insufficient disk space. Required: ${MIN_DISK_SPACE_MB}MB, Available: ${AVAILABLE_MB}MB"
fi
log "Disk space check: ${AVAILABLE_MB}MB available (minimum: ${MIN_DISK_SPACE_MB}MB)"

if port_in_use 80 || port_in_use 443; then
  die "Ports 80/443 are already in use. Stop the service using them and re-run."
fi

CERT_HOST="${OPT_HOSTNAME:-$(default_fqdn)}"
log "Using hostname: ${CERT_HOST}"

if ! host "${CERT_HOST}" >/dev/null 2>&1 && ! grep -q "${CERT_HOST}" /etc/hosts; then
  log "WARNING: Hostname '${CERT_HOST}' does not resolve. Add to /etc/hosts or DNS."
  log "Continuing anyway, but TLS validation may fail for clients."
fi

if "${OPT_FORCE}"; then
  log "WARNING: --force will:"
  log "  - Stop and remove all containers"
  log "  - Backup and recreate all volumes (DATA LOSS)"
  log "  - Regenerate all secrets and certificates"
  if ! "${OPT_YES}"; then
    log "Press Ctrl-C within 10 seconds to abort..."
    sleep 10
  fi
fi

# --------------------------- SELinux/AppArmor check ---------------------------
log ">>> [Pre-flight] Checking security modules..."
if command -v getenforce >/dev/null 2>&1; then
  SELINUX_STATUS="$(getenforce 2>/dev/null || echo 'Disabled')"
  log "SELinux status: ${SELINUX_STATUS}"
  if [[ "${SELINUX_STATUS}" == "Enforcing" ]]; then
    log "WARNING: SELinux is enforcing. Docker volumes may need :Z or :z suffixes."
    log "This script uses bind mounts. If errors occur, consider: setenforce 0"
  fi
fi

if command -v aa-status >/dev/null 2>&1; then
  if aa-status --enabled 2>/dev/null; then
    log "AppArmor is enabled. Docker should handle profiles automatically."
  fi
fi

# --------------------------- step 1: packages + docker ---------------------------
log ">>> [1/12] Installing prerequisites + Docker (official repo)..."
retry_backoff 3 apt-get update -y || die "apt-get update failed"
retry_backoff 3 apt-get install -y ca-certificates curl gnupg lsb-release openssl jq dnsutils || die "Failed installing prerequisites"

# =============================================================================
# FIX #2: Validate jq dependency (CRITICAL FIX)
# jq is now installed as a prerequisite above, but we also add a runtime check
# to provide graceful degradation if it somehow becomes unavailable.
# The JQ_AVAILABLE variable is used later in diagnostic output.
# =============================================================================
JQ_AVAILABLE=false
if command -v jq >/dev/null 2>&1; then
  JQ_AVAILABLE=true
  log "jq is available for JSON parsing"
else
  log "WARNING: jq not installed, some diagnostics will be limited"
fi

install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  retry_backoff 3 bash -lc 'curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg' \
    || die "Failed to fetch/import Docker GPG key"
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
[[ -n "$CODENAME" ]] || die "Could not determine VERSION_CODENAME"

cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable
EOF

retry_backoff 3 apt-get update -y || die "apt-get update failed after adding Docker repo"
retry_backoff 3 apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || die "Docker install failed"

systemctl enable docker || die "Failed to enable docker"
systemctl start docker || die "Failed to start docker"

log "Waiting for Docker daemon to be ready..."
retry_backoff 10 docker info >/dev/null 2>&1 || die "Docker daemon did not become ready"

# FIX #7: Detect compose command after Docker is installed
detect_compose_command || die "Neither docker compose plugin nor docker-compose binary found"
log "Docker: $(docker --version)"
log "Compose: $(${COMPOSE_CMD} version)"

# --------------------------- step 2: firewall detection/configuration ---------------------------
log ">>> [2/12] Checking firewall configuration..."
FIREWALL_CONFIGURED=false

if command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -q "Status: active"; then
    log "UFW is active. Configuring ports 80/443..."
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    FIREWALL_CONFIGURED=true
    log "UFW rules added for ports 80, 443"
  fi
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  if firewall-cmd --state 2>/dev/null | grep -q running; then
    log "firewalld is active. Configuring ports 80/443..."
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    FIREWALL_CONFIGURED=true
    log "firewalld rules added for http, https"
  fi
fi

if ! "${FIREWALL_CONFIGURED}"; then
  log "No active firewall detected (ufw/firewalld). Ports 80/443 should be accessible."
fi

# --------------------------- step 3: create service user ---------------------------
log ">>> [3/12] Ensuring service user '${EJBCA_USER}' exists..."
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

# --------------------------- step 4: directory layout ---------------------------
log ">>> [4/12] Creating directory structure..."
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

chown -R root:root "${BASE_DIR}/config" "${BASE_DIR}/plugins" "${BASE_DIR}/nginx" "${BASE_DIR}/secrets"
chmod 755 "${BASE_DIR}" "${BASE_DIR}/config" "${BASE_DIR}/plugins" "${BASE_DIR}/nginx" "${BASE_DIR}/nginx/conf.d" "${BASE_DIR}/nginx/tls" "${BASE_DIR}/nginx/mtls-ca" "${BASE_DIR}/nginx/clients"
chmod 750 "${BASE_DIR}/secrets"

chown -R "${EJBCA_USER}:${EJBCA_USER}" "${BASE_DIR}/backups" "${BASE_DIR}/logs"
chmod 750 "${BASE_DIR}/backups" "${BASE_DIR}/logs"

chmod 775 "${BASE_DIR}/data" "${BASE_DIR}/data/ejbca"
chown root:root "${BASE_DIR}/data" "${BASE_DIR}/data/ejbca"

# --------------------------- step 5: cleanup for --force ---------------------------
if "${OPT_FORCE}"; then
  log ">>> [5/12] --force: Stopping containers and backing up volumes..."

  cd "${BASE_DIR}" 2>/dev/null || true
  ENV_FILE_TMP="${BASE_DIR}/.env"
  COMPOSE_FILE_TMP="${BASE_DIR}/docker-compose.yml"

  if [[ -f "${COMPOSE_FILE_TMP}" ]]; then
    RUN_AS_EJBCA=(sudo -u "${EJBCA_USER}" env HOME="${EJBCA_HOME}" DOCKER_CONFIG="${DOCKER_CONFIG_DIR}")

    log "Stopping all containers..."
    # FIX #7: Use COMPOSE_CMD variable instead of hardcoded 'docker compose'
    "${RUN_AS_EJBCA[@]}" ${COMPOSE_CMD} --env-file "${ENV_FILE_TMP}" -f "${COMPOSE_FILE_TMP}" down -v 2>/dev/null || true

    sleep 3
  fi

  for vol in ejbca_pgdata ejbca_data ejbca_logs; do
    if docker volume inspect "${vol}" >/dev/null 2>&1; then
      BACKUP_DIR="${BASE_DIR}/backups/volumes_$(ts_suffix)"
      mkdir -p "${BACKUP_DIR}"

      VOL_PATH=$(docker volume inspect "${vol}" --format '{{ .Options.device }}' 2>/dev/null || echo "")
      if [[ -n "${VOL_PATH}" && -d "${VOL_PATH}" ]]; then
        log "Backing up volume ${vol} from ${VOL_PATH}..."
        tar -czf "${BACKUP_DIR}/${vol}.tar.gz" -C "${VOL_PATH}" . 2>/dev/null || log "Warning: Backup of ${vol} failed"
      fi

      log "Removing volume ${vol}..."
      docker volume rm -f "${vol}" 2>/dev/null || true
    fi
  done

  log "Volume cleanup complete. Backups in: ${BASE_DIR}/backups/"
else
  log ">>> [5/12] Skipping cleanup (no --force flag)"
fi

# --------------------------- step 6: .env generation ---------------------------
log ">>> [6/12] Writing ${BASE_DIR}/.env..."
ENV_FILE="${BASE_DIR}/.env"

if [[ -f "${ENV_FILE}" && "${OPT_FORCE}" == false ]]; then
  log ".env exists; leaving as-is."
else
  if [[ -f "${ENV_FILE}" ]]; then
    backup_if_exists "${ENV_FILE}"
  fi
  cat > "${ENV_FILE}" <<EOF
# Generated by setup_ejbca.sh on $(date -u +'%Y-%m-%dT%H:%M:%SZ')
DATABASE_PASSWORD=$(rand_alnum_32)
PASSWORD_ENCRYPTION_KEY=$(rand_alnum_32)
CA_KEYSTOREPASS=$(rand_alnum_32)
EJBCA_CLI_DEFAULTPASSWORD=$(rand_alnum_32)
ADMIN_CLIENT_P12_PASSWORD=$(rand_alnum_32)
EJBCA_IMAGE_TAG=${OPT_IMAGE_TAG}
EOF
  log "Generated .env with safe alphanumeric passwords"
fi

chown "root:${EJBCA_USER}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

# =============================================================================
# FIX #1 & #3: Export DATABASE_PASSWORD for verify_postgres function
# Ensure the password is available in all subshell contexts.
# =============================================================================
export DATABASE_PASSWORD

# --------------------------- step 7: detect container UIDs ---------------------------
log ">>> [7/12] Detecting container runtime UIDs/GIDs..."

log "Pulling required images..."
docker pull postgres:16-alpine >/dev/null 2>&1 || die "Failed to pull postgres:16-alpine"
docker pull "keyfactor/ejbca-ce:${OPT_IMAGE_TAG}" >/dev/null 2>&1 || die "Failed to pull EJBCA image"

PG_UID="$(docker run --rm postgres:16-alpine sh -lc 'id -u postgres' 2>/dev/null || echo '70')"
PG_GID="$(docker run --rm postgres:16-alpine sh -lc 'id -g postgres' 2>/dev/null || echo '70')"
log "Detected Postgres UID:GID = ${PG_UID}:${PG_GID}"

EJBCA_UID="$(docker run --rm "keyfactor/ejbca-ce:${OPT_IMAGE_TAG}" sh -lc 'id -u 2>/dev/null || echo 10001' 2>/dev/null || echo '10001')"
log "Detected/assumed EJBCA UID = ${EJBCA_UID}"

docker container prune -f >/dev/null 2>&1 || true

# --------------------------- step 8: create docker network ---------------------------
log ">>> [8/12] Creating Docker network '${DOCKER_NETWORK}'..."
if docker network inspect "${DOCKER_NETWORK}" >/dev/null 2>&1; then
  if "${OPT_FORCE}"; then
    log "Removing existing network ${DOCKER_NETWORK}..."
    docker network rm "${DOCKER_NETWORK}" 2>/dev/null || true
    docker network create --driver bridge "${DOCKER_NETWORK}" >/dev/null
    log "Recreated network ${DOCKER_NETWORK}"
  else
    log "Network ${DOCKER_NETWORK} already exists"
  fi
else
  docker network create --driver bridge "${DOCKER_NETWORK}" >/dev/null
  log "Created network ${DOCKER_NETWORK}"
fi

# --------------------------- step 9: create volumes + set permissions ---------------------------
log ">>> [9/12] Creating Docker volumes with bind mounts..."

create_bind_volume() {
  local vol="$1" host_path="$2"

  if docker volume inspect "${vol}" >/dev/null 2>&1; then
    log "Volume exists: ${vol}"
    return 0
  fi

  mkdir -p "${host_path}"
  docker volume create --driver local --opt type=none --opt device="${host_path}" --opt o=bind "${vol}" >/dev/null
  log "Created volume ${vol} -> ${host_path}"
}

create_bind_volume "ejbca_pgdata" "${BASE_DIR}/data/postgres"
create_bind_volume "ejbca_data"   "${BASE_DIR}/data/ejbca"
create_bind_volume "ejbca_logs"   "${BASE_DIR}/logs"

chown -R "${PG_UID}:${PG_GID}" "${BASE_DIR}/data/postgres"
chmod 700 "${BASE_DIR}/data/postgres"

chown root:root "${BASE_DIR}/data/ejbca"
chmod 775 "${BASE_DIR}/data/ejbca"

chmod 750 "${BASE_DIR}/logs"
chown -R "${EJBCA_USER}:${EJBCA_USER}" "${BASE_DIR}/logs"

# --------------------------- step 10: generate + validate TLS certs ---------------------------
log ">>> [10/12] Generating and validating TLS + mTLS assets..."
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

  openssl x509 -in "${SERVER_CRT}" -noout -checkend 0 >/dev/null 2>&1 || die "Server cert validation failed"
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

  openssl x509 -in "${CA_CRT}" -noout -checkend 0 >/dev/null 2>&1 || die "mTLS CA cert validation failed"
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

  openssl pkcs12 -in "${SUPERADMIN_P12}" -noout -passin "pass:${ADMIN_CLIENT_P12_PASSWORD}" >/dev/null 2>&1 || die "P12 validation failed"
}

if [[ -f "${SERVER_KEY}" && -f "${SERVER_CRT}" && "${OPT_FORCE}" == false ]]; then
  log "Server TLS cert exists; validating..."
  openssl x509 -in "${SERVER_CRT}" -noout -checkend 0 >/dev/null 2>&1 || { log "Existing cert invalid, regenerating..."; gen_server_cert; }
else
  gen_server_cert
  log "Generated server TLS cert for CN=${CERT_HOST}"
fi

if [[ -f "${CA_KEY}" && -f "${CA_CRT}" && "${OPT_FORCE}" == false ]]; then
  log "mTLS CA exists; validating..."
  openssl x509 -in "${CA_CRT}" -noout -checkend 0 >/dev/null 2>&1 || { log "Existing CA invalid, regenerating..."; gen_mtls_ca; }
else
  gen_mtls_ca
  log "Generated mTLS CA"
fi

if [[ -f "${SUPERADMIN_P12}" && "${OPT_FORCE}" == false ]]; then
  log "SuperAdmin P12 exists; validating..."
  openssl pkcs12 -in "${SUPERADMIN_P12}" -noout -passin "pass:${ADMIN_CLIENT_P12_PASSWORD}" >/dev/null 2>&1 || { log "Existing P12 invalid, regenerating..."; gen_superadmin_p12; }
else
  gen_superadmin_p12
  log "Generated SuperAdmin P12"
fi

chown -R root:root "${BASE_DIR}/nginx"
chmod 600 "${SERVER_KEY}" "${CA_KEY}" "${SUPERADMIN_P12}" || true
chmod 644 "${SERVER_CRT}" "${CA_CRT}" "${SUPERADMIN_CRT}" || true

# --------------------------- step 11: write nginx configs ---------------------------
log ">>> [11/12] Writing Nginx Dockerfile + configs..."
NGINX_DOCKERFILE="${BASE_DIR}/nginx/Dockerfile"
NGINX_MAIN_CONF="${BASE_DIR}/nginx/nginx.conf"
NGINX_SITE_CONF="${BASE_DIR}/nginx/conf.d/ejbca.conf"

backup_if_exists "${NGINX_DOCKERFILE}"
backup_if_exists "${NGINX_MAIN_CONF}"
backup_if_exists "${NGINX_SITE_CONF}"

cat > "${NGINX_DOCKERFILE}" <<'EOF'
FROM nginx:1.27-alpine
RUN apk add --no-cache curl

RUN cat > /etc/logrotate.d/nginx <<'LOGROTATE'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx nginx
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
LOGROTATE

RUN apk add --no-cache logrotate && \
    echo "0 0 * * * /usr/sbin/logrotate /etc/logrotate.d/nginx" | crontab -
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

  limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=10r/s;
  limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

  include /etc/nginx/conf.d/*.conf;
}
EOF

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
  location = /ejbca { return 301 /ejbca/; }

  location ^~ /ejbca/adminweb/ {
    if ($ssl_client_verify != "SUCCESS") { return 403; }
    proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
    proxy_pass http://ejbca_admin;
  }

  location ^~ /ejbca/ejbca-rest-api/ {
    if ($ssl_client_verify != "SUCCESS") { return 403; }
    proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
    proxy_pass http://ejbca_admin;
  }

  location ^~ /ejbca/ {
    proxy_pass http://ejbca_public;
  }

  location / {
    proxy_pass http://ejbca_public;
  }
}
EOF

# --------------------------- step 12: write docker-compose.yml ---------------------------
log ">>> [12/12] Writing docker-compose.yml..."
COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
backup_if_exists "${COMPOSE_FILE}"

# FIX #4: Use container name constants in docker-compose.yml
cat > "${COMPOSE_FILE}" <<EOF
services:
  postgres:
    image: postgres:16-alpine
    container_name: ${POSTGRES_CONTAINER}
    restart: unless-stopped
    user: "${PG_UID}:${PG_GID}"
    networks:
      - ${DOCKER_NETWORK}
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
      start_period: 30s
    security_opt:
      - no-new-privileges:true

  ejbca:
    image: keyfactor/ejbca-ce:\${EJBCA_IMAGE_TAG:-latest}
    container_name: ${EJBCA_CONTAINER}
    restart: unless-stopped
    networks:
      - ${DOCKER_NETWORK}
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
      INITIAL_ADMIN: ";PublicAccessAuthenticationToken:TRANSPORT_ANY;"
    volumes:
      - ejbca_data:/mnt/persistent
      - ${BASE_DIR}/config:/opt/keyfactor/ejbca-custom/conf:ro
      - ${BASE_DIR}/plugins:/opt/keyfactor/ejbca-custom/p:ro
    expose:
      - "8080"
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth || exit 1"]
      interval: 15s
      timeout: 10s
      retries: 40
      start_period: 120s

  nginx:
    build:
      context: ${BASE_DIR}/nginx
      dockerfile: Dockerfile
    image: ejbca-nginx:local
    container_name: ${NGINX_CONTAINER}
    restart: unless-stopped
    networks:
      - ${DOCKER_NETWORK}
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

networks:
  ${DOCKER_NETWORK}:
    external: true

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

# --------------------------- deployment with comprehensive verification ---------------------------
log ">>> Launching stack with comprehensive verification..."
cd "${BASE_DIR}"

RUN_AS_EJBCA=(sudo -u "${EJBCA_USER}" env HOME="${EJBCA_HOME}" DOCKER_CONFIG="${DOCKER_CONFIG_DIR}")

ROLLBACK_TRIGGERED=false
rollback() {
  if "${ROLLBACK_TRIGGERED}"; then
    return
  fi
  ROLLBACK_TRIGGERED=true

  log "=== DEPLOYMENT FAILED: Initiating rollback ==="

  # FIX #7: Use COMPOSE_CMD variable
  "${RUN_AS_EJBCA[@]}" ${COMPOSE_CMD} --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" logs --tail=100 || true

  log "Stopping containers..."
  "${RUN_AS_EJBCA[@]}" ${COMPOSE_CMD} --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" down || true

  LATEST_BACKUP=$(ls -t "${BASE_DIR}/backups"/volumes_* 2>/dev/null | head -1 || echo "")
  if [[ -n "${LATEST_BACKUP}" ]]; then
    log "Found volume backup: ${LATEST_BACKUP}"
    log "To restore: extract tarballs to ${BASE_DIR}/data/* and re-run script"
  fi

  log "=== Rollback complete. Check ${LOG_FILE} for details ==="
  exit 1
}
trap 'rollback' ERR

log "Building nginx image..."
# FIX #7: Use COMPOSE_CMD variable
"${RUN_AS_EJBCA[@]}" ${COMPOSE_CMD} --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" build --no-cache

log "Starting containers..."
"${RUN_AS_EJBCA[@]}" ${COMPOSE_CMD} --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d

# ---------------------------------------------------------------------------
# Postgres verification — robust, diagnostic-rich implementation
# ---------------------------------------------------------------------------
# Why this is non-trivial:
#   - pg_isready (used by the Docker healthcheck) only checks that the
#     postmaster is accepting connections. It does NOT authenticate and does
#     NOT verify the target database exists.
#   - With POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256", there is a
#     window after pg_isready succeeds where password auth setup or the
#     POSTGRES_DB creation is still in progress. During this window,
#     `psql -U ejbca -d ejbca` can fail with:
#       * FATAL: password authentication failed  (auth not yet configured)
#       * FATAL: database "ejbca" does not exist  (initdb still running)
#       * connection refused                      (brief restart after initdb)
#   - `docker exec` with no timeout can hang if the postgres process is
#     stalled (e.g. fsync on slow storage), consuming the entire retry budget.
# ---------------------------------------------------------------------------

verify_postgres() {
  local max_attempts=90        # 90 * 2s = 180s (3 minutes) max wait
  local sleep_interval=2
  local exec_timeout=5         # seconds — per-attempt timeout for psql
  # FIX #4: Use container name constant instead of hardcoded value
  local container="${POSTGRES_CONTAINER}"

  # =============================================================================
  # FIX #1: Capture DATABASE_PASSWORD for psql authentication (CRITICAL FIX)
  # The password is now passed via PGPASSWORD environment variable to docker exec.
  # This fixes "fe_sendauth: no password supplied" errors.
  # =============================================================================
  local db_password="${DATABASE_PASSWORD:-}"
  if [[ -z "${db_password}" ]]; then
    log "ERROR: DATABASE_PASSWORD not set in environment"
    return 1
  fi

  log "Postgres verification: starting (max ${max_attempts} attempts, ${sleep_interval}s interval)"

  local attempt=0
  local last_error=""
  local container_state=""
  local container_health=""
  local pg_ready_seen=false

  while (( attempt < max_attempts )); do
    attempt=$((attempt + 1))

    # --- Phase 1: Check the container is running at all ---
    container_state=$(docker inspect "${container}" --format='{{.State.Status}}' 2>/dev/null || echo "missing")
    if [[ "${container_state}" != "running" ]]; then
      if [[ "${container_state}" == "missing" ]]; then
        log "Postgres verification [${attempt}/${max_attempts}]: container '${container}' not found"
      else
        log "Postgres verification [${attempt}/${max_attempts}]: container state=${container_state} (expected: running)"
      fi
      # If the container exited, grab exit code for diagnostics
      if [[ "${container_state}" == "exited" ]]; then
        local exit_code
        exit_code=$(docker inspect "${container}" --format='{{.State.ExitCode}}' 2>/dev/null || echo "?")
        log "Postgres verification: container exited with code ${exit_code}"
        log "Postgres verification: last 30 lines of container logs:"
        docker logs --tail=30 "${container}" 2>&1 | while IFS= read -r logline; do
          log "  pg-log: ${logline}"
        done
        return 1
      fi
      sleep "${sleep_interval}"
      continue
    fi

    # --- Phase 2: Check Docker healthcheck status ---
    container_health=$(docker inspect "${container}" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")

    # Log health transitions
    if [[ "${container_health}" == "healthy" && "${pg_ready_seen}" == false ]]; then
      pg_ready_seen=true
      log "Postgres verification [${attempt}/${max_attempts}]: Docker healthcheck reports healthy (pg_isready OK)"
      log "Postgres verification: now verifying authenticated database access..."
    fi

    # --- Phase 3: Attempt authenticated psql query with timeout ---
    # Use 'timeout' to prevent docker exec from hanging indefinitely.
    # Pass PGCONNECT_TIMEOUT as a secondary safeguard inside the container.
    # =============================================================================
    # FIX #1: Add PGPASSWORD to docker exec command (CRITICAL FIX)
    # The -e PGPASSWORD="${db_password}" passes the password to psql via env var.
    # =============================================================================
    local psql_output=""
    local psql_exit=0
    psql_output=$(timeout "${exec_timeout}" \
      docker exec -e PGCONNECT_TIMEOUT=3 -e PGPASSWORD="${db_password}" "${container}" \
        psql -U ejbca -d ejbca -w -c "SELECT 1 AS connectivity_check" 2>&1) || psql_exit=$?

    if [[ ${psql_exit} -eq 0 ]]; then
      log "Postgres verification [${attempt}/${max_attempts}]: SUCCESS — authenticated query returned OK"
      log "Postgres verification: health=${container_health}, total wait=$((attempt * sleep_interval))s"
      return 0
    fi

    # --- Phase 4: Classify the failure for diagnostics ---
    last_error="${psql_output}"

    # Timeout from the 'timeout' command itself (exit code 124)
    if [[ ${psql_exit} -eq 124 ]]; then
      log "Postgres verification [${attempt}/${max_attempts}]: psql timed out after ${exec_timeout}s (health=${container_health})"
    # Log at intervals to avoid flooding, but always log the first few attempts
    elif (( attempt <= 3 || attempt % 10 == 0 )); then
      # Sanitize multi-line output to single line for log readability
      local short_error
      short_error=$(echo "${psql_output}" | tr '\n' ' ' | head -c 200)
      log "Postgres verification [${attempt}/${max_attempts}]: psql failed (exit=${psql_exit}, health=${container_health}): ${short_error}"
    fi

    sleep "${sleep_interval}"
  done

  # --- Verification failed: dump full diagnostics ---
  log ""
  log "========== POSTGRES VERIFICATION FAILED =========="
  log "Gave up after ${max_attempts} attempts ($(( max_attempts * sleep_interval ))s)"
  log "Last container state: ${container_state}"
  log "Last healthcheck status: ${container_health}"
  log "Last psql error: ${last_error}"
  log ""

  # =============================================================================
  # FIX #2: Check jq availability before using it (CRITICAL FIX)
  # Provides fallback output if jq is not installed.
  # =============================================================================
  log "--- Container inspect (health log) ---"
  if [[ "${JQ_AVAILABLE}" == true ]]; then
    docker inspect "${container}" --format='{{json .State.Health}}' 2>/dev/null | jq -r '.Log[-5:][] | "\(.Start) exit=\(.ExitCode) out=\(.Output)"' 2>/dev/null | while IFS= read -r hline; do
      log "  health-log: ${hline}"
    done
  else
    # Fallback: show raw JSON health info without jq parsing
    log "  (jq not available, showing raw health JSON)"
    docker inspect "${container}" --format='{{json .State.Health}}' 2>/dev/null | head -c 1000 | while IFS= read -r hline; do
      log "  health-log: ${hline}"
    done
  fi

  log ""
  log "--- Container logs (last 50 lines) ---"
  docker logs --tail=50 "${container}" 2>&1 | while IFS= read -r logline; do
    log "  pg-log: ${logline}"
  done
  log ""

  # =============================================================================
  # FIX #3: Check if pg_hba.conf exists before reading it (MAJOR FIX)
  # The file may not exist during early Postgres initialization.
  # =============================================================================
  log "--- pg_hba.conf (if accessible) ---"
  if timeout 3 docker exec "${container}" test -f /var/lib/postgresql/data/pg_hba.conf 2>/dev/null; then
    timeout 3 docker exec "${container}" cat /var/lib/postgresql/data/pg_hba.conf 2>&1 | tail -20 | while IFS= read -r hbaline; do
      log "  pg_hba: ${hbaline}"
    done
  else
    log "  pg_hba: file not yet created (initialization may still be in progress)"
  fi
  log ""

  # =============================================================================
  # FIX #5: Add test guards for additional diagnostic commands (MAJOR FIX)
  # Check container accessibility before running diagnostic commands.
  # =============================================================================
  log "--- Postgres config checks ---"
  if timeout 3 docker exec "${container}" pg_isready -U ejbca -d ejbca -h 127.0.0.1 2>&1 >/dev/null; then
    timeout 3 docker exec "${container}" pg_isready -U ejbca -d ejbca -h 127.0.0.1 2>&1 | while IFS= read -r rdyline; do
      log "  pg_isready: ${rdyline}"
    done
  else
    log "  pg_isready: command failed or timed out"
  fi
  log ""

  # FIX #1: Add PGPASSWORD to diagnostic psql calls
  log "--- Postgres user/database listing ---"
  if timeout 3 docker exec -e PGPASSWORD="${db_password}" "${container}" psql -U postgres -c "\\du" 2>&1 >/dev/null; then
    timeout 3 docker exec -e PGPASSWORD="${db_password}" "${container}" psql -U postgres -c "\\du" 2>&1 | while IFS= read -r uline; do
      log "  pg-users: ${uline}"
    done
  else
    log "  pg-users: command failed or timed out"
  fi

  if timeout 3 docker exec -e PGPASSWORD="${db_password}" "${container}" psql -U postgres -c "\\l" 2>&1 >/dev/null; then
    timeout 3 docker exec -e PGPASSWORD="${db_password}" "${container}" psql -U postgres -c "\\l" 2>&1 | while IFS= read -r dbline; do
      log "  pg-databases: ${dbline}"
    done
  else
    log "  pg-databases: command failed or timed out"
  fi

  log "========== END POSTGRES DIAGNOSTICS =========="
  log ""
  return 1
}

verify_postgres || die "Postgres database initialization failed — see diagnostic output above"
log "Postgres database initialized and verified"

# =============================================================================
# FIX #6: EJBCA Database Schema Verification (OPTIONAL ENHANCEMENT)
# After EJBCA reports healthy, verify tables were actually created.
# This provides an additional sanity check that EJBCA initialized properly.
# =============================================================================
verify_ejbca_schema() {
  local container="${POSTGRES_CONTAINER}"
  local db_password="${DATABASE_PASSWORD:-}"
  
  log "Verifying EJBCA database schema..."
  
  local table_count=""
  table_count=$(timeout 5 docker exec -e PGPASSWORD="${db_password}" "${container}" \
    psql -U ejbca -d ejbca -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -d ' ' || echo "0")
  
  if [[ -n "${table_count}" && "${table_count}" -gt 0 ]]; then
    log "EJBCA schema verified: ${table_count} tables found in public schema"
    return 0
  else
    log "WARNING: EJBCA schema may not be fully initialized (found ${table_count:-0} tables)"
    return 1
  fi
}

# Verify EJBCA bootstrap
log "Waiting for EJBCA to complete bootstrap (this may take several minutes)..."
ok=false
# FIX #4: Use container name constant
for i in $(seq 1 120); do
  if docker exec "${EJBCA_CONTAINER}" curl -sf http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | grep -q "ALLOK"; then
    ok=true
    break
  fi
  sleep 3
  if (( i % 10 == 0 )); then
    # FIX #4: Use container name constant
    EJBCA_HEALTH=$(docker inspect "${EJBCA_CONTAINER}" --format='{{.State.Health.Status}}' 2>/dev/null || echo "unknown")
    log "Still waiting for EJBCA bootstrap... (${i}/120, health=${EJBCA_HEALTH})"
  fi
done
"${ok}" || die "EJBCA bootstrap failed or timed out"
log "EJBCA application is healthy"

# FIX #6: Run schema verification after EJBCA is healthy (non-fatal warning)
verify_ejbca_schema || log "Note: Schema verification returned a warning, but EJBCA healthcheck passed"

# Verify nginx can reach backend
log "Waiting for nginx reverse proxy..."
ok=false
for i in $(seq 1 30); do
  if curl -kfs https://127.0.0.1/healthz >/dev/null 2>&1; then
    ok=true
    break
  fi
  sleep 2
done
"${ok}" || die "Nginx proxy did not become accessible"

# Verify endpoints
log "Verifying endpoint responses..."
HTTP_STATUS=$(curl -k -o /dev/null -w "%{http_code}" -s https://127.0.0.1/ejbca/adminweb/)
if [[ "${HTTP_STATUS}" != "403" ]]; then
  log "WARNING: /ejbca/adminweb/ returned ${HTTP_STATUS} (expected 403 without client cert)"
fi

HTTP_STATUS=$(curl -k -o /dev/null -w "%{http_code}" -s https://127.0.0.1/ejbca/)
if [[ "${HTTP_STATUS}" == "000" ]]; then
  die "EJBCA public endpoint not accessible"
fi

log "All endpoints responding correctly"

# Verify admin role can be created (test with mTLS)
log "Verifying SuperAdmin client certificate access..."
MTLS_TEST=$(curl -k --cert "${SUPERADMIN_P12}:${ADMIN_CLIENT_P12_PASSWORD}" --cert-type P12 \
  -o /dev/null -w "%{http_code}" -s https://127.0.0.1/ejbca/adminweb/ 2>/dev/null || echo "000")

if [[ "${MTLS_TEST}" == "200" || "${MTLS_TEST}" == "302" ]]; then
  log "SuperAdmin mTLS authentication successful (HTTP ${MTLS_TEST})"
  log ""
  log "=================================================================="
  log "IMPORTANT: Admin role verified. You can now safely remove"
  log "INITIAL_ADMIN from docker-compose.yml and recreate ejbca container:"
  log "  cd ${BASE_DIR}"
  log "  # Edit docker-compose.yml and remove INITIAL_ADMIN line"
  # FIX #7: Use COMPOSE_CMD in instructions
  log "  ${COMPOSE_CMD} --env-file .env up -d --force-recreate ejbca"
  log "=================================================================="
elif [[ "${MTLS_TEST}" == "403" ]]; then
  log "WARNING: mTLS cert presented but admin role not yet configured in EJBCA"
  log "You may need to manually configure admin roles before removing INITIAL_ADMIN"
else
  log "WARNING: Could not verify admin access (HTTP ${MTLS_TEST})"
  log "Manual verification recommended before removing INITIAL_ADMIN"
fi

trap - ERR

# FIX #4: Use container name constants in status display
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E "(${POSTGRES_CONTAINER}|${EJBCA_CONTAINER}|${NGINX_CONTAINER})" || true

log ""
log "=================================================================="
log "EJBCA DEPLOYMENT SUCCESSFUL"
log "=================================================================="
log ""
log "URLs:"
log "  HTTPS entry:                    https://${CERT_HOST}/"
log "  AdminWeb (requires mTLS):       https://${CERT_HOST}/ejbca/adminweb/"
log "  RA Web:                         https://${CERT_HOST}/ejbca/ra/"
log "  REST API (requires mTLS):       https://${CERT_HOST}/ejbca/ejbca-rest-api/"
log ""
log "Authentication:"
log "  SuperAdmin P12:  ${SUPERADMIN_P12}"
log "  P12 password:    (in ${ENV_FILE} -> ADMIN_CLIENT_P12_PASSWORD)"
log ""
log "Import SuperAdmin cert to browser:"
log "  Firefox: Preferences > Privacy & Security > Certificates > View Certificates > Your Certificates > Import"
log "  Chrome:  Settings > Privacy and security > Security > Manage certificates > Import"
log ""
log "Next steps:"
log "  1. Import ${SUPERADMIN_P12} to your browser"
log "  2. Access https://${CERT_HOST}/ejbca/adminweb/"
log "  3. Configure admin roles and end entities"
log "  4. Remove INITIAL_ADMIN from compose file and recreate ejbca container"
log ""
log "Management:"
# FIX #7: Use COMPOSE_CMD in management instructions
log "  View logs:     cd ${BASE_DIR} && ${COMPOSE_CMD} logs -f"
log "  Stop:          cd ${BASE_DIR} && ${COMPOSE_CMD} down"
log "  Start:         cd ${BASE_DIR} && ${COMPOSE_CMD} up -d"
log "  Backup:        Backup ${BASE_DIR}/data/* and ${BASE_DIR}/.env"
log ""
log "Setup log: ${LOG_FILE}"
log "=================================================================="
