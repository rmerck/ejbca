# EJBCA CE Docker Deployment (Debian 13) — PostgreSQL + Nginx (TLS + mTLS)

A production-grade, fully automated deployment script for **EJBCA Community Edition** backed by **PostgreSQL 16** and fronted by an **Nginx reverse proxy** for TLS termination and **mTLS enforcement** on administrative endpoints.

The goal is a **repeatable, one-run** deployment suitable for a dedicated VM (e.g., AWS EC2), with persistent storage and secure defaults.

---

## What This Does

`setup_ejbca.sh`:

- Installs Docker Engine + Docker Compose (plugin or standalone)
- Creates a dedicated service user (`ejbca`) and required directories under `/opt/ejbca`
- Creates **named Docker volumes bound to host paths** for persistence
- Deploys:
  - `postgres:16-alpine` with **SCRAM-SHA-256** authentication
  - `keyfactor/ejbca-ce` with persistent state stored under `/mnt/persistent`
  - Custom Nginx reverse proxy for TLS termination
- Generates:
  - Self-signed server TLS certificate for Nginx
  - mTLS CA (for administrative access enforcement at the proxy)
  - `SuperAdmin` client certificate bundle (`.p12`) for browser import
- Enforces **mTLS** on:
  - `/ejbca/adminweb/`
  - `/ejbca/ejbca-rest-api/`
- Performs health checks and validation
- Logs all output to: `/var/log/ejbca-setup.log`

---

## Architecture

```
Internet / Client Browser
        |
        | 443 (HTTPS)
        v
+-------------------------+
| Nginx (TLS termination) |
| - 80 -> 301 to HTTPS    |
| - 443 TLS               |
| - mTLS enforced on:     |
|    /ejbca/adminweb/     |
|    /ejbca/ejbca-rest-api|
+------------+------------+
             |
             | Docker bridge network (ejbca_net)
             v
+-------------------------+
| EJBCA CE (keyfactor)    |
| - HTTP listener :8080   |
| - Persistent: /mnt/persistent
+------------+------------+
             |
             v
+-------------------------+
| PostgreSQL 16           |
| - SCRAM-SHA-256 auth    |
| - Persistent: /var/lib/postgresql/data
+-------------------------+

Host persistence (bind-backed named volumes):
- /opt/ejbca/data/postgres  -> PostgreSQL data
- /opt/ejbca/data/ejbca     -> EJBCA persistent state
- /opt/ejbca/logs           -> Nginx logs
```

---

## Prerequisites

### Operating System

| Requirement | Specification |
|-------------|---------------|
| OS | Debian 12 (Bookworm) or Debian 13 (Trixie) |
| Architecture | x86_64 / amd64 |
| RAM | Minimum 4 GB (8 GB recommended) |
| Disk | Minimum 5 GB free space |
| Privileges | Root access required |

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 80 | TCP | HTTP (redirects to HTTPS) |
| 443 | TCP | HTTPS (all EJBCA traffic) |

Both ports must be available and not in use by other services. No EJBCA or PostgreSQL ports are exposed directly on the host.

### DNS / Hostname

- The script defaults the hostname to `hostname -f` (fallback to `hostname`)
- For best results, ensure your FQDN resolves in DNS or add an entry to `/etc/hosts`
- You can override with `--hostname`

---

## Quick Start

### 1. Download the Script

```bash
curl -O https://raw.githubusercontent.com/rmerck/ejbca/refs/heads/main/setup_ejbca.sh
chmod +x setup_ejbca.sh
```

### 2. Run the Deployment

```bash
# Basic deployment (uses system hostname)
sudo ./setup_ejbca.sh

# Specify a custom hostname
sudo ./setup_ejbca.sh --hostname pki.example.com

# Specify EJBCA image tag
sudo ./setup_ejbca.sh --image-tag latest

# Force reinstall (WARNING: destroys existing data)
sudo ./setup_ejbca.sh --force --yes
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--hostname <fqdn>` | Set the server hostname for certificates |
| `--image-tag <tag>` | EJBCA Docker image tag (default: `latest`) |
| `--force` | Regenerate all artifacts and recreate volumes (DATA LOSS) |
| `--yes` | Skip confirmation prompt for `--force` |
| `--help` | Display usage information |

---

## Script Behavior (Step-by-Step)

| Step | Description |
|------|-------------|
| 1 | **Preflight** — Check ports 80/443 available, disk space, DNS resolution |
| 2 | **Install dependencies** — Docker Engine + Compose from official APT repo |
| 3 | **Firewall** — Configure UFW or firewalld if active |
| 4 | **System user** — Create `ejbca` user with home `/home/ejbca` |
| 5 | **Directories** — Create `/opt/ejbca` tree structure |
| 6 | **Secrets** — Generate `.env` with strong random 32-char alphanumeric passwords |
| 7 | **Container UIDs** — Detect runtime UIDs for proper file permissions |
| 8 | **Docker network** — Create isolated `ejbca_net` bridge network |
| 9 | **Volumes** — Create bind-backed named volumes for persistence |
| 10 | **Certificates** — Generate server TLS, mTLS CA, and SuperAdmin client cert |
| 11 | **Nginx config** — Write Dockerfile and configuration files |
| 12 | **Deploy** — Build Nginx image, launch stack, verify health |

After launching, the script performs verification:
- Waits for PostgreSQL to accept authenticated connections
- Waits for EJBCA health check to report `ALLOK`
- Waits for Nginx to respond on HTTPS
- Validates endpoint responses
- Tests mTLS authentication with the SuperAdmin certificate

---

## Generated Artifacts

All generated assets live under `/opt/ejbca`:

### TLS Certificates

| File | Purpose | Location |
|------|---------|----------|
| `server.key` | Nginx TLS private key | `/opt/ejbca/nginx/tls/` |
| `server.crt` | Nginx TLS certificate | `/opt/ejbca/nginx/tls/` |

### mTLS CA

| File | Purpose | Location |
|------|---------|----------|
| `ca.key` | mTLS CA private key | `/opt/ejbca/nginx/mtls-ca/` |
| `ca.crt` | mTLS CA certificate | `/opt/ejbca/nginx/mtls-ca/` |

### SuperAdmin Client Bundle

| File | Purpose | Location |
|------|---------|----------|
| `superadmin.p12` | Admin client cert (PKCS#12) | `/opt/ejbca/nginx/clients/` |
| `superadmin.key` | Admin client private key | `/opt/ejbca/nginx/clients/` |
| `superadmin.crt` | Admin client certificate | `/opt/ejbca/nginx/clients/` |

### Secrets Storage

All sensitive values are stored in `/opt/ejbca/.env` (permissions: `640`, owner: `root:ejbca`):

```
DATABASE_PASSWORD=<random-32-char>
PASSWORD_ENCRYPTION_KEY=<random-32-char>
CA_KEYSTOREPASS=<random-32-char>
EJBCA_CLI_DEFAULTPASSWORD=<random-32-char>
ADMIN_CLIENT_P12_PASSWORD=<random-32-char>
EJBCA_IMAGE_TAG=<tag>
```

**Important:** Treat `.env` and all private keys as highly sensitive.

---

## Accessing EJBCA

### URLs

| Endpoint | URL | Authentication |
|----------|-----|----------------|
| Public Web | `https://<hostname>/ejbca/` | None |
| RA Web | `https://<hostname>/ejbca/ra/` | None (configurable) |
| Admin Web | `https://<hostname>/ejbca/adminweb/` | mTLS required |
| REST API | `https://<hostname>/ejbca/ejbca-rest-api/` | mTLS required |
| Health Check | `https://<hostname>/healthz` | None |

### Expected HTTP Responses

| Endpoint | Without Client Cert | With Valid Client Cert |
|----------|---------------------|------------------------|
| `/healthz` | 200 OK | 200 OK |
| `/ejbca/` | 200/302 | 200/302 |
| `/ejbca/ra/` | 200 OK | 200 OK |
| `/ejbca/adminweb/` | **403 Forbidden** | 200 OK or 302 Redirect |
| `/ejbca/ejbca-rest-api/` | **403 Forbidden** | 200 OK |

### Importing the SuperAdmin Certificate

First, retrieve the P12 password:

```bash
sudo grep '^ADMIN_CLIENT_P12_PASSWORD=' /opt/ejbca/.env
```

Copy `superadmin.p12` to your local machine, then import:

#### Firefox

1. Navigate to **Settings → Privacy & Security → Certificates**
2. Click **View Certificates**
3. Select the **Your Certificates** tab
4. Click **Import**
5. Select `superadmin.p12` and enter the password

#### Chrome / Edge

1. Navigate to **Settings → Privacy and security → Security**
2. Click **Manage certificates**
3. Select the **Your certificates** tab (or **Personal** on Windows)
4. Click **Import** and follow the wizard

#### macOS Keychain

1. Double-click `superadmin.p12`
2. Enter the password when prompted
3. The certificate will be added to your login keychain

#### Command Line (curl)

```bash
sudo bash -c '
P12_PASS=$(grep ADMIN_CLIENT_P12_PASSWORD /opt/ejbca/.env | cut -d= -f2)
curl -k --cert /opt/ejbca/nginx/clients/superadmin.p12:${P12_PASS} \
     --cert-type P12 \
     https://127.0.0.1/ejbca/adminweb/
'
```

After import, navigate to `https://<hostname>/ejbca/adminweb/` and select the SuperAdmin certificate when prompted.

---

## Security Model

### Why mTLS is Enforced

Administrative endpoints are high-impact targets. mTLS provides:

- **Strong authentication** — Certificate possession proves device/user identity
- **Reduced password reliance** — No passwords to phish or brute-force
- **Proxy-level enforcement** — Requests blocked before reaching EJBCA

mTLS is enforced only for:
- `/ejbca/adminweb/`
- `/ejbca/ejbca-rest-api/`

Public endpoints (`/ejbca/`, `/ejbca/ra/`) remain accessible without client certificates.

### Why EJBCA/PostgreSQL Ports Are Not Exposed

- **Minimizes attack surface** — Only ports 80/443 are accessible
- **Single controlled ingress** — All traffic flows through Nginx
- **Database isolation** — PostgreSQL is strictly internal to the Docker network

### How Secrets Are Protected

- `.env` file: permissions `640` (owner: `root`, group: `ejbca`)
- TLS private keys: permissions `600`
- CA private keys: permissions `600`
- P12 bundles: permissions `600`

---

## Persistence and Backups

### Critical Paths

| Path | Contents |
|------|----------|
| `/opt/ejbca/data/postgres/` | PostgreSQL database files |
| `/opt/ejbca/data/ejbca/` | EJBCA persistent state |
| `/opt/ejbca/.env` | All passwords and secrets |
| `/opt/ejbca/nginx/tls/` | Nginx server certificate and key |
| `/opt/ejbca/nginx/mtls-ca/` | mTLS CA certificate and key |
| `/opt/ejbca/nginx/clients/` | SuperAdmin P12 bundle |

### Backup Recommendations

- **Full VM snapshots** — EBS snapshots (AWS Backup) or equivalent
- **Database exports** — Scheduled `pg_dump` to external storage
- **Secrets backup** — Securely store `.env` and all private keys off-server
- **Test restores** — Regularly verify backup integrity

---

## Common Troubleshooting

### AdminWeb Returns 403

**Expected behavior** unless a valid client certificate is presented.

**Solution:**
1. Import `/opt/ejbca/nginx/clients/superadmin.p12` into your browser
2. Ensure you select the certificate when prompted
3. Clear any cached certificate selections in your browser

### Browser Shows "400 Bad Request - SSL Certificate Error"

**Cause:** Multiple certificates with the same CN or conflicting entries.

**Solution:**
1. Remove all previous SuperAdmin certificates from your browser
2. Re-import `superadmin.p12` fresh
3. Restart browser if necessary

### PostgreSQL Init Failures (`Operation not permitted`)

**Cause:** Wrong ownership on the Postgres data directory.

**Solution:** The script automatically detects and sets correct UID/GID. If issues persist:

```bash
# Check the expected UID/GID
docker run --rm postgres:16-alpine id postgres

# Fix ownership
sudo chown -R <uid>:<gid> /opt/ejbca/data/postgres
```

### Nginx Restarting with Cache Permission Errors

**Cause:** Permission issues with `/var/cache/nginx`.

**Solution:** The script uses tmpfs mounts to avoid this. If issues persist, check the compose file includes:

```yaml
tmpfs:
  - /var/cache/nginx
  - /var/run
```

### View Container Logs

```bash
# All containers
cd /opt/ejbca
sudo -u ejbca env HOME=/home/ejbca DOCKER_CONFIG=/home/ejbca/.docker \
  docker compose --env-file .env logs -f

# Specific container
sudo docker logs ejbca-postgres
sudo docker logs ejbca-app
sudo docker logs ejbca-nginx
```

### Check Setup Log

```bash
sudo cat /var/log/ejbca-setup.log
sudo tail -100 /var/log/ejbca-setup.log
sudo grep -i error /var/log/ejbca-setup.log
```

---

## Post-Deployment Checklist

### 1. Verify Deployment

- [ ] `https://<hostname>/healthz` returns **200 OK**
- [ ] `https://<hostname>/ejbca/` loads the public page
- [ ] `https://<hostname>/ejbca/adminweb/` returns **403** without client cert
- [ ] `https://<hostname>/ejbca/adminweb/` returns **200/302** with SuperAdmin cert

### 2. Import SuperAdmin Certificate

- [ ] Retrieve password from `/opt/ejbca/.env`
- [ ] Import `superadmin.p12` into browser
- [ ] Verify admin access works

### 3. Remove Bootstrap Admin Access

After confirming admin access works, remove `INITIAL_ADMIN` from the compose file:

```bash
cd /opt/ejbca

# Edit docker-compose.yml and remove the INITIAL_ADMIN line
sudo nano docker-compose.yml

# Recreate the EJBCA container
sudo -u ejbca env HOME=/home/ejbca DOCKER_CONFIG=/home/ejbca/.docker \
  docker compose --env-file .env up -d --force-recreate ejbca
```

### 4. Secure the Deployment

- [ ] Replace self-signed TLS certificate with CA-signed certificate
- [ ] Restrict inbound firewall/security group rules (allow 443 only from trusted IPs)
- [ ] Back up secrets and private keys to secure off-server storage
- [ ] Configure log rotation and monitoring

### 5. Production Hardening (Optional)

- [ ] Enable EJBCA audit logging
- [ ] Configure certificate revocation (CRL/OCSP)
- [ ] Set up monitoring and alerting
- [ ] Document recovery procedures

---

## Warnings / Production Notes

> ⚠️ **Docker group membership** effectively grants root-equivalent privileges. Limit group membership carefully.

> ⚠️ **Never expose PostgreSQL** directly to the internet. The database should only be accessible within the Docker network.

> ⚠️ **Back up secrets securely.** Loss of `/opt/ejbca/.env` or CA private keys may require full redeployment.

> ⚠️ **Replace self-signed certificates** before production use. The generated TLS certificate is for initial setup only.

> ⚠️ **Remove `INITIAL_ADMIN`** after initial setup to prevent unauthenticated administrative access.

> ⚠️ **Test your backups.** Regularly verify that backups can be restored successfully.

---

## License

This deployment script is provided as-is for deploying EJBCA Community Edition. EJBCA CE is licensed under the LGPL. See [EJBCA Documentation](https://doc.primekey.com/ejbca) for more information.
