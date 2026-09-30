#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  NETLIFE CASH — Self-hosted Supabase Setup Script
#  Tested on: Ubuntu 20.04 / 22.04 / 24.04, Debian 11/12
#
#  Usage:
#    chmod +x setup-ubuntu.sh
#    sudo ./setup-ubuntu.sh
#
#  What this does:
#    1. Installs Docker + Docker Compose v2
#    2. Installs Node.js 20 (needed for key generation)
#    3. Generates all secrets (.env)
#    4. Starts the full Supabase stack
#    5. Pushes the NETLIFE CASH database schema
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run this script as root: sudo ./setup-ubuntu.sh"

INSTALL_DIR="${INSTALL_DIR:-/opt/netlife-supabase}"
DOMAIN="${DOMAIN:-}"          # optional — set to your domain for nginx/SSL
SMTP_HOST="${SMTP_HOST:-}"
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      NETLIFE CASH — Supabase Self-host Installer         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
info "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=120 update -qq \
  || { warn "First apt metadata refresh failed; retrying…"; sleep 5; apt-get -o DPkg::Lock::Timeout=120 update -qq; }
apt-get -o DPkg::Lock::Timeout=120 upgrade -y -qq
apt-get -o DPkg::Lock::Timeout=120 dist-upgrade -y -qq
apt-get -o DPkg::Lock::Timeout=120 install -y -qq \
  curl wget git unzip openssl ca-certificates gnupg lsb-release apt-transport-https \
  unattended-upgrades fail2ban ufw logrotate
success "System and security packages updated"

# ── 2. Docker ─────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable --now docker
  success "Docker installed"
else
  success "Docker already installed ($(docker --version))"
fi

# Docker Compose v2 plugin
if ! docker compose version &>/dev/null 2>&1; then
  info "Installing Docker Compose v2..."
  COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  success "Docker Compose v2 installed"
else
  success "Docker Compose v2 already installed"
fi

# ── 3. Node.js 20 ─────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null || [[ $(node -e "process.exit(process.version.slice(1).split('.')[0] < 18 ? 1 : 0)" 2>/dev/null; echo $?) == "1" ]]; then
  info "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  success "Node.js installed ($(node --version))"
else
  success "Node.js already installed ($(node --version))"
fi

# ── 4. Install directory ──────────────────────────────────────────────────────
info "Setting up install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"/{volumes/{db/init,storage,functions,api},logs}

# Copy project files if running from source, else download
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
  cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR/"
  info "Copied stack files from $SCRIPT_DIR"
else
  info "Downloading stack files from repository..."
  # Fallback: user can put files here manually
  warn "Place docker-compose.yml, .env, and volumes/ in $INSTALL_DIR manually"
fi

cd "$INSTALL_DIR"

# ── 5. Generate secrets ────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  info "Generating secrets and .env file..."

  DB_PASS=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-32)
  DASH_PASS=$(openssl rand -base64 16 | tr -d '=+/')
  JWT_SECRET=$(openssl rand -base64 40 | tr -d '\n')
  SECRET_KEY_BASE=$(openssl rand -hex 40)
  LOGFLARE_KEY=$(openssl rand -hex 20)

  ANON_KEY=$(node -e "
const c=require('crypto'),s='$JWT_SECRET';
const h=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const p=Buffer.from(JSON.stringify({role:'anon',iss:'supabase',iat:1700000000,exp:1900000000})).toString('base64url');
const sg=c.createHmac('sha256',s).update(h+'.'+p).digest('base64url');
console.log(h+'.'+p+'.'+sg);
")

  SVC_KEY=$(node -e "
const c=require('crypto'),s='$JWT_SECRET';
const h=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const p=Buffer.from(JSON.stringify({role:'service_role',iss:'supabase',iat:1700000000,exp:1900000000})).toString('base64url');
const sg=c.createHmac('sha256',s).update(h+'.'+p).digest('base64url');
console.log(h+'.'+p+'.'+sg);
")

  EXTERNAL_URL="http://localhost:8000"
  [[ -n "$DOMAIN" ]] && EXTERNAL_URL="https://$DOMAIN"

  cat > .env <<EOF
# Generated by setup-ubuntu.sh on $(date)
SITE_URL=$EXTERNAL_URL
API_EXTERNAL_URL=$EXTERNAL_URL
ADDITIONAL_REDIRECT_URLS=

POSTGRES_HOST=db
POSTGRES_DB=postgres
POSTGRES_PORT=5432
POSTGRES_PASSWORD=$DB_PASS

JWT_SECRET=$JWT_SECRET
JWT_EXPIRY=3600
ANON_KEY=$ANON_KEY
SERVICE_ROLE_KEY=$SVC_KEY

DASHBOARD_USERNAME=supabase
DASHBOARD_PASSWORD=$DASH_PASS
STUDIO_DEFAULT_ORGANIZATION=NETLIFE CASH
STUDIO_DEFAULT_PROJECT=VirtualBank

DISABLE_SIGNUP=false
ENABLE_EMAIL_SIGNUP=true
ENABLE_EMAIL_AUTOCONFIRM=false
ENABLE_ANONYMOUS_USERS=false
ENABLE_PHONE_SIGNUP=true
ENABLE_PHONE_AUTOCONFIRM=false

SMTP_ADMIN_EMAIL=noreply@netlifecash.com
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=587
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SMTP_SENDER_NAME=NETLIFE CASH

KONG_HTTP_PORT=8000
KONG_HTTPS_PORT=8443

SECRET_KEY_BASE=$SECRET_KEY_BASE
REALTIME_DB_ENC_KEY=supabaserealtime

LOGFLARE_API_KEY=$LOGFLARE_KEY
IMGPROXY_ENABLE_WEBP_DETECTION=true
FUNCTIONS_VERIFY_JWT=false
EOF

  success ".env generated"
  echo ""
  echo "  ┌─────────────────────────────────────────────────────┐"
  echo "  │  SAVE THESE CREDENTIALS — shown only once!          │"
  echo "  ├─────────────────────────────────────────────────────┤"
  echo "  │  DB Password   : $DB_PASS"
  echo "  │  Dashboard User: supabase"
  echo "  │  Dashboard Pass: $DASH_PASS"
  echo "  │  Anon Key      : ${ANON_KEY:0:40}..."
  echo "  │  Service Key   : ${SVC_KEY:0:40}..."
  echo "  └─────────────────────────────────────────────────────┘"
  echo ""
  # Save to file too
  {
    echo "NETLIFE CASH Supabase Credentials — $(date)"
    echo "Dashboard: http://localhost:3000"
    echo "API:       http://localhost:8000"
    echo "DB Pass:   $DB_PASS"
    echo "Dash Pass: $DASH_PASS"
    echo "Anon Key:  $ANON_KEY"
    echo "Svc Key:   $SVC_KEY"
  } > /root/netlife-supabase-credentials.txt
  warn "Credentials also saved to /root/netlife-supabase-credentials.txt"
else
  info ".env already exists — skipping key generation"
  source .env
fi

# ── 6. Pull Docker images ──────────────────────────────────────────────────────
info "Pulling Docker images (this may take a few minutes)..."
docker compose pull

# ── 7. Start the stack ────────────────────────────────────────────────────────
info "Starting Supabase stack..."
docker compose up -d

# ── 8. Wait for database to be ready ─────────────────────────────────────────
info "Waiting for database to be healthy..."
MAX_WAIT=60
COUNT=0
until timeout 10s docker compose exec -T db pg_isready -U postgres -h localhost &>/dev/null; do
  sleep 2
  COUNT=$((COUNT+2))
  if [[ $COUNT -ge $MAX_WAIT ]]; then
    warn "Database did not become ready within ${MAX_WAIT}s."
    docker compose ps || true
    docker compose logs --tail=80 db || true
    error "Database failed to start in ${MAX_WAIT}s"
  fi
  printf "."
done
echo ""
success "Database is ready"

# ── 9. Push NETLIFE CASH schema ───────────────────────────────────────────────
SCHEMA_FILE=""
[[ -f "$SCRIPT_DIR/../all_migrations.sql" ]] && SCHEMA_FILE="$SCRIPT_DIR/../all_migrations.sql"
[[ -f "$INSTALL_DIR/all_migrations.sql" ]] && SCHEMA_FILE="$INSTALL_DIR/all_migrations.sql"

if [[ -n "$SCHEMA_FILE" ]]; then
  info "Pushing NETLIFE CASH database schema..."
  source .env 2>/dev/null || true
  docker compose exec -T db psql -U postgres -d postgres < "$SCHEMA_FILE" \
    && success "Schema pushed successfully" \
    || warn "Schema push had some warnings (check above). This is normal for re-runs."
else
  warn "Schema file (all_migrations.sql) not found — push it manually:"
  warn "  docker compose exec -T db psql -U postgres -d postgres < /path/to/all_migrations.sql"
fi

# ── 10. Create admin user ────────────────────────────────────────────────────
info "Creating NETLIFE CASH admin user (phone: 6421651)..."
source .env 2>/dev/null || true

ADMIN_RESULT=$(curl -s -X POST "http://localhost:8000/auth/v1/admin/users" \
  -H "Content-Type: application/json" \
  -H "apikey: $SERVICE_ROLE_KEY" \
  -H "Authorization: Bearer $SERVICE_ROLE_KEY" \
  -d '{
    "email": "5926421651@vbank.com",
    "password": "Zaq12wsx",
    "email_confirm": true,
    "user_metadata": {
      "full_name": "Admin",
      "phone_number": "+5926421651",
      "account_type": "admin"
    }
  }' 2>&1)

if echo "$ADMIN_RESULT" | grep -q '"id"'; then
  ADMIN_ID=$(echo "$ADMIN_RESULT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  success "Admin user created (ID: $ADMIN_ID)"

  # Insert admin role
  docker compose exec -T db psql -U postgres -d postgres -c \
    "INSERT INTO public.user_roles (user_id, role) VALUES ('$ADMIN_ID', 'admin') ON CONFLICT DO NOTHING;" \
    2>/dev/null && success "Admin role assigned" || warn "Could not assign role via DB (table may not exist yet)"

elif echo "$ADMIN_RESULT" | grep -q "email_exists"; then
  success "Admin user already exists"
else
  warn "Admin user creation: $ADMIN_RESULT"
fi

# ── 11. Optional: Nginx + SSL ─────────────────────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
  info "Setting up Nginx reverse proxy for $DOMAIN..."
  apt-get install -y -qq nginx certbot python3-certbot-nginx

  cat > /etc/nginx/sites-available/supabase <<NGINX
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /studio {
        proxy_pass http://localhost:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NGINX

  ln -sf /etc/nginx/sites-available/supabase /etc/nginx/sites-enabled/supabase
  nginx -t && systemctl reload nginx

  info "Obtaining SSL certificate for $DOMAIN..."
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" || \
    warn "SSL setup failed — run: certbot --nginx -d $DOMAIN"

  success "Nginx + SSL configured for $DOMAIN"
fi

# ── 12. Systemd service (auto-restart on reboot) ──────────────────────────────
cat > /etc/systemd/system/netlife-supabase.service <<EOF
[Unit]
Description=NETLIFE CASH Supabase Stack
Requires=docker.service
After=docker.service network.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netlife-supabase.service
success "Systemd service registered (auto-starts on reboot)"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              ✅  SETUP COMPLETE                          ║"
echo "╠══════════════════════════════════════════════════════════╣"
if [[ -n "$DOMAIN" ]]; then
echo "║  Supabase API  : https://$DOMAIN"
echo "║  Studio        : https://$DOMAIN/studio"
else
echo "║  Supabase API  : http://$(hostname -I | awk '{print $1}'):8000"
echo "║  Studio        : http://$(hostname -I | awk '{print $1}'):3000"
fi
echo "║  Admin login   : Phone 6421651  /  Password Zaq12wsx    ║"
echo "║  Credentials   : /root/netlife-supabase-credentials.txt ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Useful commands:                                        ║"
echo "║    View logs  : docker compose logs -f                  ║"
echo "║    Stop stack : docker compose down                     ║"
echo "║    Restart    : docker compose restart                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
