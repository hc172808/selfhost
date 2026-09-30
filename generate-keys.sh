#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# generate-keys.sh  —  Create JWT_SECRET, ANON_KEY, SERVICE_ROLE_KEY
# Run ONCE, then paste the output into your .env file.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

command -v node >/dev/null 2>&1 || { echo "Node.js is required"; exit 1; }

JWT_SECRET=$(openssl rand -base64 40 | tr -d '\n')
SECRET_KEY_BASE=$(openssl rand -hex 40)
LOGFLARE_API_KEY=$(openssl rand -hex 20)

ANON_KEY=$(node -e "
const crypto = require('crypto');
const secret = '$JWT_SECRET';
const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const payload = Buffer.from(JSON.stringify({role:'anon',iss:'supabase',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+315360000})).toString('base64url');
const sig = crypto.createHmac('sha256', secret).update(header+'.'+payload).digest('base64url');
console.log(header+'.'+payload+'.'+sig);
")

SERVICE_ROLE_KEY=$(node -e "
const crypto = require('crypto');
const secret = '$JWT_SECRET';
const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
const payload = Buffer.from(JSON.stringify({role:'service_role',iss:'supabase',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+315360000})).toString('base64url');
const sig = crypto.createHmac('sha256', secret).update(header+'.'+payload).digest('base64url');
console.log(header+'.'+payload+'.'+sig);
")

echo "============================================================"
echo "  COPY THESE INTO YOUR .env FILE"
echo "============================================================"
echo ""
echo "JWT_SECRET=$JWT_SECRET"
echo "SECRET_KEY_BASE=$SECRET_KEY_BASE"
echo "LOGFLARE_API_KEY=$LOGFLARE_API_KEY"
echo "ANON_KEY=$ANON_KEY"
echo "SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY"
echo ""
echo "============================================================"
