#!/bin/bash
# ============================================================================
# Secret Sanitizer — Proxmox LXC Installer
# Version: 1.1.0
# 
# Run this script on your Proxmox host to create a fully configured LXC
# container running Secret Sanitizer with all three scan engines.
#
# Usage:
#   ./install-lxc.sh [OPTIONS]
#
# Options:
#   --vmid <id>       Container VMID (default: auto-detect next free)
#   --ip <address>    Static IP (default: DHCP)
#   --bridge <n>   Network bridge (default: vmbr0)
#   --storage <n>  Storage for rootfs (default: local-lvm)
#   --template <path> Debian 12 template path (default: auto-detect)
#   --quick           Skip PII service (Gitleaks only, 256MB RAM)
#   --help            Show this help
#
# Requirements:
#   - Proxmox VE host
#   - Debian 12 LXC template available
#   - Internet access from container (for package downloads)
# ============================================================================

set -euo pipefail

# === Configuration defaults ===
VMID=""
IP="dhcp"
BRIDGE="vmbr0"
STORAGE="local-lvm"
TEMPLATE=""
QUICK_MODE=false
HOSTNAME="secret-sanitizer"
GITLEAKS_VERSION="8.22.1"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

# === Parse arguments ===
while [[ $# -gt 0 ]]; do
  case $1 in
    --vmid)     VMID="$2"; shift 2 ;;
    --ip)       IP="$2"; shift 2 ;;
    --bridge)   BRIDGE="$2"; shift 2 ;;
    --storage)  STORAGE="$2"; shift 2 ;;
    --template) TEMPLATE="$2"; shift 2 ;;
    --quick)    QUICK_MODE=true; shift ;;
    --help)
      head -25 "$0" | tail -20
      exit 0 ;;
    *) err "Unknown option: $1" ;;
  esac
done

# === Verify we're on Proxmox ===
if ! command -v pct &>/dev/null; then
  err "This script must be run on a Proxmox VE host (pct not found)"
fi

# === Find script directory (where the app files are) ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify required files exist
for f in server.js pii_service.py package.json .gitleaks.toml public/index.html; do
  [[ -f "$SCRIPT_DIR/$f" ]] || err "Missing file: $SCRIPT_DIR/$f"
done
log "Application files found in $SCRIPT_DIR"

# === Auto-detect VMID ===
if [[ -z "$VMID" ]]; then
  VMID=$(pvesh get /cluster/nextid 2>/dev/null || echo "")
  [[ -n "$VMID" ]] || err "Could not auto-detect next free VMID. Use --vmid <id>"
  info "Auto-selected VMID: $VMID"
fi

# === Auto-detect Debian 12 template ===
if [[ -z "$TEMPLATE" ]]; then
  TEMPLATE=$(pveam list local 2>/dev/null | grep -i "debian-12-standard" | awk '{print $1}' | head -1)
  if [[ -z "$TEMPLATE" ]]; then
    warn "Debian 12 template not found locally. Downloading..."
    pveam update
    pveam download local debian-12-standard_12.7-1_amd64.tar.zst || err "Failed to download template"
    TEMPLATE="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"
  fi
  log "Using template: $TEMPLATE"
fi

# === Set resources based on mode ===
if $QUICK_MODE; then
  RAM=256
  DISK=4
  info "Quick mode: Gitleaks only (256MB RAM, 4GB disk)"
else
  RAM=2048
  DISK=8
  info "Full mode: Gitleaks + Presidio + Deduce (2GB RAM, 8GB disk)"
fi

# === Network config ===
if [[ "$IP" == "dhcp" ]]; then
  NET_CONFIG="name=eth0,bridge=$BRIDGE,ip=dhcp"
else
  # Assume /24 if no CIDR provided
  [[ "$IP" == */* ]] || IP="$IP/24"
  NET_CONFIG="name=eth0,bridge=$BRIDGE,ip=$IP"
fi

# === Create container ===
echo ""
info "Creating LXC container $VMID..."
echo "  Hostname:  $HOSTNAME"
echo "  RAM:       ${RAM}MB"
echo "  Disk:      ${DISK}GB"
echo "  Network:   $NET_CONFIG"
echo "  Template:  $TEMPLATE"
echo ""

pct create "$VMID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --memory "$RAM" \
  --cores 1 \
  --rootfs "$STORAGE:$DISK" \
  --net0 "$NET_CONFIG" \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1

# Wait for container to start
sleep 3
log "Container $VMID created and started"

# Get container IP
sleep 5
CONTAINER_IP=$(pct exec "$VMID" -- hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
info "Container IP: $CONTAINER_IP"

# === Install Node.js 20 ===
info "Installing Node.js 20..."
pct exec "$VMID" -- bash -c "
  apt-get update -qq && \
  apt-get install -y -qq curl ca-certificates > /dev/null 2>&1 && \
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1 && \
  apt-get install -y -qq nodejs > /dev/null 2>&1
"
log "Node.js $(pct exec "$VMID" -- node --version) installed"

# === Install Gitleaks ===
info "Installing Gitleaks ${GITLEAKS_VERSION}..."
pct exec "$VMID" -- bash -c "
  curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    | tar xz -C /usr/local/bin gitleaks && \
  chmod +x /usr/local/bin/gitleaks
"
log "Gitleaks $(pct exec "$VMID" -- /usr/local/bin/gitleaks version 2>&1) installed"

# === Install poppler-utils (PDF extraction) ===
info "Installing poppler-utils (PDF extraction)..."
pct exec "$VMID" -- apt-get install -y -qq poppler-utils > /dev/null 2>&1
log "pdftotext installed"

# === Deploy application files ===
info "Deploying application files..."
pct exec "$VMID" -- mkdir -p /opt/secret-sanitizer/public

# Push files into container
for f in server.js pii_service.py package.json .gitleaks.toml; do
  pct push "$VMID" "$SCRIPT_DIR/$f" "/opt/secret-sanitizer/$f"
done
pct push "$VMID" "$SCRIPT_DIR/public/index.html" "/opt/secret-sanitizer/public/index.html"

# Optional: copy docs if present
for f in README.md DEPLOYMENT.md CHANGELOG.md; do
  [[ -f "$SCRIPT_DIR/$f" ]] && pct push "$VMID" "$SCRIPT_DIR/$f" "/opt/secret-sanitizer/$f" || true
done

log "Application files deployed"

# === Install Node.js dependencies ===
info "Installing Node.js dependencies..."
pct exec "$VMID" -- bash -c "cd /opt/secret-sanitizer && npm install --production --silent 2>&1 | tail -1"
log "Node.js dependencies installed"

# === Install Python PII service (unless quick mode) ===
if ! $QUICK_MODE; then
  info "Installing Python 3 + PII service (this takes a few minutes)..."
  pct exec "$VMID" -- apt-get install -y -qq python3 python3-pip python3-venv > /dev/null 2>&1

  info "Creating Python virtual environment + installing packages..."
  pct exec "$VMID" -- bash -c "
    cd /opt/secret-sanitizer && \
    python3 -m venv pii-venv && \
    pii-venv/bin/pip install --quiet flask presidio-analyzer presidio-anonymizer deduce 2>&1 | tail -3
  "
  log "Python packages installed"

  info "Downloading spaCy Dutch NLP model (~500MB)..."
  pct exec "$VMID" -- bash -c "
    /opt/secret-sanitizer/pii-venv/bin/python -m spacy download nl_core_news_lg 2>&1 | tail -1
  "
  log "spaCy nl_core_news_lg model installed"

  info "Building Deduce lookup structures (1-2 minutes)..."
  pct exec "$VMID" -- bash -c "
    /opt/secret-sanitizer/pii-venv/bin/python -c \"
from deduce import Deduce
d = Deduce(build_lookup_structs=True)
print('Deduce initialized')
\"
  "
  log "Deduce lookup structures built"
fi

# === Infrastructure hardening ===
info "Applying security hardening..."

# Temp file auto-cleanup
pct exec "$VMID" -- bash -c 'cat > /etc/tmpfiles.d/secret-sanitizer.conf << EOF
e /tmp/sanitize-* - - - 5m
e /tmp/upload_* - - - 5m
EOF'
pct exec "$VMID" -- systemd-tmpfiles --create

# Disable core dumps
pct exec "$VMID" -- bash -c '
  echo "kernel.core_pattern=/dev/null" > /etc/sysctl.d/99-no-coredump.conf
  sysctl -p /etc/sysctl.d/99-no-coredump.conf 2>/dev/null || true
  mkdir -p /etc/systemd/coredump.conf.d
  cat > /etc/systemd/coredump.conf.d/disable.conf << EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
'

# Limit log retention
pct exec "$VMID" -- bash -c '
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/retention.conf << EOF
[Journal]
MaxRetentionSec=48h
SystemMaxUse=50M
EOF
  systemctl restart systemd-journald
'

log "Security hardening applied"

# === Create systemd services ===
info "Creating systemd services..."

# Main Node.js service
pct exec "$VMID" -- bash -c 'cat > /etc/systemd/system/secret-sanitizer.service << EOF
[Unit]
Description=Secret Sanitizer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/secret-sanitizer
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=3100

[Install]
WantedBy=multi-user.target
EOF'

if ! $QUICK_MODE; then
  # Python PII service
  pct exec "$VMID" -- bash -c 'cat > /etc/systemd/system/pii-service.service << EOF
[Unit]
Description=PII Detection Service (Presidio + Deduce)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/secret-sanitizer
ExecStart=/opt/secret-sanitizer/pii-venv/bin/python pii_service.py
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF'

  pct exec "$VMID" -- bash -c "
    systemctl daemon-reload && \
    systemctl enable --now pii-service
  "
  log "PII service started (waiting 15s for initialization...)"
  sleep 15
fi

pct exec "$VMID" -- bash -c "
  systemctl daemon-reload && \
  systemctl enable --now secret-sanitizer
"
log "Secret Sanitizer service started"

# === Verify ===
sleep 3
info "Running health check..."
HEALTH=$(pct exec "$VMID" -- curl -s http://localhost:3100/health 2>/dev/null || echo '{"error":"failed"}')
echo "  $HEALTH"

# === Summary ===
echo ""
echo "============================================"
echo -e "${GREEN}  Secret Sanitizer v1.1.0 installed!${NC}"
echo "============================================"
echo ""
echo "  Container VMID:  $VMID"
echo "  Container IP:    $CONTAINER_IP"
echo "  Internal URL:    http://$CONTAINER_IP:3100"
echo "  Health check:    http://$CONTAINER_IP:3100/health"
if $QUICK_MODE; then
  echo "  Mode:            Quick (Gitleaks only)"
else
  echo "  Mode:            Full (Gitleaks + Presidio + Deduce)"
fi
echo ""
echo "  Security hardening:"
echo "    ✓ Temp file auto-cleanup (5min)"
echo "    ✓ Core dumps disabled"
echo "    ✓ Log retention 48h/50MB"
echo "    ✓ Memory wipe on scan"
echo "    ✓ Console PII filtering"
echo "    ✓ Audit logging (metadata only)"
echo ""
echo "  Next steps:"
echo "  1. Set up a static IP/DHCP reservation for $CONTAINER_IP"
echo "  2. Configure your reverse proxy → http://$CONTAINER_IP:3100"
echo "  3. (Optional) Add Authelia 2FA"
echo ""
echo "  Test: curl -s http://$CONTAINER_IP:3100/health"
echo ""
