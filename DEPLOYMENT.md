# Secret Sanitizer — Deployment Guide

Complete installation instructions for deploying Secret Sanitizer on a Proxmox LXC container.

## Prerequisites

- Proxmox VE host with access to create LXC containers
- Debian 12 LXC template (`debian-12-standard_12.7-1_amd64.tar.zst`)
- Reverse proxy with SSL (e.g., NPMplus, Nginx Proxy Manager)
- Optional: Authelia or similar for 2FA authentication

---

## 1. Create LXC container

```bash
pct create <VMID> local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname secret-sanitizer \
  --memory 2048 \
  --swap 1024 \
  --cores 2 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
```

> **Resource requirements:** 1GB RAM + 1GB swap minimum (spaCy + Deduce need ~1.7GB at peak). 8GB disk for Python packages + spaCy model. Scale down to 256MB RAM / 4GB disk if only using Gitleaks (Quick mode).

## 2. Install Node.js 20

```bash
pct exec <VMID> -- bash -c "apt update && apt install -y curl ca-certificates && \
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install -y nodejs"
```

## 3. Install Gitleaks

```bash
pct exec <VMID> -- bash -c "
  curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.22.1/gitleaks_8.22.1_linux_x64.tar.gz \
    | tar xz -C /usr/local/bin gitleaks && \
  chmod +x /usr/local/bin/gitleaks && \
  gitleaks version
"
```

## 4. Install PDF extraction tools

```bash
pct exec <VMID> -- apt install -y poppler-utils
pct exec <VMID> -- pdftotext -v
```

## 5. Install Python 3 + PII service

```bash
pct exec <VMID> -- apt install -y python3 python3-pip python3-venv
```

Create virtual environment and install dependencies:

```bash
pct exec <VMID> -- bash -c "
  cd /opt/secret-sanitizer && \
  python3 -m venv pii-venv && \
  pii-venv/bin/pip install flask presidio-analyzer presidio-anonymizer deduce && \
  pii-venv/bin/python -m spacy download nl_core_news_lg
"
```

> **Note:** spaCy model download is ~500MB. Total venv size is ~1.5GB.

Build Deduce lookup structures (first-time initialization):

```bash
pct exec <VMID> -- bash -c "
  /opt/secret-sanitizer/pii-venv/bin/python -c \"
from deduce import Deduce
print('Building Deduce lookup structures...')
d = Deduce(build_lookup_structs=True)
print('Done')
\"
"
```

> **Note:** This takes 1-2 minutes and only runs once. The structures are cached for subsequent starts.

## 6. Deploy application files

Create the application directory:

```bash
pct exec <VMID> -- mkdir -p /opt/secret-sanitizer/public
```

Copy the application files to the container. From your local machine, transfer to the Proxmox host first, then push into the container:

```bash
# From your local machine → Proxmox host
scp server.js package.json pii_service.py .gitleaks.toml root@<PROXMOX_IP>:/tmp/
scp public/index.html root@<PROXMOX_IP>:/tmp/index.html

# From Proxmox host → container
pct push <VMID> /tmp/server.js /opt/secret-sanitizer/server.js
pct push <VMID> /tmp/pii_service.py /opt/secret-sanitizer/pii_service.py
pct push <VMID> /tmp/index.html /opt/secret-sanitizer/public/index.html
pct push <VMID> /tmp/.gitleaks.toml /opt/secret-sanitizer/.gitleaks.toml
pct push <VMID> /tmp/package.json /opt/secret-sanitizer/package.json
```

Install Node.js dependencies:

```bash
pct exec <VMID> -- bash -c "cd /opt/secret-sanitizer && npm install --production"
```

## 7. Infrastructure hardening

### Temp file auto-cleanup (systemd-tmpfiles)

```bash
pct exec <VMID> -- bash -c 'cat > /etc/tmpfiles.d/secret-sanitizer.conf << EOF
# Auto-cleanup temp files older than 5 minutes
e /tmp/sanitize-* - - - 5m
e /tmp/upload_* - - - 5m
EOF'
pct exec <VMID> -- systemd-tmpfiles --create
```

### Disable core dumps

```bash
pct exec <VMID> -- bash -c '
  echo "kernel.core_pattern=/dev/null" >> /etc/sysctl.d/99-no-coredump.conf
  sysctl -p /etc/sysctl.d/99-no-coredump.conf
  mkdir -p /etc/systemd/coredump.conf.d
  cat > /etc/systemd/coredump.conf.d/disable.conf << EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
'
```

### Limit log retention

```bash
pct exec <VMID> -- bash -c '
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/retention.conf << EOF
[Journal]
MaxRetentionSec=48h
SystemMaxUse=50M
EOF
  systemctl restart systemd-journald
'
```

## 8. Create systemd services

### Node.js service (main API)

```bash
pct exec <VMID> -- bash -c 'cat > /etc/systemd/system/secret-sanitizer.service << EOF
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
```

### Python PII service

```bash
pct exec <VMID> -- bash -c 'cat > /etc/systemd/system/pii-service.service << EOF
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
```

### Enable and start both services

```bash
pct exec <VMID> -- bash -c "
  systemctl daemon-reload && \
  systemctl enable --now pii-service && \
  sleep 15 && \
  systemctl enable --now secret-sanitizer
"
```

> **Note:** Start pii-service first and wait ~15 seconds for Presidio + Deduce to initialize before starting the Node.js service.

## 9. Verify

```bash
# Service status
pct exec <VMID> -- systemctl status secret-sanitizer --no-pager | head -6
pct exec <VMID> -- systemctl status pii-service --no-pager | head -6

# Health check
pct exec <VMID> -- curl -s http://localhost:3100/health | python3 -m json.tool

# Functional test (deep scan)
pct exec <VMID> -- curl -s -X POST http://localhost:3100/api/sanitize \
  -H "Content-Type: application/json" \
  -d '{"text":"Jan de Vries zijn IBAN is NL91ABNA0417164300 en token=abc123def456ghi789jkl","depth":"deep"}'
```

## 10. Reverse proxy setup

Configure your reverse proxy to forward traffic to `http://<CONTAINER_IP>:3100`:

- SSL termination at the proxy
- WebSocket support not required
- Set `client_max_body_size 50m;` for file uploads
- Optional: Add Authelia for 2FA authentication

Example for NPMplus/Nginx Proxy Manager:
- Domain: `secret.yourdomain.com`
- Scheme: `http`
- Forward hostname/IP: `<CONTAINER_IP>`
- Forward port: `3100`
- SSL: Force, HTTP/2 support

---

## Updating

### Application files

```bash
# Backup current files
pct exec <VMID> -- cp /opt/secret-sanitizer/server.js /opt/secret-sanitizer/server.js.bak
pct exec <VMID> -- cp /opt/secret-sanitizer/public/index.html /opt/secret-sanitizer/public/index.html.bak

# Deploy new files (from local machine via Proxmox host)
scp server.js root@<PROXMOX_IP>:/tmp/server.js
pct push <VMID> /tmp/server.js /opt/secret-sanitizer/server.js
pct exec <VMID> -- systemctl restart secret-sanitizer
```

### Python PII service

```bash
pct exec <VMID> -- cp /opt/secret-sanitizer/pii_service.py /opt/secret-sanitizer/pii_service.py.bak
scp pii_service.py root@<PROXMOX_IP>:/tmp/pii_service.py
pct push <VMID> /tmp/pii_service.py /opt/secret-sanitizer/pii_service.py
pct exec <VMID> -- systemctl restart pii-service
```

---

## Troubleshooting

### PII service crashes on startup

**Symptom:** `pii-service` fails with `EOFError: Ran out of input`
**Cause:** Corrupt Deduce cache (often after OOM kill during initial setup)
**Fix:**
```bash
pct exec <VMID> -- systemctl stop pii-service
pct exec <VMID> -- bash -c "find / -path '*/deduce*cache*' -exec rm -rf {} + 2>/dev/null; rm -rf /root/.cache/deduce"
pct exec <VMID> -- bash -c "/opt/secret-sanitizer/pii-venv/bin/python -c \"from deduce import Deduce; Deduce(build_lookup_structs=True)\""
pct exec <VMID> -- systemctl start pii-service
```

### Out of memory

**Symptom:** Services get OOM-killed
**Cause:** Insufficient RAM for spaCy model + Deduce lookups
**Fix:** Ensure at least 2GB RAM + 1GB swap:
```bash
pct set <VMID> --memory 2048 --swap 1024
pct reboot <VMID>
```

### PII service unavailable (Quick mode still works)

**Symptom:** Standard/Deep scans fail, Quick scans work
**Cause:** Python PII service not running
**Fix:**
```bash
pct exec <VMID> -- systemctl status pii-service --no-pager
pct exec <VMID> -- journalctl -u pii-service --no-pager -n 20
pct exec <VMID> -- systemctl restart pii-service
```

### Gitleaks false positives

**Fix:** Edit `/opt/secret-sanitizer/.gitleaks.toml` to add patterns to the relevant rule's allowlist or the global allowlist:
```toml
[allowlist]
regexes = [
  '''your-false-positive-pattern'''
]
```

Restart after changes: `systemctl restart secret-sanitizer`
