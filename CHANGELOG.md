# Changelog

## [1.1.0] — 2026-02-17: Security Hardening + Cross-Reference Feedbackloop

### Added

**Cross-reference feedbackloop (Deep mode)**
- New `/api/cross-reference` endpoint in Python PII service
- Two-pass algorithm: value propagation (find detected values elsewhere in text) + email-to-name extraction (derive person names from email local parts)
- Non-overlapping enforcement: cross-reference findings skip already-covered spans
- Integrated into scan pipeline as fourth step in Deep mode (Gitleaks → Presidio → Deduce → cross-reference)
- Skip-word and tussenvoegsel filtering to prevent false positives from common Dutch words
- Cross-reference findings tagged with `source: "cross-reference"` and include `reason` field (value-propagation / email-extraction)

**Security hardening**
- Console output sanitization: PII patterns (BSN, IBAN, phone numbers, postcodes) automatically filtered from all console.log/error/warn output
- Audit logging: metadata-only logging (timestamp, scan depth, findings count, file type/size, duration) — never logs content
- Memory wipe: temp files and uploaded files overwritten with zeros (Buffer.fill(0)) before deletion
- Health endpoint now includes `version: "1.1.0"` and `hardening` status object

**Privacy**
- Privacy notice modal in frontend UI explaining data minimization approach
- Privacy link (🔒) in status bar
- Modal covers: local processing, no storage, memory wipe, console filtering, audit logging, scan history (localStorage), security measures

**Frontend**
- Cross-reference layer badge (purple) in layer badges panel
- Findings panel shows `x-ref` source tag with reason indicator (propagated / from email)
- Deep mode label updated to mention cross-reference
- Version shown in privacy modal
- Scan history off by default — toggle switch in history drawer to enable (stored in localStorage)

### Changed
- `server.js`: version in health endpoint, console sanitization active on startup, audit entries on every scan
- `pii_service.py`: new `/api/cross-reference` endpoint, health endpoint includes `cross_reference: true`
- `package.json`: version bumped to 1.1.0

### Infrastructure hardening (deployment steps)
These are applied at the OS level during deployment, not in the application code:
- `systemd-tmpfiles`: auto-cleanup of temp files older than 5 minutes
- Core dumps disabled (`kernel.core_pattern=/dev/null`, systemd coredump off)
- Journal log retention limited to 48 hours / 50MB

---

## [1.0.0] — 2026-02-13: Initial Release

### Features
- Three-layer scan pipeline: Gitleaks (credentials) → Presidio (structured PII) → Deduce (Dutch names/orgs)
- Scan depth selector: Quick (Gitleaks only) / Standard (+ Presidio) / Deep (+ Deduce)
- File upload with drag & drop: text files + PDF (.pdf) + Word (.docx) with automatic text extraction
- PDF extraction via pdftotext (poppler-utils), Word extraction via mammoth
- Custom Gitleaks configuration with 8 rules extending defaults, optimized for n8n workflow patterns
- Microsoft Presidio with Dutch spaCy NLP model (nl_core_news_lg) and custom recognizers (BSN with elfproef, KvK, Dutch phone numbers)
- Deduce 3.x for Dutch-specific de-identification
- Findings merge algorithm with deduplication, score-based priority, and offset-based redaction
- Dark theme web UI with two-panel layout, layer badges, scrollable findings panel
- Scan history with localStorage (24h TTL, max 50 items)
- 50MB file size limit
- Express server with Helmet security headers and rate limiting
- Python Flask microservice for PII detection
- Systemd services for both Node.js and Python components
- Proxmox LXC installer script for one-command deployment
- Health endpoint reporting all component versions and status
