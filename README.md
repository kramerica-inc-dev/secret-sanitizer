# Secret Sanitizer

A web-based security tool that detects and redacts sensitive information from text, files, and documents before sharing, exporting, or archiving.

## What it does

Paste text or upload files → the sanitizer scans for secrets and PII → outputs a redacted version ready to share safely.

### Features

- Three-layer scan pipeline: Gitleaks (credentials) → Presidio (structured PII) → Deduce (Dutch NLP)
- Cross-reference feedbackloop in Deep mode: propagates detected values across text and extracts person names from email addresses
- Scan depth selector: Quick ⚡ / Standard 🔍 / Deep 🔬
- File upload with drag & drop — supports text files, PDF, and Word (.docx) with automatic text extraction
- Custom Gitleaks config with 8 rules extending defaults, optimized for n8n workflow patterns
- Custom Presidio recognizers for BSN (elfproef), KvK-nummer, and Dutch phone numbers
- Security hardening: memory wipe after processing, console PII filtering, metadata-only audit logging
- Privacy-by-design: no persistent storage, no content logging, temp file auto-cleanup, core dumps disabled
- Dark theme UI with findings panel, layer badges, scan history, privacy notice, and copy-to-clipboard

### Detection engines

Secret Sanitizer uses a three-layer scan pipeline with cross-reference feedbackloop. Each layer adds deeper detection:

| Mode | Engines | Detects |
|---|---|---|
| ⚡ **Quick** | Gitleaks | API keys, tokens, passwords, Basic Auth, SSH keys, credentials in code |
| 🔍 **Standard** | + Presidio | IBAN, BSN, credit cards, email, phone numbers, IP addresses, URLs |
| 🔬 **Deep** | + Deduce + cross-reference | Dutch person names, organizations, locations, dates, ages. Cross-reference propagates detected values and extracts names from email addresses. |

### Supported input

- **Paste text:** JSON, YAML, TOML, Markdown, scripts, logs, config files
- **Upload files:** All text formats + PDF (.pdf) and Word (.docx) with automatic text extraction
- **Max file size:** 50MB

### Output

Redacted text with tagged replacements:
- Credentials: `[REDACTED:rule-id]`
- Structured PII: `[ENTITY_TYPE]` (e.g., `[IBAN_CODE]`, `[EMAIL_ADDRESS]`)
- Dutch PII: `[PERSOON]`, `[LOCATIE]`, `[ORGANISATIE]`

---

## Architecture

```
Internet → DNS (secret.yourdomain.com)
  → Reverse proxy / NPMplus (SSL termination)
    → Authelia (2FA authentication)
      → LXC container
          ├── Node.js 20 + Express (port 3100)
          │   ├── Gitleaks 8.22.1 (Go binary, CLI)
          │   ├── Text extraction (pdftotext + mammoth)
          │   └── Pipeline orchestrator
          └── Python 3.11 + Flask (port 5002)
              ├── Presidio Analyzer + spaCy nl_core_news_lg
              │   └── Custom recognizers (BSN, KvK, NL phone)
              ├── Deduce 3.x (Dutch NLP de-identification)
              └── Cross-reference feedbackloop
```

### Scan pipeline flow

```
Input (text or file)
  │
  ├─ File type detection
  │   ├─ Text → direct
  │   ├─ PDF → pdftotext → text
  │   └─ Word → mammoth → text
  │
  ▼
┌─────────────────────────────────┐
│  Layer 1: Gitleaks (always)     │  → Credentials, tokens, secrets
│  Layer 2: Presidio (standard+)  │  → IBAN, BSN, email, phone, IP
│  Layer 3: Deduce (deep only)    │  → Dutch names, orgs, locations
│  Layer 4: Cross-ref (deep only) │  → Value propagation, email→name
└─────────────────────────────────┘
  │
  ▼
Merge & deduplicate findings
  │
  ▼
Redacted output + findings report
```

---

## Privacy & Security

Secret Sanitizer is designed with **data minimization** as its core principle:

- **Local processing only** — nothing is sent to external services
- **No persistent storage** — text and files are wiped from memory immediately after processing
- **Memory wipe** — temp files overwritten with zeros before deletion
- **No content logging** — audit logs contain only metadata (timing, counts, file type)
- **Console sanitization** — PII patterns (BSN, IBAN, phone numbers) filtered from all log output
- **Temp file cleanup** — systemd-tmpfiles automatically removes files older than 5 minutes
- **Core dumps disabled** — prevents memory content from being written to disk
- **Log retention** — journal logs automatically deleted after 48 hours

---

## API

### `POST /api/sanitize`

Scan pasted text.

```json
{
  "text": "Jan de Vries heeft IBAN NL91ABNA0417164300",
  "depth": "deep"
}
```

Response:
```json
{
  "sanitized": "[PERSON] heeft IBAN [IBAN_CODE]",
  "findings": [
    {"source": "presidio", "rule": "PERSON", "text": "Jan de Vries", "score": 0.85},
    {"source": "presidio", "rule": "IBAN_CODE", "text": "NL91ABNA0417164300", "score": 1.0}
  ],
  "count": 2,
  "layers": {"gitleaks": 0, "presidio": 2, "deduce": 1, "crossReference": 0},
  "depth": "deep"
}
```

### `POST /api/sanitize-file`

Scan uploaded file (multipart/form-data).

- Field `file`: the file to scan
- Field `depth`: `"quick"`, `"standard"`, or `"deep"`

Returns the same response format, plus `filename`, `size`, and for PDF/Word: `extracted`, `sourceType`, `extractedLength`.

### `GET /health`

Returns status of all components:
```json
{
  "status": "ok",
  "version": "1.1.0",
  "gitleaks": "8.22.1",
  "pdftotext": "22.12.0",
  "mammoth": "included",
  "pii_service": {
    "status": "ok",
    "engine": "presidio+deduce",
    "language": "nl",
    "model": "nl_core_news_lg",
    "deduce": "3.x",
    "cross_reference": true,
    "custom_recognizers": ["BSN", "KVK_NUMBER", "NL_PHONE_NUMBER"]
  },
  "hardening": {
    "memoryWipe": true,
    "auditLogging": true,
    "consoleSanitization": true,
    "tempFileCleanup": "systemd-tmpfiles"
  }
}
```

---

## Project structure

```
/opt/secret-sanitizer/
├── server.js               # Node.js Express server + pipeline orchestrator
├── pii_service.py           # Python Flask microservice (Presidio + Deduce + cross-ref)
├── package.json             # Node.js dependencies
├── .gitleaks.toml           # Custom Gitleaks config (8 rules + defaults)
├── pii-venv/                # Python virtual environment
└── public/
    └── index.html           # Web UI (dark theme, scan depth selector)

/usr/local/bin/gitleaks      # Gitleaks 8.22.1 binary
/usr/bin/pdftotext           # Poppler-utils (PDF extraction)
```

### Services

| Service | File | Port | Description |
|---|---|---|---|
| `secret-sanitizer` | server.js | 3100 | Main API + web UI |
| `pii-service` | pii_service.py | 5002 | Presidio + Deduce + cross-reference PII detection |

---

## Detection details

### Gitleaks (Layer 1)

Custom `.gitleaks.toml` with 8 rules extending the default Gitleaks ruleset, optimized for n8n workflow patterns:

- `Buffer.from()` credentials (Basic Auth in n8n Code nodes)
- Basic Auth headers with encoded credentials
- Password/secret in quoted assignments
- Plain text credentials (login/password/username followed by value, with extensive allowlist)
- Unquoted key=value credentials (env files, configs)
- n8n credential references with embedded IDs
- High-entropy hex strings in JSON values
- curl credentials

Global allowlist excludes node_modules, .git, package-lock.json, cache directories, and placeholder patterns.

### Presidio (Layer 2)

Microsoft Presidio with Dutch spaCy NLP model (`nl_core_news_lg`).

**Built-in recognizers:** EMAIL_ADDRESS, IBAN_CODE, CREDIT_CARD, IP_ADDRESS, URL, PHONE_NUMBER, PERSON, LOCATION, ORGANIZATION

**Custom recognizers:**

| Entity | Description | Validation |
|---|---|---|
| `BSN` | Burgerservicenummer (9 digits) | Elfproef (11-test) mathematical validation |
| `KVK_NUMBER` | Kamer van Koophandel (8 digits) | Context keyword boosting |
| `NL_PHONE_NUMBER` | Dutch phone numbers | +31, 06-, landline patterns |

Confidence threshold: 0.5 (configurable per request).

### Deduce (Layer 3)

Dutch-specific de-identification by UMC Utrecht. Rule-based + lookup tables.

Detects: person names (incl. tussenvoegsels), locations, institutions, hospitals, phone numbers, email, BSN, patient numbers, dates, ages.

### Cross-reference feedbackloop (Layer 4)

Uses already-detected findings to discover additional occurrences:

- **Value propagation:** searches for detected PII values in other positions in the text
- **Email-to-name extraction:** derives person names from email local parts (e.g., `jan.devries@company.nl` → searches for "jan" and "devries" as names)
- Filters out common Dutch words and tussenvoegsels to prevent false positives
- Only runs in Deep mode, non-critical (scan succeeds even if cross-reference fails)

### Findings merge

When multiple engines detect the same text span, the merge algorithm deduplicates by position. On overlap, the finding with the higher confidence score wins. On tie: Gitleaks > Presidio > Deduce / cross-reference (source priority).

---

## Infrastructure requirements

| Property | Value |
|---|---|
| OS | Debian 12 (or compatible) |
| RAM | 2GB + 1GB swap (minimum for all three layers) |
| Disk | 8GB (Python packages + spaCy model) |
| CPU | 2 cores recommended |
| Node.js | 20.x |
| Python | 3.11+ |

For Quick mode only (Gitleaks), 256MB RAM and 4GB disk is sufficient.

See [DEPLOYMENT.md](DEPLOYMENT.md) for full installation instructions.

---

## Context

n8n workflow JSON exports contain hardcoded credentials that can't be isolated via n8n's credential system — particularly `Buffer.from('user:pass')` in Code nodes and tokens in query parameters. `process.env` is unavailable in the n8n Code node sandbox, so passwords must remain in the code. Secret Sanitizer is the safety net: before sharing a workflow JSON, run it through the sanitizer.

---

## Acknowledgments

This project builds on the following open-source tools:

- [Gitleaks](https://github.com/gitleaks/gitleaks) — Secret detection in code via regex and entropy analysis
- [Microsoft Presidio](https://github.com/microsoft/presidio) — PII detection and anonymization framework
- [Deduce](https://github.com/vmminidept/deduce) — Dutch de-identification by UMC Utrecht
- [spaCy](https://spacy.io/) — Industrial-strength NLP, used with the `nl_core_news_lg` Dutch model
- [Express](https://expressjs.com/) — Node.js web framework
- [Flask](https://flask.palletsprojects.com/) — Python microservice framework
- [mammoth](https://github.com/mwilliamson/mammoth.js) — Word document (.docx) text extraction
- [Poppler](https://poppler.freedesktop.org/) — PDF text extraction via `pdftotext`
- [Authelia](https://www.authelia.com/) — Authentication and 2FA gateway
- [NPMplus](https://github.com/ZoeyVid/NPMplus) — Reverse proxy management

---

## Contributing

This repository is for personal use, but feel free to fork and adapt for your own workflow!

## License

Personal project — use freely
