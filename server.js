const express = require("express");
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const http = require("http");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const mammoth = require("mammoth");

const app = express();
const PORT = 3100;
const PII_SERVICE_URL = "http://127.0.0.1:5002";

// === Console output sanitization ===
// Prevent PII patterns from leaking into system logs
const PII_PATTERNS = [
  /\b[0-9]{9}\b/g,                          // BSN-achtig (9 cijfers)
  /\bNL\d{2}[A-Z]{4}\d{10}\b/g,            // IBAN
  /\b06[- ]?\d{8}\b/g,                      // NL mobiel
  /\+31[- ]?\d{9}\b/g,                      // NL internationaal
  /\b\d{4}\s?[A-Z]{2}\b/g,                  // Postcode
];

function sanitizeForLog(str) {
  if (typeof str !== "string") return str;
  let result = str;
  PII_PATTERNS.forEach(pattern => {
    result = result.replace(new RegExp(pattern.source, pattern.flags), "[FILTERED]");
  });
  return result;
}

// Override console methods to filter PII
const originalLog = console.log;
const originalError = console.error;
const originalWarn = console.warn;
console.log = (...args) => originalLog(...args.map(a => sanitizeForLog(String(a))));
console.error = (...args) => originalError(...args.map(a => sanitizeForLog(String(a))));
console.warn = (...args) => originalWarn(...args.map(a => sanitizeForLog(String(a))));

// === Audit logging (metadata only, never content) ===
function auditLog(event, metadata) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...metadata
  };
  // Log to stdout (picked up by journald) — no content, only metadata
  originalLog(`[AUDIT] ${JSON.stringify(entry)}`);
}

// === File type definitions ===
const TEXT_EXTENSIONS = [
  ".json", ".yaml", ".yml", ".toml", ".env", ".sh", ".bash",
  ".log", ".txt", ".md", ".xml", ".csv", ".ini", ".cfg",
  ".conf", ".properties", ".py", ".js", ".ts", ".html", ".css"
];
const BINARY_EXTENSIONS = [".pdf", ".docx"];
const ALL_EXTENSIONS = [...TEXT_EXTENSIONS, ...BINARY_EXTENSIONS];

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALL_EXTENSIONS.includes(ext) || ext === "") cb(null, true);
    else cb(new Error(`File type ${ext} not supported. Allowed: ${ALL_EXTENSIONS.join(", ")}`));
  }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public"));
const limiter = rateLimit({ windowMs: 60000, max: 30, message: { error: "Too many requests" } });
app.use("/api/", limiter);

// === Text extraction ===

async function extractPdfText(filePath) {
  return new Promise((resolve, reject) => {
    execFile("pdftotext", ["-layout", filePath, "-"], { timeout: 30000, maxBuffer: 5 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`PDF extraction failed: ${stderr || err.message}`));
      if (!stdout || stdout.trim().length === 0) return reject(new Error("PDF extraction returned no text."));
      resolve(stdout);
    });
  });
}

async function extractDocxText(filePath) {
  const result = await mammoth.extractRawText({ path: filePath });
  if (!result.value || result.value.trim().length === 0) throw new Error("Word extraction returned no text.");
  return result.value;
}

async function extractText(filePath, ext) {
  if (ext === ".pdf") return { text: await extractPdfText(filePath), extracted: true, sourceType: "PDF" };
  if (ext === ".docx") return { text: await extractDocxText(filePath), extracted: true, sourceType: "Word" };
  return { text: fs.readFileSync(filePath, "utf8"), extracted: false, sourceType: "text" };
}

// === Layer 1: Gitleaks ===

async function scanWithGitleaks(text, originalExt) {
  const ext = originalExt || ".txt";
  const tmpFile = path.join(os.tmpdir(), `sanitize-${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  const reportFile = tmpFile + ".json";
  try {
    fs.writeFileSync(tmpFile, text);
    const findings = await new Promise((resolve, reject) => {
      execFile("/usr/local/bin/gitleaks", [
        "detect", "--source", tmpFile,
        "--config", "/opt/secret-sanitizer/.gitleaks.toml",
        "--report-format", "json", "--report-path", reportFile,
        "--no-git", "--exit-code", "0"
      ], { timeout: 30000 }, (err) => {
        if (err) return reject(err);
        try {
          const report = fs.existsSync(reportFile) ? JSON.parse(fs.readFileSync(reportFile, "utf8")) : [];
          resolve(Array.isArray(report) ? report : []);
        } catch { resolve([]); }
      });
    });
    const details = [];
    const sorted = [...findings].sort((a, b) => (b.Secret?.length || 0) - (a.Secret?.length || 0));
    sorted.forEach((f) => {
      if (f.Secret) {
        const start = text.indexOf(f.Secret);
        if (start !== -1) {
          details.push({
            source: "gitleaks", entity_type: f.RuleID, text: f.Secret,
            start, end: start + f.Secret.length, score: 1.0,
            description: f.Description || f.RuleID
          });
        }
      }
    });
    return details;
  } finally {
    // Wipe file contents from memory before cleanup
    try {
      const fileContent = fs.readFileSync(tmpFile);
      fileContent.fill(0);
      fs.writeFileSync(tmpFile, fileContent);
    } catch {}
    [tmpFile, reportFile].forEach((f) => { try { fs.unlinkSync(f); } catch {} });
  }
}

// === Layer 2 & 3: PII service calls ===

function callPiiService(endpoint, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: "127.0.0.1", port: 5002, path: endpoint, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      timeout: 60000
    }, (res) => {
      let chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString());
          if (result.error) return reject(new Error(result.error));
          const src = endpoint.includes("presidio") ? "presidio" : endpoint.includes("deduce") ? "deduce" : "cross-reference";
          resolve((result.findings || result.additional_findings || []).map((f) => ({
            source: f.source || src, entity_type: f.entity_type, text: f.text,
            start: f.start, end: f.end, score: f.score,
            reason: f.reason || undefined
          })));
        } catch { reject(new Error("PII service returned invalid response")); }
      });
    });
    req.on("error", (e) => reject(new Error(`PII service unavailable: ${e.message}`)));
    req.on("timeout", () => { req.destroy(); reject(new Error("PII service timeout")); });
    req.write(data);
    req.end();
  });
}

async function scanWithPresidio(text, threshold) {
  return callPiiService("/api/presidio", { text, threshold: threshold || 0.5 });
}

async function scanWithDeduce(text) {
  return callPiiService("/api/deduce", { text });
}

// === Cross-reference feedbackloop ===

async function callCrossReference(text, findings) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ text, findings });
    const req = http.request({
      hostname: "127.0.0.1", port: 5002, path: "/api/cross-reference", method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      timeout: 30000
    }, (res) => {
      let chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString());
          if (result.error) return reject(new Error(result.error));
          resolve((result.additional_findings || []).map((f) => ({
            source: "cross-reference",
            entity_type: f.entity_type,
            text: f.text,
            start: f.start,
            end: f.end,
            score: f.score,
            reason: f.reason
          })));
        } catch { reject(new Error("Cross-reference returned invalid response")); }
      });
    });
    req.on("error", (e) => reject(new Error(`Cross-reference unavailable: ${e.message}`)));
    req.on("timeout", () => { req.destroy(); reject(new Error("Cross-reference timeout")); });
    req.write(data);
    req.end();
  });
}

// === Merge & Redact ===

function mergeFindings(allFindings) {
  if (!allFindings.length) return [];
  const prio = { gitleaks: 3, presidio: 2, deduce: 1, "cross-reference": 1 };
  const sorted = [...allFindings].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    if (b.score !== a.score) return b.score - a.score;
    return (prio[b.source] || 0) - (prio[a.source] || 0);
  });
  const merged = [];
  let lastEnd = -1;
  for (const f of sorted) {
    if (f.start >= lastEnd) {
      merged.push(f);
      lastEnd = f.end;
    } else {
      const prev = merged[merged.length - 1];
      if (f.end > lastEnd && (f.score > prev.score || (f.score === prev.score && (prio[f.source]||0) > (prio[prev.source]||0)))) {
        merged[merged.length - 1] = f;
        lastEnd = f.end;
      }
    }
  }
  return merged;
}

function applyRedactions(text, findings) {
  const sorted = [...findings].sort((a, b) => b.start - a.start);
  let out = text;
  for (const f of sorted) {
    let tag;
    if (f.source === "gitleaks") tag = `[REDACTED:${f.entity_type}]`;
    else if (f.source === "presidio") tag = `[${f.entity_type}]`;
    else tag = `[${f.entity_type.toUpperCase()}]`;
    out = out.substring(0, f.start) + tag + out.substring(f.end);
  }
  return out;
}

// === Pipeline ===

async function scanPipeline(text, depth, originalExt) {
  const allFindings = [];
  const layers = {};

  // Layer 1: Gitleaks (always)
  try {
    const gl = await scanWithGitleaks(text, originalExt);
    allFindings.push(...gl);
    layers.gitleaks = gl.length;
  } catch (err) { layers.gitleaks = { error: err.message }; }

  // Layer 2: Presidio (standard + deep)
  if (depth === "standard" || depth === "deep") {
    try {
      const pr = await scanWithPresidio(text);
      allFindings.push(...pr);
      layers.presidio = pr.length;
    } catch (err) { layers.presidio = { error: err.message }; }
  }

  // Layer 3: Deduce (deep only)
  if (depth === "deep") {
    try {
      const dd = await scanWithDeduce(text);
      allFindings.push(...dd);
      layers.deduce = dd.length;
    } catch (err) { layers.deduce = { error: err.message }; }
  }

  // Cross-reference feedbackloop (deep only, non-critical)
  if (depth === "deep" && allFindings.length > 0) {
    try {
      const xref = await callCrossReference(text, allFindings);
      allFindings.push(...xref);
      layers.crossReference = xref.length;
    } catch (err) {
      // Non-critical — log warning but don't fail the scan
      console.warn(`Cross-reference warning: ${err.message}`);
      layers.crossReference = 0;
    }
  }

  const merged = mergeFindings(allFindings);
  const sanitized = applyRedactions(text, merged);
  const findings = merged.map((f) => ({
    source: f.source, rule: f.entity_type, text: f.text,
    score: f.score, description: f.description || f.entity_type,
    reason: f.reason || undefined
  }));

  return { sanitized, findings, count: merged.length, layers, depth };
}

// === Endpoints ===

app.post("/api/sanitize", async (req, res) => {
  const startTime = Date.now();
  const { text, depth, debug } = req.body;
  if (!text || typeof text !== "string") return res.status(400).json({ error: "No text provided" });
  if (text.length > 50 * 1024 * 1024) return res.status(400).json({ error: "Text too large (max 50MB)" });
  const d = ["quick", "standard", "deep"].includes(depth) ? depth : "quick";
  try {
    const result = await scanPipeline(text, d);
    // Strip PII from findings unless debug mode is requested (#7)
    if (!debug) {
      result.findings = result.findings.map(({ text, ...rest }) => rest);
    }
    auditLog("scan_text", {
      inputLength: text.length,
      findingsCount: result.count,
      depth: d,
      durationMs: Date.now() - startTime
    });
    res.json(result);
  }
  catch (err) { res.status(500).json({ error: "Scan failed", details: err.message }); }
});

app.post("/api/sanitize-file", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const startTime = Date.now();
  const uploadedPath = req.file.path;
  try {
    const ext = path.extname(req.file.originalname).toLowerCase();
    const { text, extracted, sourceType } = await extractText(uploadedPath, ext);
    const scanExt = extracted ? ".txt" : ext;
    const d = ["quick", "standard", "deep"].includes(req.body?.depth) ? req.body.depth : "quick";
    const debugMode = req.body?.debug === "true" || req.body?.debug === true;
    const result = await scanPipeline(text, d, scanExt);
    // Strip PII from findings unless debug mode is requested (#7)
    if (!debugMode) {
      result.findings = result.findings.map(({ text, ...rest }) => rest);
    }
    result.filename = req.file.originalname;
    result.size = req.file.size;
    if (extracted) { result.extracted = true; result.sourceType = sourceType; result.extractedLength = text.length; }
    auditLog("scan_file", {
      filename: req.file.originalname,
      fileSize: req.file.size,
      fileType: ext,
      extracted: extracted || false,
      sourceType: sourceType || "text",
      findingsCount: result.count,
      depth: d,
      durationMs: Date.now() - startTime
    });
    res.json(result);
  } catch (err) {
    if (err.message?.includes("not supported")) res.status(400).json({ error: err.message });
    else if (err.message?.includes("extraction failed") || err.message?.includes("returned no text")) res.status(422).json({ error: err.message });
    else res.status(500).json({ error: "Scan failed", details: err.message });
  } finally {
    // Wipe uploaded file content before deletion
    try {
      const buf = fs.readFileSync(uploadedPath);
      buf.fill(0);
      fs.writeFileSync(uploadedPath, buf);
    } catch {}
    try { fs.unlinkSync(uploadedPath); } catch {}
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "File too large (max 50MB)" });
    return res.status(400).json({ error: err.message });
  }
  if (err.message?.includes("not supported")) return res.status(400).json({ error: err.message });
  next(err);
});

app.get("/health", (req, res) => {
  execFile("/usr/local/bin/gitleaks", ["version"], (err, stdout) => {
    execFile("pdftotext", ["-v"], (err2, stdout2, stderr2) => {
      const pdfV = stderr2 ? stderr2.split("\n")[0].replace("pdftotext version ", "").trim() : "not installed";
      http.get(`${PII_SERVICE_URL}/health`, (piiRes) => {
        let chunks = [];
        piiRes.on("data", (c) => chunks.push(c));
        piiRes.on("end", () => {
          let pii; try { pii = JSON.parse(Buffer.concat(chunks).toString()); } catch { pii = { status: "error" }; }
          res.json({
            status: "ok",
            version: "1.1.0",
            gitleaks: stdout?.trim() || "unknown",
            pdftotext: pdfV,
            mammoth: "included",
            pii_service: pii,
            hardening: {
              memoryWipe: true,
              auditLogging: true,
              consoleSanitization: true,
              tempFileCleanup: "systemd-tmpfiles"
            }
          });
        });
      }).on("error", () => {
        res.json({
          status: "ok",
          version: "1.1.0",
          gitleaks: stdout?.trim() || "unknown",
          pdftotext: pdfV,
          mammoth: "included",
          pii_service: { status: "unavailable" },
          hardening: {
            memoryWipe: true,
            auditLogging: true,
            consoleSanitization: true,
            tempFileCleanup: "systemd-tmpfiles"
          }
        });
      });
    });
  });
});

app.listen(PORT, "0.0.0.0", () => console.log(`Secret Sanitizer v1.1.0 running on port ${PORT}`));
