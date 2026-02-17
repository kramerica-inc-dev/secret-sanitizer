"""
PII Detection Microservice — Presidio + Deduce + Custom Dutch Recognizers + Cross-Reference
Runs as Flask API on port 5002, called by the Node.js Secret Sanitizer.
"""

from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from deduce import Deduce
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pii-service")

app = Flask(__name__)

# === Custom Recognizers ===

class BsnRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = [Pattern("BSN", r"\b[0-9]{9}\b", 0.3)]
        super().__init__(
            supported_entity="BSN",
            supported_language="nl",
            patterns=patterns,
            name="BSN Recognizer",
            context=["bsn", "burgerservicenummer", "sofinummer", "sofi"]
        )

    def validate_result(self, pattern_text):
        if not re.match(r"^[0-9]{9}$", pattern_text):
            return False
        digits = [int(d) for d in pattern_text]
        total = (
            9 * digits[0] + 8 * digits[1] + 7 * digits[2] +
            6 * digits[3] + 5 * digits[4] + 4 * digits[5] +
            3 * digits[6] + 2 * digits[7] - 1 * digits[8]
        )
        return total % 11 == 0 and total != 0

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        validated = []
        for result in results:
            matched_text = text[result.start:result.end]
            if self.validate_result(matched_text):
                result.score = 0.85
                validated.append(result)
        return validated


class KvkRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = [Pattern("KVK", r"\b[0-9]{8}\b", 0.15)]
        super().__init__(
            supported_entity="KVK_NUMBER",
            supported_language="nl",
            patterns=patterns,
            name="KvK Recognizer",
            context=["kvk", "kamer van koophandel", "kvk-nummer", "handelsregister"]
        )


class DutchPhoneRecognizer(PatternRecognizer):
    def __init__(self):
        patterns = [
            Pattern("NL_PHONE_INTL", r"(?:\+31|0031)[\s\-]?[1-9][\s\-]?(?:[0-9][\s\-]?){7,8}", 0.7),
            Pattern("NL_PHONE_MOBILE", r"\b06[\s\-]?(?:[0-9][\s\-]?){8}\b", 0.7),
            Pattern("NL_PHONE_LANDLINE", r"\b0[1-9][0-9][\s\-]?(?:[0-9][\s\-]?){6,7}\b", 0.5),
        ]
        super().__init__(
            supported_entity="NL_PHONE_NUMBER",
            supported_language="nl",
            patterns=patterns,
            name="Dutch Phone Recognizer",
            context=["telefoon", "telefoonnummer", "mobiel", "bellen", "phone", "tel", "mobile"]
        )


# === Engine Setup ===

def create_analyzer():
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "nl", "model_name": "nl_core_news_lg"}]
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["nl"]
    )

    analyzer.registry.add_recognizer(BsnRecognizer())
    analyzer.registry.add_recognizer(KvkRecognizer())
    analyzer.registry.add_recognizer(DutchPhoneRecognizer())

    logger.info("Presidio analyzer initialized with Dutch NLP + custom recognizers")
    return analyzer


analyzer = create_analyzer()
deduce_instance = Deduce()
logger.info("Deduce initialized")

DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS", "IBAN_CODE", "CREDIT_CARD", "IP_ADDRESS", "URL",
    "PHONE_NUMBER", "PERSON", "LOCATION", "ORGANIZATION",
    "BSN", "KVK_NUMBER", "NL_PHONE_NUMBER"
]


# === Cross-Reference Feedbackloop ===

# Words to skip during value propagation (common Dutch words, prepositions, etc.)
SKIP_WORDS = {
    "de", "het", "een", "van", "in", "op", "te", "en", "is", "dat", "die", "voor",
    "met", "zijn", "naar", "aan", "bij", "uit", "als", "maar", "nog", "wel", "niet",
    "ook", "dan", "kan", "moet", "zou", "zal", "heeft", "wordt", "werd", "geen",
    "meer", "veel", "goed", "naam", "naam:", "email", "telefoon", "adres", "straat",
    "true", "false", "null", "none", "yes", "no", "the", "and", "for", "with",
}

# Dutch tussenvoegsels — should not be propagated as standalone names
TUSSENVOEGSELS = {
    "van", "de", "den", "der", "het", "ten", "ter", "te", "in", "op",
    "aan", "bij", "tot", "uit", "von", "la", "le", "du", "des",
}


def extract_names_from_email(email_text):
    """Extract potential person names from email local part (before @)."""
    local = email_text.split("@")[0] if "@" in email_text else ""
    if not local or len(local) < 3:
        return []

    # Split on common separators: dots, underscores, hyphens
    parts = re.split(r'[._\-]', local)
    names = []
    for part in parts:
        part = part.strip()
        # Must be at least 2 chars, alphabetic, not a common word
        if (len(part) >= 2 and part.isalpha() and
            part.lower() not in SKIP_WORDS and
            part.lower() not in TUSSENVOEGSELS):
            names.append(part)
    return names


def find_additional_occurrences(text, value, existing_findings):
    """Find all occurrences of a value in text that aren't already covered by findings."""
    if len(value) < 3:
        return []

    additional = []
    # Use word-boundary regex for matching, case-insensitive
    try:
        pattern = re.compile(r'\b' + re.escape(value) + r'\b', re.IGNORECASE)
    except re.error:
        return []

    # Collect existing covered ranges
    covered = set()
    for f in existing_findings:
        for i in range(f.get("start", 0), f.get("end", 0)):
            covered.add(i)

    for match in pattern.finditer(text):
        start, end = match.start(), match.end()
        # Check if this span is already covered
        if not any(i in covered for i in range(start, end)):
            additional.append((start, end, match.group()))

    return additional


@app.route("/api/cross-reference", methods=["POST"])
def cross_reference():
    """Cross-reference feedbackloop: use detected PII values to find additional occurrences."""
    data = request.get_json()
    if not data or "text" not in data or "findings" not in data:
        return jsonify({"error": "Requires 'text' and 'findings'"}), 400

    text = data["text"]
    findings = data["findings"]
    additional_findings = []

    # Pass 1: Value propagation — search for detected values elsewhere in text
    for f in findings:
        value = f.get("text", "")
        entity_type = f.get("entity_type", "")

        # Skip short values, common words, and tussenvoegsels
        if (len(value) < 3 or
            value.lower() in SKIP_WORDS or
            value.lower() in TUSSENVOEGSELS):
            continue

        occurrences = find_additional_occurrences(text, value, findings + additional_findings)
        for start, end, matched in occurrences:
            additional_findings.append({
                "entity_type": entity_type,
                "start": start,
                "end": end,
                "score": f.get("score", 0.7),
                "text": matched,
                "source": "cross-reference",
                "reason": "value-propagation"
            })

    # Pass 2: Email-to-name extraction — derive names from email addresses
    email_findings = [f for f in findings if f.get("entity_type") in ("EMAIL_ADDRESS", "email")]
    for ef in email_findings:
        names = extract_names_from_email(ef.get("text", ""))
        for name in names:
            occurrences = find_additional_occurrences(text, name, findings + additional_findings)
            for start, end, matched in occurrences:
                additional_findings.append({
                    "entity_type": "PERSON",
                    "start": start,
                    "end": end,
                    "score": 0.5,
                    "text": matched,
                    "source": "cross-reference",
                    "reason": "email-extraction"
                })

    return jsonify({
        "additional_findings": additional_findings,
        "count": len(additional_findings)
    })


# === API Endpoints ===

@app.route("/api/presidio", methods=["POST"])
def analyze_presidio():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data["text"]
    threshold = data.get("threshold", 0.5)
    entities = data.get("entities", DEFAULT_ENTITIES)

    if len(text) > 2 * 1024 * 1024:
        return jsonify({"error": "Text too large (max 2MB)"}), 400

    try:
        results = analyzer.analyze(
            text=text,
            language="nl",
            entities=entities,
            score_threshold=threshold
        )

        findings = []
        for r in results:
            findings.append({
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 2),
                "text": text[r.start:r.end]
            })

        findings.sort(key=lambda f: f["start"])
        return jsonify({"findings": findings, "count": len(findings)})

    except Exception as e:
        logger.error(f"Presidio analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/deduce", methods=["POST"])
def analyze_deduce():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data["text"]

    if len(text) > 2 * 1024 * 1024:
        return jsonify({"error": "Text too large (max 2MB)"}), 400

    try:
        doc = deduce_instance.deidentify(text)

        findings = []
        for annotation in doc.annotations:
            findings.append({
                "entity_type": annotation.tag,
                "start": annotation.start_char,
                "end": annotation.end_char,
                "score": 0.75,
                "text": annotation.text
            })

        findings.sort(key=lambda f: f["start"])
        return jsonify({"findings": findings, "count": len(findings)})

    except Exception as e:
        logger.error(f"Deduce analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine": "presidio+deduce",
        "language": "nl",
        "model": "nl_core_news_lg",
        "deduce": "3.x",
        "cross_reference": True,
        "custom_recognizers": ["BSN", "KVK_NUMBER", "NL_PHONE_NUMBER"]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
