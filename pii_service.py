"""
PII Detection Microservice — Presidio + Deduce + Custom Dutch Recognizers
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
        "custom_recognizers": ["BSN", "KVK_NUMBER", "NL_PHONE_NUMBER"]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
