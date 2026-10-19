PATTERNS = {
    "EMAIL": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "confidence": "HIGH",
    },

    "PHONE": {
        "pattern": r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{3,4}(?!\w)",
        "confidence": "MEDIUM",
    },

    "IP_ADDRESS": {
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "confidence": "HIGH",
    },

    "CREDIT_CARD": {
        "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "confidence": "HIGH",
    },



    "SECRET": {
        "pattern": r"""(?i)\b(?:api[_-]?key|secret[_-]?key|secret[_-]?token|access[_-]?token|password|passwd)\b\s*[:=]\s*["']?([A-Za-z0-9_\-!@#$%^&*./+=]{8,})["']?""",
        "confidence": "HIGH",
    },
    }
