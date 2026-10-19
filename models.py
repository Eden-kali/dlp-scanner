from dataclasses import dataclass

@dataclass
class Finding:
    data_type: str
    value: str
    redacted_value: str
    start: int
    end: int
    confidence: str
