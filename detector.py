import ipaddress
import re

from models import Finding
from patterns import PATTERNS

def redact_email(email):
    username, domain = email.split("@", 1)

    if len(username) <=1:
        hidden_username = "*"
    else:
        hidden_username = username[0] + ("*" * (len(username) - 1))
    return f"{hidden_username}@{domain}"

def is_valid_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_phone(value):
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return False

    digits = re.sub(r"\D", "", value)

    return 7 <= len(digits) <= 15

def is_valid_luhn(value):
    digits = re.sub(r"\D", "", value)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(reverse_digits):
        number = int(digit)

        if index % 2 == 1:
            number *= 2

            if number > 9:
                number -= 9

        total += number

    return total % 10 == 0

def redact_card(value):
    digits = re.sub(r"\D", "", value)

    return "*" * (len(digits) - 4) + digits[-4:]

def overlaps(first, second):
    return first.start < second.end and second.start <first.end

def is_inside_card_like_sequence(text, start, end):
    card_pattern = r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"

    for match in re.finditer(card_pattern, text):
        if start >= match.start() and end <= match.end():
            return True
    return False
def extract_secret_value(value):
    if "=" in value:
        secret = value.split("=", 1)[1]
    elif ":" in value:
        secret = value.split(":", 1)[1]
    else:
        return ""

    return secret.strip().strip("\"'")


def secret_confidence(value):
    secret = extract_secret_value(value)

    if not secret:
        return "LOW"

    score = 0

    if len(secret) >= 12:
        score += 1

    if re.search(r"[a-z]", secret):
        score += 1

    if re.search(r"[A-Z]", secret):
        score += 1

    if re.search(r"\d", secret):
        score += 1

    if re.search(r"[^A-Za-z0-9]", secret):
        score += 1

    if score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"

def scan_text(text):
    findings = []

    for data_type, config in PATTERNS.items():
        pattern = config["pattern"]
        confidence = config["confidence"]

        for match in re.finditer(pattern, text):
            value = match.group()

            finding_confidence = confidence

            if data_type == "SECRET":
                finding_confidence = secret_confidence(value)

            if data_type == "IP_ADDRESS" and not is_valid_ipv4(value):
                continue

            if data_type == "PHONE":
                if not is_valid_phone(value):
                    continue

                if is_inside_card_like_sequence(
                    text,
                    match.start(),
                    match.end()
                ):
                    continue

            if data_type == "CREDIT_CARD" and not is_valid_luhn(value):
                continue

            if data_type == "EMAIL":
                redacted = redact_email(value)
            elif data_type == "PHONE":
                redacted = "[PHONE REDACTED]"
            elif data_type == "IP_ADDRESS":
                redacted = "[IP REDACTED]"
            elif data_type == "CREDIT_CARD":
                redacted = redact_card(value)
            elif data_type == "SECRET":
                redacted = "[SECRET REDACTED]"
            else:
                redacted = "[REDACTED]"

            finding = Finding(
                data_type=data_type,
                value=value,
                redacted_value=redacted,
                start=match.start(),
                end=match.end(),
                confidence=finding_confidence,
            )

            findings.append(finding)

        credit_cards = [
        finding
        for finding in findings
        if finding.data_type == "CREDIT_CARD"
    ]

        filtered_findings = []

    for finding in findings:
        if finding.data_type == "PHONE":
            overlaps_card = any(
                overlaps(finding, card)
                for card in credit_cards
            )

            if overlaps_card:
                continue

        filtered_findings.append(finding)

        filtered_findings.sort(key=lambda finding: finding.start)

    return filtered_findings
