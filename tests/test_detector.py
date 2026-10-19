from detector import scan_text, redact_email

def test_detect_single_email():
    results = scan_text("Contact jack@example.com for assistance.")

    assert len(results) == 1
    assert results[0].data_type == "EMAIL"
    assert results[0].value == "jack@example.com"
    assert results[0].confidence == "HIGH"

def test_detect_multiple_emails():
    results = scan_text(
        "Contact alice@company.com or bob@security.org"
    )

    assert len(results) == 2
    assert results[0].value == "alice@company.com"
    assert results[1].value == "bob@security.org"

def test_email_redaction():
    assert redact_email("jack@example.com") == "j***@example.com"
    assert redact_email("alice@company.com") == "a****@company.com"

def test_single_character_email_redaction():
    assert redact_email("a@example.com") == "*@example.com"

def test_no_sensitive_data():
    results = scan_text("This sentence contains no sensitive information.")

    assert results == []

def test_email_position():
    text = "Contact jack@example.com today."
    results = scan_text(text)

    finding = results[0]

    assert text[finding.start:finding.end] == "jack@example.com"

def test_detect_phone():
    results = scan_text("Call +254 712 345 678")

    phone_results = [
        finding for finding in results
        if finding.data_type == "PHONE"
    ]
    assert len(phone_results) == 1
    assert phone_results[0].value == "+254 712 345 678"
    assert phone_results[0].redacted_value == "[PHONE REDACTED]"
    assert phone_results[0].confidence == "MEDIUM"

def test_detect_valid_ipv4():
    results = scan_text("Server IP: 192.168.1.25")

    ip_results = [
        finding for finding in results
        if finding.data_type == "IP_ADDRESS"
    ]

    assert len(ip_results) == 1
    assert ip_results[0].value == "192.168.1.25"
    assert ip_results[0].redacted_value == "[IP REDACTED]"

def test_reject_invalid_ipv4():
    results = scan_text("Server IP: 999.999.999.999")

    assert results == []

def test_ip_not_detected_as_phone():
    results = scan_text("Server IP:  192.168.1.25")

    phone_results = [
        finding for finding in results
        if finding.data_type == "PHONE"
    ]

    assert phone_results == []

def test_mixed_sensitive_data():
    results = scan_text(
        "Contact admin@example.com from 192.168.1.25 "
        "or call +254 712 345 678."
    )

    data_types = {
        finding.data_type
        for finding in results
    }

    assert data_types == {
        "EMAIL",
        "PHONE",
        "IP_ADDRESS",
    }

def test_valid_credit_card():
    results = scan_text(
        "Payment card: 4539 1488 0343 6467"
    )

    cards = [
        finding for finding in results
        if finding.data_type == "CREDIT_CARD"
    ]

    assert len(cards) == 1
    assert cards[0].value == "4539 1488 0343 6467"
    assert cards[0].redacted_value == "************6467"
    assert cards[0].confidence == "HIGH"


def test_invalid_credit_card():
    results = scan_text(
        "Random number: 4539 1488 0343 6468"
    )

    assert results == []


def test_card_not_detected_as_phone():
    results = scan_text(
        "Payment card: 4539 1488 0343 6467"
    )

    phones = [
        finding for finding in results
        if finding.data_type == "PHONE"
    ]

    assert phones == []


def test_luhn_validation():
    from detector import is_valid_luhn

    assert is_valid_luhn("4539 1488 0343 6467") is True
    assert is_valid_luhn("4539 1488 0343 6468") is False


def test_card_redaction():
    from detector import redact_card

    assert (
        redact_card("4539 1488 0343 6467")
        == "************6467"
    )
def test_detect_secret():
    results = scan_text(
        'api_key = "f8Jk2Pq9Xm4Vz7Lc"'
    )

    secrets = [
        finding for finding in results
        if finding.data_type == "SECRET"
    ]

    assert len(secrets) == 1
    assert secrets[0].redacted_value == "[SECRET REDACTED]"
    assert secrets[0].confidence == "HIGH"


def test_low_confidence_secret():
    results = scan_text('password = "password"')

    assert len(results) == 1
    assert results[0].data_type == "SECRET"
    assert results[0].confidence == "LOW"


def test_medium_confidence_secret():
    results = scan_text('api_key = "abc12345"')

    assert len(results) == 1
    assert results[0].confidence == "MEDIUM"


def test_secret_discussion_not_detected():
    results = scan_text(
        "Please reset your password tomorrow."
    )

    assert results == []


def test_secret_value_not_exposed():
    results = scan_text(
        'password = "MyStrongPassword123!"'
    )

    assert results[0].redacted_value == "[SECRET REDACTED]"
