# 🔐 DLP Security Scanner

A Python-based Data Loss Prevention (DLP) scanner designed to identify potentially sensitive information in text files and directories.

The scanner uses regular expressions, validation techniques, confidence ratings, and redaction to help identify possible data exposure.

Built as an educational cybersecurity project focused on defensive security, secure file handling, and automated testing.

## Features

* **Sensitive data detection:** Identifies email addresses, phone numbers, IPv4 addresses, credit card numbers, and potential secrets.
* **Credit card validation:** Uses the Luhn algorithm to reduce false positives.
* **Recursive directory scanning:** Scans supported files within a directory.
* **Confidence classification:** Categorizes findings as HIGH, MEDIUM, or LOW confidence.
* **Sensitive data redaction:** Masks detected values in terminal output and JSON reports.
* **JSON reporting:** Exports structured reports for individual files or directories.
* **File-size protection:** Limits individual scans to 5 MiB.
* **Symlink protection:** Uses Linux file-opening safeguards to reduce certain symbolic-link risks.
* **Safer report creation:** Prevents overwriting existing reports and attempts to remove incomplete reports after write errors.
* **Automated testing:** Includes 38 pytest tests.

## Technologies Used

* Python 3
* Rich — terminal formatting
* pytest — automated testing
* Regular expressions
* Python standard-library file handling and JSON modules

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/dlp-scanner.git
cd dlp-scanner
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

### Scan a single file

```bash
python main.py scan sample.txt
```

### Scan a directory

```bash
python main.py scan test_documents/
```

### Export a single-file JSON report

```bash
python main.py scan sample.txt --json sample.dlp-report.json
```

### Export a directory JSON report

```bash
python main.py scan test_documents/ --json directory.dlp-report.json
```

Reports are created without overwriting existing files.

## Example Findings

| Data type   | Example redacted output | Confidence |
| ----------- | ----------------------- | ---------- |
| EMAIL       | `j***@example.com`      | HIGH       |
| IP_ADDRESS  | `[IP REDACTED]`         | HIGH       |
| PHONE       | `[PHONE REDACTED]`      | MEDIUM     |
| CREDIT_CARD | `************6467`      | HIGH       |
| SECRET      | `[SECRET REDACTED]`     | HIGH       |

The examples use synthetic test data.

## Running Tests

Execute the full test suite:

```bash
python -m pytest -v
```

Latest verified local result:

```text
38 passed in 0.18s
```

Tests cover sensitive-data detection, redaction, input validation, directory scanning, JSON exports, file-size restrictions, symlink handling, and report cleanup.

## Security Considerations

The scanner incorporates several defensive controls, but it is not a complete security boundary.

* Pattern-based detection can produce false positives and false negatives.
* Scanning supports selected text-based file extensions, not arbitrary binary documents.
* Symbolic-link protections reduce certain risks but do not eliminate every filesystem race condition.
* Failed report writes trigger cleanup attempts, but sudden process termination or power loss may leave incomplete reports.
* Redacted reports may still contain metadata such as filenames, offsets, and partial values.
* The scanner does not automatically quarantine, encrypt, or block files.

Use the tool only on files and directories you own or are authorized to inspect.

## Project Structure

```text
dlp-scanner/
├── main.py
├── detector.py
├── patterns.py
├── models.py
├── requirements.txt
├── README.md
├── .gitignore
├── sample.txt
├── test_documents/
└── tests/
    ├── test_cli.py
    └── test_detector.py
```

## Future Improvements

* Configurable detection patterns
* CSV and HTML report formats
* File exclusion rules configurable from the CLI
* Improved filesystem error reporting
* Additional automated security tests
* Support for more document formats

## Disclaimer

This project is intended for cybersecurity education, authorized security assessments, and defensive research. It is not a replacement for enterprise-grade DLP software.

## Author

Developed by **Eden-kali** as part of a cybersecurity learning and project portfolio.
