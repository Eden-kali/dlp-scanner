import json

from main import scan_directory
from main import export_json
from detector import scan_text

from main import scan_file, MAX_FILE_SIZE


def test_scan_file_detects_email(tmp_path):
    file_path = tmp_path / "contacts.txt"
    file_path.write_text(
        "Contact alice@example.com",
        encoding="utf-8"
    )

    findings = scan_file(file_path)

    assert len(findings) == 1
    assert findings[0].data_type == "EMAIL"


def test_scan_file_rejects_large_files(tmp_path):
    file_path = tmp_path / "large.txt"

    with file_path.open("wb") as file:
        file.truncate(MAX_FILE_SIZE + 1)

    findings = scan_file(file_path)

    assert findings is None


def test_scan_file_rejects_symlinks(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text(
        "admin@example.com",
        encoding="utf-8"
    )

    link = tmp_path / "linked.txt"
    link.symlink_to(original)

    findings = scan_file(link)

    assert findings is None


def test_scan_file_handles_missing_files(tmp_path):
    missing = tmp_path / "missing.txt"

    findings = scan_file(missing)

    assert findings is None

def test_json_export_creates_file(tmp_path):
    findings = scan_text("Contact alice@example.com")
    output = tmp_path / "report.json"

    export_json(findings, "sample.txt", output)

    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["total_findings"] == 1
    assert report["findings"][0]["data_type"] == "EMAIL"


def test_json_export_redacts_secrets(tmp_path):
    secret = "MyStrongPassword123!"
    findings = scan_text(f'password = "{secret}"')
    output = tmp_path / "report.json"

    export_json(findings, "config.env", output)

    report_text = output.read_text(encoding="utf-8")
    report = json.loads(report_text)

    assert secret not in report_text
    assert report["findings"][0]["redacted_value"] == "[SECRET REDACTED]"


def test_json_export_empty_findings(tmp_path):
    output = tmp_path / "empty.json"

    export_json([], "empty.txt", output)

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["total_findings"] == 0
    assert report["findings"] == []

def test_json_export_prevents_overwrite(tmp_path):
    output = tmp_path / "reports.json"

    output.write_text(
        "Original report",
        encoding="utf-8"
    )

    result = export_json([], "sample.txt", output)

    assert result is False
    assert output.read_text(
        encoding="utf-8"
    ) == "Original report"

def test_directory_json_export(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    (directory / "contacts.txt").write_text(
        "alice@example.com",
        encoding="utf-8"
    )

    (directory / "server.log").write_text(
        "192.168.1.25",
        encoding="utf-8"
    )

    output = tmp_path / "directory_report.json"

    scan_directory(directory, output)

    assert output.exists()

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 2
    assert report["total_findings"] == 2
    assert len(report["files"]) == 2


def test_directory_json_export_redacts_secrets(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    secret = "MyStrongPassword123!"

    (directory / "config.env").write_text(
        f'password = "{secret}"',
        encoding="utf-8"
    )

    output = tmp_path / "directory_report.json"

    scan_directory(directory, output)

    report_text = output.read_text(
        encoding="utf-8"
    )

    assert secret not in report_text
    assert "[SECRET REDACTED]" in report_text


def test_directory_json_export_empty_directory(tmp_path):
    directory = tmp_path / "empty_documents"
    directory.mkdir()

    output = tmp_path / "empty_report.json"

    scan_directory(directory, output)

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 0
    assert report["total_findings"] == 0
    assert report["files"] == []

def test_directory_skips_generated_reports(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    (directory / "contacts.txt").write_text(
        "alice@example.com",
        encoding="utf-8"
    )

    (directory / "previous.dlp-report.json").write_text(
        '{"email": "bob@example.com"}',
        encoding="utf-8"
    )

    output = tmp_path / "result.json"

    scan_directory(directory, output)

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 1
    assert report["total_findings"] == 1
    assert len(report["files"]) == 1
    assert report["files"][0]["file"].endswith(
        "contacts.txt"
    )

def test_directory_does_not_follow_symlinked_folders(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    external = tmp_path / "external"
    external.mkdir()

    (external / "secret.txt").write_text(
        "hidden@example.com",
        encoding="utf-8"
    )

    (directory / "linked_external").symlink_to(
        external,
        target_is_directory=True
    )

    output = tmp_path / "symlink-report.json"

    scan_directory(directory, output)

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 0
    assert report["total_findings"] == 0


def test_directory_skips_excluded_folders(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    excluded = directory / ".venv"
    excluded.mkdir()

    (excluded / "secrets.txt").write_text(
        "hidden@example.com",
        encoding="utf-8"
    )

    (directory / "visible.txt").write_text(
        "visible@example.com",
        encoding="utf-8"
    )

    output = tmp_path / "excluded-report.json"

    scan_directory(directory, output)

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 1
    assert report["total_findings"] == 1
    assert report["files"][0]["file"].endswith(
        "visible.txt"
    )

def test_directory_counts_skipped_large_files(tmp_path):
    directory = tmp_path / "documents"
    directory.mkdir()

    (directory / "valid.txt").write_text(
        "alice@example.com",
        encoding="utf-8"
    )

    (directory / "large.txt").write_bytes(
        b"A" * (5 * 1024 * 1024 + 1)
    )

    output = tmp_path / "skipped-report.json"

    scan_directory(directory, output)

    report = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert report["files_scanned"] == 1
    assert report["files_skipped"] == 1
    assert report["total_findings"] == 1
    assert len(report["files"]) == 1

def test_json_export_removes_incomplete_report(tmp_path):
    from main import export_report_data

    output = tmp_path / "incomplete.dlp-report.json"

    report = {
        "scanner": "DLP Security Scanner",
        "findings": [
            {"data_type": "EMAIL", "value": "redacted"},
            {"invalid": object()}
        ]
    }

    result = export_report_data(report, output)

    assert result is False
    assert not output.exists()

def test_scan_file_rejects_symlink_race(tmp_path, monkeypatch):
    import os
    from pathlib import Path

    from main import scan_file

    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text(
        "alice@example.com",
        encoding="utf-8"
    )

    target = tmp_path / "target.txt"
    target.write_text(
        "Safe content",
        encoding="utf-8"
    )

    original_open = os.open

    def replace_before_open(path, flags, *args, **kwargs):
        if Path(path) == target:
            target.unlink()
            target.symlink_to(sensitive)

        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_before_open)

    findings = scan_file(target)

    assert findings is None
