import stat
import argparse
import json
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from detector import scan_text

console = Console()

MAX_FILE_SIZE = 5 * 1024 * 1024

SUPPORTED_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".env",
    ".py",
    ".js",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
}

SKIP_DIRECTORIES = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
}

#A. Scan an entire directory
def scan_directory(directory_path, json_output=None):
    directory = Path(directory_path)

    if not directory.is_dir():
        console.print("[red]Invalid directory.[/red]")
        return

    files_scanned = 0
    files_skipped = 0
    all_findings = []
    file_reports = []

    for root, dirs, files in os.walk(
        directory,
        topdown=True,
        followlinks=False,
    ):
        root_path = Path(root)

        dirs[:] = sorted(
            name
            for name in dirs
            if name not in SKIP_DIRECTORIES
            and not (root_path / name).is_symlink()
        )

        for filename in sorted(files):
            path = root_path / filename

            if path.is_symlink() or not path.is_file():
                continue

            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue

            if path.name.endswith(".dlp-report.json"):
                continue

            console.print(
                f"\n[bold cyan]Scanning:[/bold cyan] {path}"
            )

            findings = scan_file(path)

            if findings is None:
                files_skipped += 1
                continue

            files_scanned += 1
            all_findings.extend(findings)

            file_reports.append({
                "file": str(path),
                "total_findings": len(findings),
                "findings": [
                    {
                        "data_type": finding.data_type,
                        "redacted_value": finding.redacted_value,
                        "confidence": finding.confidence,
                        "start": finding.start,
                        "end": finding.end,
                    }
                    for finding in findings
                ],
            })

    high = sum(
        finding.confidence == "HIGH"
        for finding in all_findings
    )

    medium = sum(
        finding.confidence == "MEDIUM"
        for finding in all_findings
    )

    low = sum(
        finding.confidence == "LOW"
        for finding in all_findings
    )

    console.print(
        Panel(
            f"Files Scanned: {files_scanned}\n"
            f"Total Findings: {len(all_findings)}\n"
            f"High Confidence: {high}\n"
            f"Medium Confidence: {medium}\n"
            f"Low Confidence: {low}",
            title="Directory Security Summary",
            border_style="magenta",
        )
    )

    if json_output:
        report = {
            "scanner": "DLP Security Scanner",
            "source": str(directory),
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "total_findings": len(all_findings),
            "summary": {
                "high": high,
                "medium": medium,
                "low": low,
            },
            "files": file_reports,
        }

        export_report_data(report, json_output)

#B. Scan individual file.

def scan_file(file_path):
    path = Path(file_path)

    if path.is_symlink():
        console.print(
            "[yellow]SKIPPED:[/yellow] Symbolic links are not scanned."
        )
        return None

    if not path.is_file():
        console.print(
            f"[red]ERROR:[/red] File not found: {path}"
        )
        return None

    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW

        fd = os.open(path, flags)

        with os.fdopen(fd, "rb") as file:
            file_info = os.fstat(file.fileno())

            if not stat.S_ISREG(file_info.st_mode):
                console.print(
                    "[yellow]SKIPPED:[/yellow]"
                    "Not a regular file."
                )
                return None

            if file_info.st_size > MAX_FILE_SIZE:
                console.print(
                    "[yellow]SKIPPED[/yellow] "
                    f"File exceeds the 5 MiB size limit: {path}"
                )
                return None

            raw_content = file.read(MAX_FILE_SIZE + 1)

        if len(raw_content) > MAX_FILE_SIZE:
            console.print(
                "[yellow]SKIPPED[/yellow] "
                f"File exceeds the 5 MiB size limit: {path}"
            )
            return None

        content = raw_content.decode("utf-8")

    except (OSError, UnicodeError) as error:
        console.print(
            f"[red]ERROR[/red] Unable to read file: {error}"
        )
        return None

    findings = scan_text(content)

    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]DLP SECURITY SCANNER[/bold cyan]\n"
            f"Target: {path}",
            title="Security Audit",
            border_style="cyan",
        )
    )

    if not findings:
        console.print(
            "[green]No sensitive data detected.[/green]"
        )
        return findings

    table = Table(
        title="Sensitive Data Findings",
        show_lines=True
    )

    table.add_column("Line", justify="center")
    table.add_column("Data Type", style="cyan")
    table.add_column("Redacted Value")
    table.add_column("Confidence")

    confidence_colors = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    for finding in findings:
        line_number = content.count(
            "\n", 0, finding.start
        ) + 1

        color = confidence_colors.get(
            finding.confidence, "white"
        )

        table.add_row(
            str(line_number),
            finding.data_type,
            finding.redacted_value,
            f"[{color}]{finding.confidence}[/{color}]",
        )

    console.print(table)

    high = sum(
        1 for finding in findings
        if finding.confidence == "HIGH"
    )

    medium = sum(
        1 for finding in findings
        if finding.confidence == "MEDIUM"
    )

    low = sum(
        1 for finding in findings
        if finding.confidence == "LOW"
    )

    console.print(
        Panel(
            f"Total Findings: {len(findings)}\n"
            f"High Confidence: {high}\n"
            f"Medium Confidence: {medium}\n"
            f"Low Confidence: {low}",
            title="Scan Summary",
            border_style="blue",
        )
    )
    return findings
#C. Build a single-file JSON report.

def export_json(findings, source_path, output_path):
    report = {
        "scanner": "DLP Security Scanner",
        "source": str(source_path),
        "total_findings": len(findings),
        "findings": [
            {
                "data_type": finding.data_type,
                "redacted_value": finding.redacted_value,
                "confidence": finding.confidence,
                "start": finding.start,
                "end": finding.end,
            }
            for finding in findings
        ],
    }

    return export_report_data(report, output_path)

#D. Securely write a json report

def export_report_data(report, output_path):
    output = Path(output_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    created = False

    try:
        fd = os.open(output, flags, 0o600)
        created = True

        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        console.print(
            f"[green]JSON report saved:[/green] {output}"
        )
        return True

    except FileExistsError:
        console.print(
            "[yellow]ERROR:[/yellow] Report already exists. "
            "Choose a different filename."
        )

    except (OSError, TypeError, ValueError) as error:
        console.print(
            f"[red]ERROR:[/red] Could not save report: {error}"
        )

    if created:
        try:
            output.unlink()
        except OSError as error:
            console.print(
                f"[yellow]WARNING:[/yellow] "
                f"Could not remove incomplete report: {error}"
            )

    return False

#E. Handle cli arguments.
def main():
    parser = argparse.ArgumentParser(
        description="DLP Scanner - Detect sensitive information in files"
    )

    parser.add_argument(
        "command",
        choices=["scan"],
        help="Action to perform",
    )

    parser.add_argument(
        "--json",
        dest="json_output",
        help="Save redacted findings as a JSON report",
    )

    parser.add_argument(
        "file",
        help="Path to the file to scan",
    )

    args = parser.parse_args()

    if args.command == "scan":
        target = Path(args.file)

        if target.is_dir():
            scan_directory(target, args.json_output)

        else:
            findings = scan_file(target)

            if args.json_output and findings is not None:
                export_json(
                    findings,
                    target,
                    args.json_output,
                )


if __name__ == "__main__":
    main()
