"""Secret scanning"""
from pathlib import Path
from typing import Generator

from rich.progress import Progress

from secretscanner.secret_info import secret_issuer_parse_info
from secretscanner.find import find_secrets
from secretscanner.gitignore import set_ignored_flag
from secretscanner.types import (
    Secret,
    SecretResults,
    ScanResults,
)
from secretscanner.progress_column_file import FileColumn


def file_filter(path: Path):
    """Filter out files before processing"""
    return path


def walk(path: Path) -> Generator[str, None, None]:
    """Walk a path and return all files found"""
    for entry in Path(path).iterdir():
        if entry.is_dir():
            yield from walk(entry)
            continue

        if entry.stat().st_size <= 0:
            continue

        resolved = entry.resolve()
        if file_filter(resolved):
            yield str(resolved)


def scan(scan_path: Path, quiet: bool = False) -> ScanResults | None:
    """Scan a path for secrets"""
    if scan_path.is_file():
        files = [str(scan_path)]
    else:
        files = list(walk(scan_path))

    if not files:
        return None

    file_count = len(files)
    finished_time = 0
    found: SecretResults = []

    if quiet:
        for idx, file_to_scan in enumerate(files):
            scan_file(file_to_scan, found)
    else:
        if file_count > 1:
            file_progress_column = FileColumn(files, root_path=str(scan_path))
            task = None
            with Progress(
                *Progress.get_default_columns(), file_progress_column
            ) as progress:
                scan_task = progress.add_task("Scanning...", total=file_count)
                for idx, file_to_scan in enumerate(files):
                    scan_file(file_to_scan, found)
                    progress.update(scan_task, completed=idx + 1)

                task = progress._tasks[scan_task]  # type: ignore

            finished_time = int(task.finished_time or 0)
        else:
            scan_file(files[0], found)

    if found:
        set_ignored_flag(found, scan_path)

    results: ScanResults = {
        "file_count": file_count,
        "scan_time": finished_time,
        "secrets": found,
    }
    return results


def scan_file(file_to_scan: str, found: SecretResults):
    """Scan a single file for secrets"""
    with open(file_to_scan, "r", encoding="utf-8") as fileptr:
        try:
            data = fileptr.read(-1)
        except UnicodeDecodeError:
            return

    for issuer, secret_info in secret_issuer_parse_info.items():
        for secret_type, secret_format in secret_info.items():
            secrets = find_secrets(data, secret_format)
            if secrets:
                for secret_text in secrets:
                    secret: Secret = {
                        "file": str(file_to_scan),
                        "issuer": issuer,
                        "type": secret_type,
                        "secret": secret_text,
                        "ignored": False,
                    }
                    found.append(secret)
