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
)
from secretscanner.progress_column_file import FileColumn


def walk(path: Path) -> Generator[Path, None, None]:
    """Walk a path and return all files found"""
    for entry in Path(path).iterdir():
        if entry.is_dir():
            yield from walk(entry)
            continue
        yield entry.resolve()


def scan(scan_path: Path) -> SecretResults:
    """Scan a path for secrets"""
    if scan_path.is_file():
        files = [str(scan_path)]
    else:
        files = list(walk(scan_path))

    found: SecretResults = []
    file_count = len(files)
    file_progress_column = FileColumn(files, root_path=str(scan_path))

    with Progress(*Progress.get_default_columns(), file_progress_column) as progress:
        scan_task = progress.add_task("Scanning...", total=file_count)
        for idx, file_to_scan in enumerate(files):
        with open(file_to_scan, "r") as fp:
            try:
                data = fp.read(-1)
            except UnicodeDecodeError:
                continue

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

            progress.update(scan_task, completed=idx + 1)

    if found:
        set_ignored_flag(found, scan_path)

    return found
