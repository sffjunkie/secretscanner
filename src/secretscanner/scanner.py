"""Secret scanning"""
from datetime import timedelta
from pathlib import Path
from typing import Generator

from rich.progress import Progress
from rich.text import Text

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

    if not files:
        return []

    found: SecretResults = []
    file_count = len(files)
    file_progress_column = FileColumn(files, root_path=str(scan_path))

    task = None
    with Progress(*Progress.get_default_columns(), file_progress_column) as progress:
        scan_task = progress.add_task("Scanning...", total=file_count)
        for idx, file_to_scan in enumerate(files):
            with open(file_to_scan, "r", encoding="utf-8") as fileptr:
            try:
                    data = fileptr.read(-1)
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

        task = progress._tasks[scan_task]  # type: ignore

    finished_time = int(task.finished_time or 0)
    print(f"{len(files)} files scanned", end="")

    if finished_time > 0:
        total_time = timedelta(seconds=finished_time)
        finished_time_text = Text(str(total_time), style="progress.elapsed")
        print(f" in {finished_time_text}")
    else:
        print()

    if found:
        set_ignored_flag(found, scan_path)

    return found
