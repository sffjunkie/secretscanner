"""Secret scanning"""
from pathlib import Path
from typing import Generator

from secretscanner.secret_info import secret_issuer_parse_info
from secretscanner.find import find_secrets
from secretscanner.gitignore import set_ignored_flag
from secretscanner.types import (
    Secret,
    SecretResults,
)


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
        files = [scan_path]
    else:
        files = list(walk(scan_path))

    found: SecretResults = []
    for file_to_scan in files:
        with open(file_to_scan, "r") as fp:
            try:
                data = fp.read(-1)
            except UnicodeDecodeError:
                continue

        for issuer, secret_info in secret_issuer_parse_info.items():
            for secret_type, secret_format in secret_info.items():
                secrets = find_secrets(data, secret_format)
                if secrets:
                    for match in secrets:
                        secret_text = str(match.group(0))
                        secret: Secret = {
                            "file": str(file_to_scan),
                            "issuer": issuer,
                            "type": secret_type,
                            "secret": secret_text,
                            "ignored": False,
                        }
                        found.append(secret)

    if found:
        set_ignored_flag(found, scan_path)

    return found
