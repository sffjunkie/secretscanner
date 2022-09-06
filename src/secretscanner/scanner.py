"""Token scanning"""
from pathlib import Path
from typing import Generator

from secretscanner.token_info import token_issuer_parse_info
from secretscanner.find import find_tokens
from secretscanner.gitignore import set_ignored_flag
from secretscanner.types import (
    Token,
    TokenResults,
)


def walk(path: Path) -> Generator[Path, None, None]:
    """Walk a path and return all files found"""
    for entry in Path(path).iterdir():
        if entry.is_dir():
            yield from walk(entry)
            continue
        yield entry.resolve()


def scan(scan_path: Path) -> TokenResults:
    """Scan a path for tokens"""
    if scan_path.is_file():
        files = [scan_path]
    else:
        files = list(walk(scan_path))

    found: TokenResults = []
    for file_to_scan in files:
        with open(file_to_scan, "r") as fp:
            try:
                data = fp.read(-1)
            except UnicodeDecodeError:
                continue

        for issuer, token_info in token_issuer_parse_info.items():
            for token_type, token_format in token_info.items():
                tokens = find_tokens(data, token_format)
                if tokens:
                    for match in tokens:
                        token_text = str(match.group(0))
                        token: Token = {
                            "file": str(file_to_scan),
                            "issuer": issuer,
                            "type": token_type,
                            "token": token_text,
                            "ignored": False,
                        }
                        found.append(token)

    if found:
        set_ignored_flag(found, scan_path)

    return found
