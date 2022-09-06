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
    for p in Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def scan(scan_me: Path) -> TokenResults:
    """Scan a path for tokens"""
    if scan_me.is_file():
        files = [scan_me]
    else:
        files = list(walk(scan_me))

    found: TokenResults = []
    for f in files:
        with open(f, "r") as fp:
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
                        ft: Token = {
                            "file": str(f),
                            "issuer": issuer,
                            "type": token_type,
                            "token": token_text,
                            "ignored": False,
                        }
                        found.append(ft)

    if found:
        set_ignored_flag(found, scan_me)

    return found
