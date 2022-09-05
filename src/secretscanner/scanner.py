from pathlib import Path
from typing import Generator

from secretscanner.find import find_tokens
from secretscanner.types import (
    TokenInfo,
    TokenIssuerParseInfo,
    TokenParseInfo,
    TokenResults,
)

token_format: TokenParseInfo = {
    "github": "[A-Za-z0-9_]{36,251}",
    "digitalocean": "[A-Za-z0-9_]{64,}",
}
token_issuer_parse_info: TokenIssuerParseInfo = {
    "github": {
        "pat": f"re(ghp_{token_format['github']})",
        "oauth": f"re(gho_{token_format['github']})",
        "user-to-server": f"re(ghu_{token_format['github']})",
        "server-to-server": f"re(ghs_{token_format['github']})",
        "refresh": f"re(ghr_{token_format['github']})",
    },
    "pypi": {"pat": "re(pypi-[A-Za-z0-9_]{16,})"},
    # https://docs.digitalocean.com/reference/api/create-personal-access-token/
    "digitalocean": {
        "pat": f"re(dop_v1_{token_format['digitalocean']})",
        "oauth": f"re(doo_v1_{token_format['digitalocean']})",
        "refresh": f"re(dor_v1_{token_format['digitalocean']})",
    },
    "postgresql": {"url": "url(postgres)"},
}


def walk(path: Path) -> Generator[Path, None, None]:
    for p in Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def scan(scan_dir: Path) -> TokenResults:
    found: TokenResults = []
    for f in walk(scan_dir):
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
                            ft: TokenInfo = {
                                "file": str(f),
                                "issuer": issuer,
                                "type": token_type,
                                "token": str(match.group(0)),
                                "ignored": True,
                            }
                            found.append(ft)

    return found
