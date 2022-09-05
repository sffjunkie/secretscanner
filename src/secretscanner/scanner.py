from pathlib import Path
from typing import Generator

from secretscanner.find import find_tokens
from secretscanner.gitignore import set_ignored_flag
from secretscanner.types import (
    TokenInfo,
    TokenIssuerParseInfo,
    TokenParseInfo,
    TokenResults,
)

token_format: TokenParseInfo = {
    "github": "[A-Za-z0-9_]{36,251}",
    "digitalocean": "[A-Za-z0-9_]{64,}",
    "adafruit": "[A-Za-z0-9]{32}",
    "discord": "[A-Za-z0-9]{32}",
    "linode": "[A-Za-z0-9]{64}",
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
    "adafruit": {
        # https://io.adafruit.com/api/docs/#authentication
        "header": f"re(X-AIO-Key: {token_format['adafruit']})",
        "url": f"re(x-aio-key={token_format['adafruit']})",
        "env": fr"ADAFRUIT_IO_KEY\s*\=\s*{token_format['adafruit']}",
    },
    "discord": {
        "url": f"re(client_id={token_format['discord']})",
        "bot": f"re(Authorization: Bot {token_format['discord']})",
    },
    "linode": {
        "env": fr"LINODE_API_TOKEN\s*=\s*{token_format['linode']}",
        "yaml": fr"LINODE_API_TOKEN\s*:\s*\"?{token_format['linode']}\"?",
        "bearer": f"re(Authorization: Bearer {token_format['linode']})",
    },
}


def walk(path: Path) -> Generator[Path, None, None]:
    for p in Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def scan(scan_me: Path) -> TokenResults:
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
                        ft: TokenInfo = {
                            "file": str(f),
                            "issuer": issuer,
                            "type": token_type,
                            "token": str(match.group(0)),
                            "ignored": True,
                        }
                        found.append(ft)

    if found:
        set_ignored_flag(found, scan_me)

    return found
