import json
import re
from collections import defaultdict
from pathlib import Path
from textwrap import wrap
from typing import Any, Generator, TypedDict

import rich
import rich.console

__version__ = "0.1.1"

home = Path.home()
config_dir = home / ".config"

TokenIssuer = str
Tokens = dict[str, str]
TokenInfo = dict[TokenIssuer, Tokens]

token_format: dict[str, str] = {
    "github": "[A-Za-z0-9_]{36,251}",
    "digitalocean": "[A-Za-z0-9_]{64,}",
}
tokens: TokenInfo = {
    "github": {
        "pat": f"ghp_{token_format['github']}",
        "oauth": f"gho_{token_format['github']}",
        "user-to-server": f"ghu_{token_format['github']}",
        "server-to-server": f"ghs_{token_format['github']}",
        "refresh": f"ghr_{token_format['github']}",
    },
    "pypi": {"pat": "pypi-[A-Za-z0-9_]{16,}"},
    # https://docs.digitalocean.com/reference/api/create-personal-access-token/
    "digitalocean": {
        "pat": f"dop_v1_{token_format['digitalocean']}",
        "oauth": f"doo_v1_{token_format['digitalocean']}",
        "refresh": f"dor_v1_{token_format['digitalocean']}",
    },
}


class TokenResult(TypedDict):
    file: str
    issuer: TokenIssuer
    token: str
    type: str


FoundTokens = list[TokenResult]


def walk(path: Path) -> Generator[Path, None, None]:
    for p in Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def scan(walk_me: Path) -> FoundTokens:
    found: FoundTokens = []
    for f in walk(walk_me):
        with open(f, "r") as fp:
            try:
                data = fp.read(-1)
            except UnicodeDecodeError:
                continue

            for issuer, token_info in tokens.items():
                for token_type, token_re in token_info.items():
                    matches = re.finditer(token_re, data, flags=re.IGNORECASE)
                    if matches is not None:
                        for match in matches:
                            ft: TokenResult = {
                                "file": str(f),
                                "issuer": issuer,
                                "type": token_type,
                                "token": str(match.group(0)),
                            }
                            found.append(ft)

    return found


def report(tokens: FoundTokens, verbose: bool) -> None:
    console = rich.console.Console()
    indent = "  "

    files: dict[str, list[Any]] = defaultdict(list)
    for item in tokens:
        files[item["file"]].append(item)

    if files:
        rich.print("[green]Files with embedded secrets:[/]")
        for file, tokens in files.items():
            rich.print(f"{indent}[yellow]{file}[/]")
            if verbose:
                for token in tokens:
                    rich.print(f"{indent*2}- [blue]Issuer[/]: {token['issuer']}")
                    rich.print(f"{indent*2}  [blue]Type[/]: {token['type']}")
                    if len(token["token"]) + 20 < console.width:
                        rich.print(f"{indent*2}  [blue]Token[/]: {token['token']}")
                    else:
                        rich.print(f"{indent*2}  [blue]Token[/]:")
                        txt = wrap(
                            token["token"],
                            width=console.width - 4,
                            initial_indent=indent * 3 + "  ",
                            subsequent_indent=indent * 3 + "  ",
                        )
                        rich.print("\n".join(txt))


def json_report(tokens: FoundTokens) -> None:
    print(json.dumps(tokens))
