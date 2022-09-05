import json
from collections import defaultdict
from textwrap import wrap
from typing import Any

import rich
import rich.console

from secretscanner.types import TokenResults, TokenInfo

INDENT = "  "


def tokenlist_to_dict(tokens: TokenResults) -> dict[str, list[Any]]:
    files: dict[str, list[Any]] = defaultdict(list)
    for item in tokens:
        files[item["file"]].append(item)

    return files


def print_token(token: TokenInfo, console: rich.console.Console):
    rich.print(f"{INDENT*2}- [blue]Issuer[/]: {token['issuer']}")
    rich.print(f"{INDENT*2}  [blue]Type[/]: {token['type']}")
    if len(token["token"]) + 20 < console.width:
        rich.print(f"{INDENT*2}  [blue]Token[/]: {token['token']}")
    else:
        rich.print(f"{INDENT*2}  [blue]Token[/]:")
        txt = wrap(
            token["token"],
            width=console.width - 4,
            initial_indent=INDENT * 3 + "  ",
            subsequent_indent=INDENT * 3 + "  ",
        )
        rich.print("\n".join(txt))


def report(tokens: TokenResults, verbose: bool) -> None:
    console = rich.console.Console()

    td = tokenlist_to_dict(tokens)
    if not td:
        return

    rich.print("[green]Files with embedded secrets:[/]")
    for file, tokens in sorted(td.items()):
        ignored = tokens[0]["ignored"]
        if ignored:
            color = "dim yellow"
            suffix = " (ignored via .gitignore)"
        else:
            color = "yellow"
            suffix = ""

        rich.print(f"{INDENT}[{color}]{file} {suffix}[/]")
        if verbose:
            for token in tokens:
                print_token(token, console)


def json_report(tokens: TokenResults) -> None:
    print(json.dumps(tokens))
