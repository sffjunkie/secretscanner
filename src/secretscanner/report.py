import json
from collections import defaultdict
from textwrap import wrap
from typing import Any

import rich
import rich.console

from secretscanner.types import TokenResults, Token

INDENT = "  "


def tokenlist_to_dict(tokens: TokenResults) -> dict[str, list[Any]]:
    """Convert the list of tokens to a dict with file name as key."""
    files: dict[str, list[Any]] = defaultdict(list)
    for item in tokens:
        files[item["file"]].append(item)

    return files


def print_token(token: Token, console: rich.console.Console):
    """Print the information on a single token"""
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
    """Print out report."""
    console = rich.console.Console()

    td = tokenlist_to_dict(tokens)

    rich.print("[green]Files with embedded secrets:[/]")
    for file, tokens in sorted(td.items()):
        ignored = tokens[0]["ignored"]
        if ignored:
            color = "dim yellow"
            suffix = " (ignored via .gitignore)"
        else:
            color = "yellow"
            suffix = ""

        rich.print(f"{INDENT}[{color}]{file}{suffix}[/]")
        if verbose:
            for token in tokens:
                print_token(token, console)


def json_report(tokens: TokenResults) -> None:
    """Print out the tokens as a JSON formatted string."""
    print(json.dumps(tokens))
