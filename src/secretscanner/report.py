import json
from collections import defaultdict
from pathlib import Path
from textwrap import wrap
from typing import Any

import rich
import rich.console

from secretscanner.gitignore import gitignored
from secretscanner.types import TokenResults


def tokenlist_to_dict(tokens: TokenResults) -> dict[str, list[Any]]:
    files: dict[str, list[Any]] = defaultdict(list)
    for item in tokens:
        files[item["file"]].append(item)

    return files


def set_ignored(tokens: TokenResults, directory: Path):
    td = tokenlist_to_dict(tokens)
    files = list(td.keys())
    if td:
        ignored = gitignored(files, directory)
        rich.print("[green]Files with embedded secrets:[/]")
        for file, tokens in sorted(td.items()):
            for token in tokens:
                if file in ignored[0]:
                    token["ignored"] = True
                else:
                    token["ignored"] = False


def report(tokens: TokenResults, verbose: bool) -> None:
    console = rich.console.Console()
    indent = "  "

    td = tokenlist_to_dict(tokens)
    if td:
        rich.print("[green]Files with embedded secrets:[/]")
        for file, tokens in sorted(td.items()):
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


def json_report(tokens: TokenResults) -> None:
    print(json.dumps(tokens))
