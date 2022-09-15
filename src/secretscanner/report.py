"""Print scan report"""
import json
from collections import defaultdict
from textwrap import wrap
from typing import Any

import rich
import rich.console

from secretscanner.highlighter import SecretHighlighter
from secretscanner.types import SecretResults, Secret

INDENT = "  "


def secretlist_to_file_dict(secrets: SecretResults) -> dict[str, list[Any]]:
    """Convert the list of secrets to a dict with file name as key."""
    files: dict[str, list[Any]] = defaultdict(list)
    for item in secrets:
        files[item["file"]].append(item)

    return files


def print_secret(secret: Secret, console: rich.console.Console):
    """Print the information on a single secret"""
    highlighter = SecretHighlighter()
    rich.print(f"{INDENT*2}- [blue]Issuer[/]: {secret['issuer']}")
    rich.print(f"{INDENT*2}  [blue]Type[/]: {secret['type']}")
    if len(secret["secret"]) + 20 < console.width:
        secret_text = secret["secret"].strip("\n")
        rich.print(f"{INDENT*2}  [blue]Secret[/]: ", end="")
        rich.print(highlighter(f"{secret_text}"))
    else:
        rich.print(f"{INDENT*2}  [blue]Secret[/]:")
        txt = wrap(
            secret["secret"],
            width=console.width - 4,
            initial_indent=INDENT * 3 + "  ",
            subsequent_indent=INDENT * 3 + "  ",
        )
        rich.print(highlighter("\n".join(txt)))


def report(secrets: SecretResults, verbose: bool) -> None:
    """Print out report."""
    console = rich.console.Console()
    if not secrets:
        rich.print("[green]No secrets found[/]")
        return

    secret_to_file = secretlist_to_file_dict(secrets)

    rich.print("[green]Files with embedded secrets:[/]")
    for file, secrets_in_file in sorted(secret_to_file.items()):
        ignored = secrets_in_file[0]["ignored"]
        if ignored:
            color = "dim blue"
            suffix = " [italic](ignored via .gitignore)[/]"
        else:
            color = "blue"
            suffix = ""

        rich.print(f"{INDENT}[{color}]{file}{suffix}[/]")
        if verbose:
            for secret in secrets_in_file:
                print_secret(secret, console)


def json_report(secrets: SecretResults) -> None:
    """Print out the secrets as a JSON formatted string."""
    if secrets:
    print(json.dumps(secrets))
