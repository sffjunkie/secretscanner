"""Print scan report"""
import json
from collections import defaultdict
from textwrap import wrap
from typing import Any

import rich
import rich.console

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
    rich.print(f"{INDENT*2}- [blue]Issuer[/]: {secret['issuer']}")
    rich.print(f"{INDENT*2}  [blue]Type[/]: {secret['type']}")
    if len(secret["secret"]) + 20 < console.width:
        rich.print(f"{INDENT*2}  [blue]Secret[/]: {secret['secret']}")
    else:
        rich.print(f"{INDENT*2}  [blue]Secret[/]:")
        txt = wrap(
            secret["secret"],
            width=console.width - 4,
            initial_indent=INDENT * 3 + "  ",
            subsequent_indent=INDENT * 3 + "  ",
        )
        rich.print("\n".join(txt))


def report(secrets: SecretResults, verbose: bool) -> None:
    """Print out report."""
    console = rich.console.Console()

    secret_to_file = secretlist_to_file_dict(secrets)

    rich.print("[green]Files with embedded secrets:[/]")
    for file, secrets_in_file in sorted(secret_to_file.items()):
        ignored = secrets_in_file[0]["ignored"]
        if ignored:
            color = "dim yellow"
            suffix = " (ignored via .gitignore)"
        else:
            color = "yellow"
            suffix = ""

        rich.print(f"{INDENT}[{color}]{file}{suffix}[/]")
        if verbose:
            for secret in secrets_in_file:
                print_secret(secret, console)


def json_report(secrets: SecretResults) -> None:
    """Print out the secrets as a JSON formatted string."""
    print(json.dumps(secrets))
