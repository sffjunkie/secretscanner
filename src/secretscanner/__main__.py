#!/usr/bin/python3
from pathlib import Path

import click
import rich

from secretscanner import json_report, scan, report


@click.command()
@click.argument("directory", type=click.Path())
@click.option(
    "-v",
    "--verbose",
    default=False,
    is_flag=True,
    help="If set includes information on the tokens in the report.",
)
@click.option(
    "-q", "--quiet", default=False, is_flag=True, help="If set no output is printed."
)
@click.option(
    "-j",
    "--json",
    default=False,
    is_flag=True,
    help="If set the report is output as json.",
)
def run(directory: str, verbose: bool, quiet: bool, json: bool):
    """Scan a directory for secrets."""
    walk_me = Path(directory).expanduser()
    if not walk_me.exists():
        rich.print(f"Directory {str(walk_me)} not found.")

    found_tokens = scan(walk_me)
    if not quiet:
        if not json:
            report(found_tokens, verbose)
        else:
            json_report(found_tokens)

    if len(found_tokens) == 0:
        exit(0)
    else:
        exit(1)


run()
