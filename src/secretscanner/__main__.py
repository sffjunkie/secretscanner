#!/usr/bin/python3
from pathlib import Path

import click
import rich

from secretscanner.report import json_report, report
from secretscanner.scanner import scan


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
    scan_dir = Path(directory).expanduser()
    if not scan_dir.exists():
        rich.print(f"Directory {directory} not found.")

    tokens = scan(scan_dir)
    if not quiet:
        if not json:
            report(tokens, verbose)
        else:
            json_report(tokens)

    if len(tokens) == 0:
        exit(0)
    else:
        exit(1)


run()
