from secretscanner.types import TokenResults
from pathlib import Path
import pathspec
from typing import Iterable


def rfindfile(filename: str, path: Path | None = None) -> Path | None:
    """Scan for a filename moving up the directory tree"""
    if path is None:
        path = Path.cwd()

    while True:
        files = [p.name for p in path.glob("*")]
        if filename in files:
            return path / filename
        else:
            if path.parent == path:
                return None
            else:
                return rfindfile(filename, path.parent)


def gitignore_pathspec(gitignore: Path) -> pathspec.PathSpec:
    """Get a pathspec for the `.gitignore` file"""
    with open(gitignore, "r") as gifp:
        gidata = gifp.readlines()
        spec = pathspec.PathSpec.from_lines(  # type: ignore
            pathspec.patterns.GitWildMatchPattern, gidata
        )
        return spec  # type: ignore


def gitignored(
    files: Iterable[str], directory: Path
) -> tuple[Iterable[str], Iterable[str]]:
    """Determine whether files are ignored by `.gitignore` or not"""
    gi = rfindfile(".gitignore", directory)
    if gi is not None:
        gispec = gitignore_pathspec(gi)
        ignored: list[str] = []
        notignored: list[str] = []
        for file in files:
            if gispec.match_file(file):  # type: ignore
                ignored.append(file)
            else:
                notignored.append(file)
        return ignored, notignored
    else:
        return files, []


def set_ignored_flag(tokens: TokenResults, directory: Path):
    files = {t["file"] for t in tokens}
    if not files:
        return

    ignored, notignored = gitignored(files, directory)
    for token in tokens:
        if token["file"] in ignored and token["file"] not in notignored:
            token["ignored"] = True
        else:
            token["ignored"] = False
