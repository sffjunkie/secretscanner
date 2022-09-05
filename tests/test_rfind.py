from pathlib import Path

from secretscanner.gitignore import rfindfile


def test_rfind():
    p = Path(__file__).parent.parent / ".gitignore"

    assert rfindfile(".gitignore") == p


def test_rfind_directory():
    p = Path(__file__).parent.parent / ".gitignore"

    assert rfindfile(".gitignore", Path.cwd()) == p
