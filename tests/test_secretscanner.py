from pathlib import Path

from secretscanner import __version__, scan


def test_version():
    assert __version__ == "0.1.0"


def test_pypi_count():
    p = Path(__file__).parent / "dir" / "pypi"
    results = scan(p)

    assert len(results) == 1


def test_github_count():
    p = Path(__file__).parent / "dir" / "github"
    results = scan(p)

    assert len(results) == 5


def test_digitalocean_count():
    p = Path(__file__).parent / "dir" / "digitalocean"
    results = scan(p)

    assert len(results) == 3


def test_all_count():
    p = Path(__file__).parent / "dir"
    results = scan(p)

    assert len(results) == 9


def test_pypi_info():
    p = Path(__file__).parent / "dir" / "pypi"
    results = scan(p)

    assert results[0]["issuer"] == "pypi"
    assert results[0]["type"] == "pat"
