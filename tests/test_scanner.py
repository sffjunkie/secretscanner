from pathlib import Path

from secretscanner import __version__, scanner


def test_version():
    assert __version__ == "0.1.1"


def test_pypi_count():
    p = Path(__file__).parent / "dir" / "pypi"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 1


def test_github_count():
    p = Path(__file__).parent / "dir" / "github"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 5


def test_digitalocean_count():
    p = Path(__file__).parent / "dir" / "digitalocean"
    results = scanner.scan(p)
    assert results is not None
    assert len(results["secrets"]) == 3


def test_postgresql_count():
    p = Path(__file__).parent / "dir" / "postgresql"
    results = scanner.scan(p)
    assert results is not None
    assert len(results["secrets"]) == 1


def test_adafruit_count():
    p = Path(__file__).parent / "dir" / "adafruit"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 3


def test_discord_count():
    p = Path(__file__).parent / "dir" / "discord"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 2


def test_linode_count():
    p = Path(__file__).parent / "dir" / "linode"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 3


def test_password_count():
    p = Path(__file__).parent / "dir" / "password"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 1


def test_all_count():
    p = Path(__file__).parent / "dir"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 19


def test_pypi_info():
    p = Path(__file__).parent / "dir" / "pypi"
    results = scanner.scan(p)

    assert results is not None
    assert results["secrets"][0]["issuer"] == "pypi"
    assert results["secrets"][0]["type"] == "pat"
