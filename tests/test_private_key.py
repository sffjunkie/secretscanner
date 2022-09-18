from pathlib import Path

from secretscanner import scanner


def test_private_key_count():
    p = Path(__file__).parent / "dir" / "private_key"
    results = scanner.scan(p)

    assert results is not None
    assert len(results["secrets"]) == 1
