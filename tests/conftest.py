import os
import sys

import pytest

# Make the project root importable so `import main` works under pytest.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _fast_kdf_everywhere(monkeypatch):
    """Lower Argon2 cost for every database created during tests (fixtures + merge output)."""
    import main
    from kdbx_factory import _fast_kdf

    original = main.create_database

    def wrapped(*args, **kwargs):
        kp = original(*args, **kwargs)
        _fast_kdf(kp)
        return kp

    monkeypatch.setattr(main, "create_database", wrapped)
