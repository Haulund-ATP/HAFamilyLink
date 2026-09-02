"""Shared test fixtures.

Two things have to happen before any test module is imported:

* ``SHARE_DIR`` must point somewhere writable. ``app/main.py`` builds its
  application at import time on purpose - a token that cannot be established
  has to stop the process - so importing it with the default ``/share`` path
  would fail on a developer machine.
* the repository root and the add-on directory must be importable, so
  ``import app...`` and ``import custom_components.familylink...`` both work
  without installing anything.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDON_ROOT = REPO_ROOT / "familylink-playwright"

for path in (str(REPO_ROOT), str(ADDON_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

# Import-time side effect, deliberately: see the module docstring.
_IMPORT_SHARE_DIR = tempfile.mkdtemp(prefix="familylink-import-")
os.environ.setdefault("SHARE_DIR", _IMPORT_SHARE_DIR)

import pytest  # noqa: E402


@pytest.fixture
def share_dir(tmp_path: Path) -> Path:
    """An empty, writable stand-in for /share/familylink."""
    directory = tmp_path / "familylink"
    directory.mkdir()
    return directory
