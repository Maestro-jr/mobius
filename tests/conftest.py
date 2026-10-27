"""Shared pytest fixtures.

Every test gets its own SQLite file and workspace under ``tmp_path`` so nothing
leaks between tests and no test can touch a real project.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow `import themob` when the package is not pip-installed.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from themob.storage.db import Database, open_database          # noqa: E402
from themob.storage.repositories import Repositories           # noqa: E402
from themob.storage.workspace import Workspace                 # noqa: E402


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = open_database(tmp_path / "themob.db")
    yield database
    database.close_all()


@pytest.fixture()
def repos(db: Database) -> Repositories:
    return Repositories(db)


@pytest.fixture()
def workspace(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path / "home", "proj0001").create()


@pytest.fixture()
def sample_apk(tmp_path: Path) -> Path:
    """A minimal but *real* zip that looks enough like an APK for intake tests."""
    import zipfile

    path = tmp_path / "sample.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary-manifest")
        zf.writestr("classes.dex", b"dex\n035\x00")
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return path
