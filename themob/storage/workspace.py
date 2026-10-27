"""Per-project filesystem workspace for artifacts.

The database holds structured results; everything bulky (the uploaded binary,
raw tool output, decompiled sources, extracted resources) lives on disk under a
project workspace. Findings reference artifacts by a *workspace-relative* path,
never an absolute one, so a project directory stays portable.

Layout::

    <root>/projects/<project_id>/
        input/        the uploaded binary (chmod read-only after ingest)
        raw/<analyzer>/   raw tool output, exactly as the tool emitted it
        artifacts/<name>/ decoded/decompiled trees produced by an analyzer
        evidence/     snippets and files attached to findings

Security note: paths that come back from an analyzer are untrusted. Anything
resolved through :meth:`Workspace.resolve` is checked to be inside the project
directory, so a tool emitting ``../../etc/passwd`` cannot make the UI read it.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

# Analyzer/artifact names become directory names, keep them boring.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_HASH_CHUNK = 1024 * 1024


class WorkspaceError(RuntimeError):
    """The workspace was asked to do something unsafe or impossible."""


def sha256_file(path: str | Path) -> str:
    """Streaming SHA-256 of a file (inputs can be hundreds of megabytes)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(name: str, what: str) -> str:
    if not _SAFE_NAME_RE.match(name or ""):
        raise WorkspaceError(f"unsafe {what} name: {name!r}")
    return name


@dataclass(frozen=True)
class IngestedInput:
    """The result of copying an uploaded binary into a workspace."""
    path: Path              # absolute path to the stored copy
    relative: str           # workspace-relative path, for the DB
    sha256: str
    size: int
    original_name: str


class Workspace:
    """The artifact directory for one project."""

    def __init__(self, root: str | Path, project_id: str) -> None:
        self.project_id = _safe_name(project_id, "project id")
        self.root = Path(root).expanduser().resolve()
        self.path = self.root / "projects" / self.project_id

    # ------------------------------------------------------------------ layout

    @property
    def input_dir(self) -> Path:
        return self.path / "input"

    @property
    def raw_root(self) -> Path:
        return self.path / "raw"

    @property
    def artifacts_root(self) -> Path:
        return self.path / "artifacts"

    @property
    def evidence_dir(self) -> Path:
        return self.path / "evidence"

    @property
    def reports_dir(self) -> Path:
        """Where exports land by default.

        Inside the project rather than beside the app, so a report sits next to
        the evidence it cites and one deletion removes both.
        """
        return self.path / "reports"

    def create(self) -> "Workspace":
        for directory in (self.input_dir, self.raw_root, self.artifacts_root,
                          self.evidence_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def raw_dir(self, analyzer: str) -> Path:
        directory = self.raw_root / _safe_name(analyzer, "analyzer")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def artifact_dir(self, name: str) -> Path:
        directory = self.artifacts_root / _safe_name(name, "artifact")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    # ------------------------------------------------------------------ ingest

    def ingest(self, source: str | Path) -> IngestedInput:
        """Copy an uploaded binary into ``input/`` and hash it.

        The stored copy is made read-only: nothing downstream should ever mutate
        the sample, and the sandbox mounts it read-only as well.
        """
        src = Path(source).expanduser()
        if not src.is_file():
            raise WorkspaceError(f"input is not a file: {src}")
        size = src.stat().st_size
        if size == 0:
            raise WorkspaceError(f"input file is empty: {src}")

        self.create()
        # Never trust the uploaded filename for a path component.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)[:120] or "sample"
        dest = self.input_dir / safe
        shutil.copy2(src, dest)
        try:
            dest.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:                 # best effort; Windows ACLs may refuse
            pass

        return IngestedInput(
            path=dest,
            relative=self.relative(dest),
            sha256=sha256_file(dest),
            size=size,
            original_name=src.name,
        )

    def stored_input(self) -> Path | None:
        """The ingested binary, if this workspace has one."""
        if not self.input_dir.is_dir():
            return None
        for entry in sorted(self.input_dir.iterdir()):
            if entry.is_file():
                return entry
        return None

    # ------------------------------------------------------------------- paths

    def relative(self, path: str | Path) -> str:
        """Workspace-relative POSIX path for *path* (for storage in the DB)."""
        resolved = Path(path).resolve()
        try:
            return resolved.relative_to(self.path).as_posix()
        except ValueError as exc:
            raise WorkspaceError(
                f"path is outside the project workspace: {resolved}") from exc

    def resolve(self, relative: str) -> Path:
        """Absolute path for a stored workspace-relative path.

        Rejects absolute paths and anything that escapes the project directory,
        the stored value may have originated in untrusted tool output.
        """
        if not relative:
            raise WorkspaceError("empty workspace path")
        candidate = Path(relative)
        if candidate.is_absolute() or (os.name == "nt" and candidate.drive):
            raise WorkspaceError(f"absolute workspace path rejected: {relative}")
        resolved = (self.path / candidate).resolve()
        if resolved != self.path and self.path not in resolved.parents:
            raise WorkspaceError(f"workspace path escapes the project: {relative}")
        return resolved

    # ---------------------------------------------------------------- teardown

    def size_bytes(self) -> int:
        total = 0
        for dirpath, _dirnames, filenames in os.walk(self.path):
            for name in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    continue
        return total

    def delete(self) -> None:
        """Remove the whole project workspace (input files are read-only)."""
        def _force(func, path, _exc):        # read-only files need the write bit
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except OSError:
                pass

        if self.path.exists():
            shutil.rmtree(self.path, onerror=_force)


def default_root() -> Path:
    """Where projects live unless the caller says otherwise."""
    env = os.environ.get("THEMOB_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".themob"
