"""Stage 0: intake.

Takes a file the operator picked, decides whether themob will touch it at all,
copies it into a project workspace, and creates the project record. It does
*not* authorize the project: that is the gate's job, and until the gate runs,
:func:`require_authorization` refuses every analyzer.

The checks here are the cheap, structural ones that can be done without parsing:
magic bytes, size, extension. Anything that requires actually interpreting the
container happens later, in a sandbox.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..adapters.base import Target
from ..audit.attestation import Action, AuditTrail, current_operator
from ..model.enums import Platform
from ..storage.repositories import Project, Repositories
from ..storage.workspace import Workspace, default_root

# 4 GiB. Above this we are being fed something that is not a mobile app.
MAX_SAMPLE_BYTES = 4 * 1024 * 1024 * 1024
# Zip local-file-header magic. APK, XAPK and IPA are all zip containers.
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_ANDROID_SUFFIXES = {".apk", ".xapk", ".apkm"}
_IOS_SUFFIXES = {".ipa"}


class IntakeError(ValueError):
    """The file cannot be accepted as an analysis target."""


@dataclass
class IntakeResult:
    """A project ready for the authorization gate."""
    project: Project
    workspace: Workspace
    target: Target

    @property
    def sha256(self) -> str:
        return self.project.source_sha256


def detect_platform(path: Path) -> Platform:
    """Android or iOS, from the extension then the container layout."""
    suffix = path.suffix.lower()
    if suffix in _ANDROID_SUFFIXES:
        return Platform.ANDROID
    if suffix in _IOS_SUFFIXES:
        return Platform.IOS
    # Unknown extension: peek at the central directory (names only. No parsing
    # of member contents, and a bad zip raises rather than being trusted).
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()[:2000]
    except (zipfile.BadZipFile, OSError) as exc:
        raise IntakeError(f"not a readable app package: {exc}") from exc
    if any(n == "AndroidManifest.xml" or n.startswith("classes") for n in names):
        return Platform.ANDROID
    if any(n.startswith("Payload/") for n in names):
        return Platform.IOS
    raise IntakeError(
        "could not identify the package: expected an Android APK/XAPK or an iOS IPA")


def validate_sample(path: Path) -> Path:
    """Structural checks that need no interpretation of the file's contents."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise IntakeError(f"file not found: {resolved}")
    size = resolved.stat().st_size
    if size == 0:
        raise IntakeError("file is empty")
    if size > MAX_SAMPLE_BYTES:
        raise IntakeError(
            f"file is {size / 1024 ** 3:.1f} GiB, above the {MAX_SAMPLE_BYTES // 1024 ** 3} GiB intake limit")
    with open(resolved, "rb") as handle:
        magic = handle.read(4)
    if not any(magic.startswith(m) for m in _ZIP_MAGIC):
        raise IntakeError(
            "file is not a zip container: APK, XAPK and IPA packages all are")
    return resolved


def intake(source: str | Path, repos: Repositories, audit: AuditTrail, *,
           name: str = "", root: Path | None = None,
           platform: Platform | None = None) -> IntakeResult:
    """Accept a sample and create its project. The project is not yet authorized."""
    path = validate_sample(Path(source))
    resolved_platform = platform or detect_platform(path)

    project = Project(
        name=(name.strip() or path.stem)[:200],
        target_platform=resolved_platform,
        source_sha256="",           # filled in after the copy is hashed
        source_path="",
    )
    workspace = Workspace(root or default_root(), project.id).create()
    try:
        ingested = workspace.ingest(path)
    except Exception:
        workspace.delete()          # never leave a half-made project on disk
        raise

    project.source_sha256 = ingested.sha256
    project.source_path = ingested.relative
    try:
        repos.projects.create(project)
    except Exception:
        workspace.delete()
        raise

    audit.record(Action.PROJECT_CREATED, project_id=project.id,
                 target_sha256=project.source_sha256, actor=current_operator(),
                 original_name=ingested.original_name, size=ingested.size,
                 platform=resolved_platform.value)

    return IntakeResult(
        project=project,
        workspace=workspace,
        target=Target(project_id=project.id, platform=resolved_platform,
                      sample_path=ingested.path, sha256=ingested.sha256,
                      name=ingested.original_name),
    )


def target_for(project: Project, workspace: Workspace) -> Target:
    """Rebuild the :class:`Target` for an existing project (re-runs, reopen)."""
    sample = workspace.stored_input()
    if sample is None:
        raise IntakeError(
            f"project {project.name!r} has no sample in its workspace. "
            "the workspace may have been moved or deleted")
    return Target(project_id=project.id, platform=project.target_platform,
                  sample_path=sample, sha256=project.source_sha256,
                  name=sample.name)
