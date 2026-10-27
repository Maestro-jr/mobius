"""The REA handoff: deep reverse engineering, at arm's length.

themob measures native libraries (nativelib reads their ELF hardening) and
decompiles Java, but it does not reverse the logic inside a native binary or an
obfuscated class. REA (github.com/morluto/rea) does, with LLM agents. That is a
non-deterministic, network-reaching act, so it does not belong inside themob's
contained, reproducible pipeline. It belongs beside it, operator-driven, the way
the TOPRECON handoff and the dynamic panel already work: themob prepares, the
operator runs the external tool with their own keys, themob imports the result.

So this module never imports ``rea-agents`` and never reaches the network. It
has two halves:

* :func:`prepare` resolves a chosen target (a native library, or a decompiled
  class) to its file in the project workspace, copies it into a handoff bundle
  with the context themob already has, and returns the exact ``rea`` command to
  run. The operator runs it.
* :func:`import_summary` takes what REA reported back and attaches it as a note
  on a finding, marked as external reverse-engineering evidence, not a
  themob-derived finding. It changes no severity, confidence or status.

Both are gated: the project must carry an authorization attestation, and both
append to the hash-chained audit trail, so what was sent out and what came back
are on the record like every other step.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .audit.attestation import (Action, AuditTrail, AuthorizationError,
                                current_operator, require_authorization)
from .correlate.graph import build_snapshot
from .model.enums import EntityType
from .storage.db import open_database
from .storage.repositories import Repositories
from .storage.workspace import Workspace, WorkspaceError, default_root

logger = logging.getLogger(__name__)

FORMAT = "themob.rea-handoff/1"
_MAX_SUMMARY = 20000          # a note is evidence, not a second report


def _resolve_home(home) -> Path:
    return Path(home).expanduser() if home else default_root()


@contextmanager
def _session(home) -> Iterator[tuple[Repositories, AuditTrail]]:
    database = open_database(_resolve_home(home) / "themob.db")
    try:
        repos = Repositories(database)
        yield repos, AuditTrail(repos.audit)
    finally:
        database.close_all()


def _resolve_project(repos: Repositories, token: str):
    projects = repos.projects.list(limit=500)
    if not projects:
        return None, "no projects yet. Authorize and analyze a sample first"
    if not token:
        return projects[0], ""
    for project in projects:
        if project.id == token:
            return project, ""
    prefix = [p for p in projects if p.id.startswith(token)]
    named = [p for p in projects if p.name == token]
    if len(prefix) == 1 and not named:
        return prefix[0], ""
    if len(named) == 1 and not prefix:
        return named[0], ""
    if len(prefix) + len(named) > 1:
        return None, f"{token!r} matches more than one project; use a longer id prefix"
    if named:
        return named[0], ""
    return None, f"no project matches {token!r}"


def _find_native_lib(workspace: Workspace, key: str) -> Path | None:
    """The native binary on disk for a NATIVE_LIB whose key is its in-package path.

    On Android the key is the canonical ``lib/<abi>/<name>.so`` and apktool wrote
    the decoded tree under an output directory; on iOS it is the Mach-O's bundle
    path (``Payload/<app>.app/<exe>``) and ios-unpack decoded the bundle under
    ``artifacts/ios``. Either way the file sits deeper than the key alone, so this
    prefers an exact path-suffix match and falls back to the basename. This is
    exactly the native-binary case REA exists for.
    """
    root = workspace.artifacts_root
    if not root.is_dir():
        return None
    wanted = key.replace("\\", "/").lstrip("/")
    basename = wanted.rsplit("/", 1)[-1]
    fallback: Path | None = None
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = Path(dirpath) / name
            if full.as_posix().endswith(wanted):
                return full
            if name == basename and fallback is None:
                fallback = full
    return fallback


def _class_file(workspace: Workspace, snapshot, fqcn: str) -> tuple[Path | None, str]:
    """The decompiled ``.java`` for a class, resolved safely in the workspace."""
    from .adapters.jadx_decompile import read_class_index

    app = snapshot.root
    index_path = app.attributes.get("class_index") if app else None
    if not index_path:
        return None, "no decompiled sources yet. Run analyze so jadx runs"
    index = read_class_index(workspace, str(index_path))
    entry = next((e for e in index if e["fqcn"] == fqcn), None)
    if entry is None:
        match = [e for e in index if fqcn in e["fqcn"]]
        entry = match[0] if len(match) == 1 else None
    if entry is None:
        return None, f"no class matching {fqcn!r}"
    try:
        return workspace.resolve(entry["path"]), entry["fqcn"]
    except WorkspaceError as exc:
        return None, f"the class path is unsafe: {exc}"


def _findings_on(repos: Repositories, project_id: str, entity_id: str) -> list[dict]:
    return [{
        "fingerprint": f.fingerprint,
        "title": f.title,
        "severity": f.severity.value,
        "weakness_key": f.weakness_key,
    } for f in repos.findings.list(project_id)
        if entity_id in (f.entity_ids or [])]


def prepare(home=None, project: str = "", kind: str = "", target: str = "",
            out: str = "rea-handoff") -> dict:
    """Assemble a handoff bundle for one target and return the rea command.

    ``kind`` is ``"native"`` (a native library, by its key or entity id) or
    ``"class"`` (a decompiled class, by its fully-qualified name). The project
    must be authorized. Nothing is sent anywhere: the operator runs the returned
    command themselves, with their own REA setup and keys.
    """
    if kind not in ("native", "class"):
        return {"error": "kind must be 'native' or 'class'"}
    if not target:
        return {"error": "a target is required (a native library key/id, or a "
                         "class fully-qualified name)"}

    with _session(home) as (repos, audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        try:
            require_authorization(proj)
        except AuthorizationError as exc:
            return {"error": f"{exc}"}

        workspace = Workspace(_resolve_home(home), proj.id)
        snapshot = build_snapshot(repos, proj.id)

        entity = None
        if kind == "native":
            entity = snapshot.get(target) or next(
                (e for e in snapshot.of_type(EntityType.NATIVE_LIB)
                 if e.key == target), None)
            if entity is None:
                return {"error": f"no native library {target!r} in this project"}
            source = _find_native_lib(workspace, entity.key)
            if source is None:
                return {"error": "the native library file is not in the "
                                 "workspace. Run analyze so the unpack stage "
                                 "extracts it, then retry."}
            label = entity.key
        else:
            source, resolved = _class_file(workspace, snapshot, target)
            if source is None:
                return {"error": resolved}
            label = resolved
            entity = next((e for e in snapshot.of_type(EntityType.COMPONENT)
                           if e.key == resolved), None)

        try:
            bundle = Path(out).expanduser()
            bundle.mkdir(parents=True, exist_ok=True)
            dest = bundle / source.name
            shutil.copy2(source, dest)
        except OSError as exc:
            return {"error": f"could not write the handoff bundle: {exc}"}

        app = snapshot.root
        context = {
            "format": FORMAT,
            "project_id": proj.id,
            "app": {"package": (app.attributes.get("package") or app.key)
                    if app else None},
            "target": {"kind": kind, "name": label,
                       "entity_id": entity.id if entity else None,
                       "attributes": dict(entity.attributes) if entity else {}},
            "known_findings": _findings_on(repos, proj.id, entity.id)
            if entity else [],
            "note": ("themob prepared this bundle. Run REA against the file below "
                     "with your own setup and keys; themob does not run it and "
                     "does not reach the network. Import REA's summary back with "
                     "'themob rea import'."),
        }
        try:
            (bundle / "context.json").write_text(
                json.dumps(context, indent=2, default=str), encoding="utf-8")
        except OSError as exc:
            return {"error": f"could not write the context file: {exc}"}

        command = f'rea "{dest}"'
        audit.record(Action.REA_PREPARED, project_id=proj.id,
                     actor=current_operator(), kind=kind, target=label,
                     bundle=str(bundle))
        return {
            "project": proj.id,
            "kind": kind,
            "target": label,
            "file": str(dest),
            "bundle_dir": str(bundle),
            "command": command,
            "context": context,
        }


def import_summary(home=None, project: str = "", fingerprint: str = "",
                   summary: str = "", operator: str = "",
                   source: str = "rea") -> dict:
    """Attach REA's result as external reverse-engineering evidence on a finding.

    Recorded as a note prefixed with its provenance, so it reads as an outside
    agent's observation rather than a themob-derived finding, and audited. It
    changes no severity, confidence or status. The project must be authorized.
    """
    text = (summary or "").strip()
    if not fingerprint:
        return {"error": "a finding fingerprint is required"}
    if not text:
        return {"error": "nothing to import: provide REA's summary"}

    who = operator.strip() or current_operator()
    with _session(home) as (repos, audit):
        proj, error = _resolve_project(repos, project)
        if proj is None:
            return {"error": error}
        try:
            require_authorization(proj)
        except AuthorizationError as exc:
            return {"error": f"{exc}"}

        finding = repos.findings.get_by_fingerprint(proj.id, fingerprint)
        if finding is None:
            match = [f for f in repos.findings.list(proj.id, limit=100000)
                     if f.fingerprint.startswith(fingerprint)]
            finding = match[0] if len(match) == 1 else None
        if finding is None:
            return {"error": f"no finding {fingerprint!r} in this project"}

        note_text = f"[external: {source}] {text[:_MAX_SUMMARY]}"
        repos.findings.add_note(finding.id, note_text, who)
        audit.record(Action.REA_IMPORTED, project_id=proj.id, actor=who,
                     finding=finding.id, fingerprint=finding.fingerprint,
                     source=source, chars=len(text))
        return {"project": proj.id, "fingerprint": finding.fingerprint,
                "title": finding.title, "source": source, "note_added": True}
