"""jadx decompile: DEX to readable Java.

Stage 2 of the pipeline (*reverse engineering*). Like the unpack adapters, it
inventories rather than judges: it decompiles, indexes the classes, and wires
each manifest component to the source file that implements it. Turning code
into ``CryptoUsage`` / ``StorageSink`` entities is pattern matching, and that is
semgrep's job in 1.5: reading *this* source tree. Doing it twice would mean
two sets of rules disagreeing about the same code.

What it contributes:

* ``artifacts/jadx/sources/``: the decompiled tree the code browser renders
  and the SAST stage scans;
* ``artifacts/jadx/classes.json``: the class index the browser's tree is built
  from, kept out of the graph because a large app has tens of thousands of
  classes and none of them are attack surface on their own;
* ``source_path`` on each ``Component`` that was decompiled, which is what makes
  "click a component, land on its code" possible.
"""
from __future__ import annotations

import json
import ntpath
import re
from pathlib import PurePosixPath
from typing import Any

from ..model.enums import EntityType, Platform, Stage
from ..sandbox.runner import (CONTAINER_INPUT, SandboxRunner, SandboxResult,
                              with_limits)
from ..storage.workspace import Workspace, WorkspaceError
from .base import (AnalysisContext, Analyzer, AnalyzerResult, RawResult,
                   Target)

_CLASS_RE = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
_MAX_TEXT = 6000
_MAX_CLASSES = 40000
_MAX_PACKAGES = 4000
#: The index is written by our own worker, but it was produced from a hostile
#: binary, so it is still read with a size ceiling.
_MAX_INDEX_BYTES = 64 * 1024 * 1024


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


class JadxDecompileAnalyzer(Analyzer):
    """Decompile an Android package's DEX to Java with jadx."""

    name = "jadx-decompile"
    display = "jadx · decompile to Java"
    stage = Stage.REVERSE_ENGINEERING
    platforms = (Platform.ANDROID,)
    suffixes = (".apk", ".xapk", ".apkm")
    image = "themob/jadx:1"
    tool = "jadx"
    # Decompilation is the slowest thing in the pipeline and the hungriest.
    timeout = 1800.0
    memory = "4g"
    license_note = ("jadx is Apache-2.0; invoked as a subprocess in a container so "
                    "hostile input never reaches the engine process.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        from ..sandbox.runner import _safe_mount_name

        container_sample = f"{CONTAINER_INPUT}/{_safe_mount_name(target.sample_path.name)}"
        artifact_dir = workspace.artifact_dir("jadx")

        result = sandbox.run(
            self.image,
            [container_sample],
            sample=target.sample_path,
            output_dir=artifact_dir,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory,
                               # Decompiling is CPU-bound and the worker uses up
                               # to four threads; starving it just means a longer
                               # container lifetime holding the same memory.
                               cpus=max(sandbox.limits.cpus, 4.0)),
        )
        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "jadx.json"
            try:
                target_file.write_bytes(result.stdout)
                raw_path = workspace.relative(target_file)
            except OSError:
                raw_path = None

        base = RawResult(
            analyzer=self.name,
            raw_path=raw_path,
            stderr=result.stderr[:_MAX_TEXT],
            exit_code=result.exit_code,
            duration_s=result.duration_s,
        )

        if not result.stdout:
            base.error = result.error or "the worker produced no output"
            return base
        try:
            payload = json.loads(result.stdout.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            base.error = f"worker output was not valid JSON: {exc}"
            return base
        if not isinstance(payload, dict):
            base.error = "worker output was not a JSON object"
            return base

        base.payload = payload
        # A sandbox-level failure (timeout, output flood) is the only thing that
        # outranks the worker's own diagnosis. Otherwise a generic "exited with
        # code 1" replaces a message like "Failed to read zip entry:
        # classes.dex": the one thing a tester actually needs to see.
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "jadx reported a failure"
        elif result.error and not result.ok:
            base.error = result.error
        else:
            base.ok = True
        return base

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        result = AnalyzerResult()
        if not raw.ok or not raw.payload:
            return result

        payload = raw.payload
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        sources = _text(payload.get("sources_dir"), 128) or "sources"
        sources_root = f"artifacts/jadx/{sources}"
        result.artifacts.append(sources_root)

        index_name = _text(payload.get("index_path"), 128)
        index_path = f"artifacts/jadx/{index_name}" if index_name else None
        if index_path:
            result.artifacts.append(index_path)

        stats = _mapping(payload, "stats")
        packages = [
            {"name": _text(p.get("name"), 400) or "",
             "classes": _number(p.get("classes")) or 0}
            for p in (payload.get("packages") or [])[:_MAX_PACKAGES]
            if isinstance(p, dict)
        ]

        result.entities.append(self.entity(
            # jadx decompiles DEX and never reads the manifest, so the App
            # key comes from whatever the unpack stage established.
            EntityType.APP, target.fallback_app_key, target,
            label=target.package or target.name or target.fallback_app_key,
            sources_dir=sources_root,
            class_index=index_path,
            decompiler=_text(payload.get("tool_version"), 64),
            class_count=_number(stats.get("class_count")),
            package_count=_number(stats.get("package_count")),
            source_bytes=_number(stats.get("source_bytes")),
            decompile_errors=_number(stats.get("decompile_errors")),
            # True when jadx could not fully decompile everything, or the index
            # hit its ceiling. The code browser says so rather than implying the
            # tree is complete.
            decompilation_partial=bool(payload.get("partial")),
            top_packages=packages[:200],
        ))
        return result

    # -- post-run wiring -------------------------------------------------------

    def link_components(self, workspace: Workspace, index_path: str,
                        component_keys: list[str]) -> dict[str, str]:
        """Map component class names to their decompiled source paths.

        Called by the code browser and by :mod:`themob.correlate` rather than
        during ``normalize``: it needs the components already in the graph, and
        an adapter has no business querying the database.
        """
        index = read_class_index(workspace, index_path)
        by_fqcn = {entry["fqcn"]: entry["path"] for entry in index}
        return {key: by_fqcn[key] for key in component_keys if key in by_fqcn}


def _contained(path: str) -> bool:
    """Whether a workspace-relative path is structurally safe to keep.

    A string check, not a filesystem one, and deliberately so: the index holds
    tens of thousands of classes and resolving every one costs a syscall per
    class the tester will never open. The authoritative containment check runs
    in ``Workspace.resolve`` at the moment a file is actually read, which is
    where it matters and where symlinks are also caught.
    """
    # String operations, not PurePosixPath: constructing a path object per class
    # over tens of thousands of entries was the bulk of read_class_index. A
    # POSIX-absolute path starts with "/", a Windows drive or UNC root is caught
    # by splitdrive, and a ".." segment is an exact split component. These are
    # the same three rejections the path-object form made, at a fraction of the
    # cost; the authoritative check still runs in Workspace.resolve on read.
    if not path or path.startswith("/"):
        return False
    if ntpath.splitdrive(path)[0]:
        return False
    return ".." not in path.split("/")


def read_class_index(workspace: Workspace, index_path: str) -> list[dict[str, Any]]:
    """Load and validate the class index the worker wrote.

    Our own worker produced it, but from a hostile binary, so every field is
    re-checked and the whole thing is bounded, the same rule as any other tool
    output.
    """
    if not index_path:
        return []
    try:
        resolved = workspace.resolve(index_path)
    except WorkspaceError:
        return []
    if not resolved.is_file() or resolved.stat().st_size > _MAX_INDEX_BYTES:
        return []
    try:
        document = json.loads(resolved.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    if not isinstance(document, dict):
        return []

    # The worker writes every path relative to its own /output mount, which the
    # adapter maps to artifacts/jadx/. The index lives under that same root, so
    # its parent is the prefix the class paths need to become workspace-relative.
    # Without this the index points at sources/... and nothing resolves.
    root = PurePosixPath(index_path).parent

    entries: list[dict[str, Any]] = []
    for item in (document.get("classes") or [])[:_MAX_CLASSES]:
        if not isinstance(item, dict):
            continue
        fqcn = _text(item.get("fqcn"), 512)
        path = _text(item.get("path"), 700)
        if not fqcn or not path or not _CLASS_RE.match(fqcn):
            continue
        # Checked before joining, so a ".." segment cannot climb out of the
        # artifact directory by hiding behind the prefix.
        if not _contained(path):
            continue
        entries.append({
            "fqcn": fqcn,
            "package": _text(item.get("package"), 400) or "",
            "name": _text(item.get("name"), 200) or fqcn.rsplit(".", 1)[-1],
            "path": str(root / path),
            "size": _number(item.get("size")) or 0,
        })
    return entries
