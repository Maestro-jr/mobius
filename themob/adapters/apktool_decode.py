"""apktool decode: resources and the plain-text manifest.

Stage 1 alongside androguard. Its output is mostly *not* graph nodes: what it
produces is the decoded tree that four later analyzers read,

* the config auditor (1.3) needs a plain-text ``AndroidManifest.xml`` and the
  resolved ``network_security_config``;
* gitleaks and apkleaks (1.4) scan the decoded resources and assets;
* semgrep (1.5) scans them too;
* the endpoint extractor (1.7) mines the string resources and assets.

So this adapter emits artifacts and enriches the ``App`` node; it deliberately
emits **no findings**. "Cleartext is permitted for this domain" is a judgement,
and judgements belong to the auditor that has the whole picture, the same
inventory/judgement split androguard follows.

It upserts the App on the package name from the decoded manifest, so its
attributes merge onto the node androguard already created rather than forking a
second one.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..model.enums import EntityType, Platform, Stage
from ..sandbox.runner import (CONTAINER_INPUT, SandboxRunner, SandboxResult,
                              with_limits)
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, RawResult,
                   Target)

_PACKAGE_RE = re.compile(r"^[A-Za-z_][\w]*(\.[A-Za-z_0-9][\w]*)*$")
_MAX_TEXT = 4096
_MAX_ASSETS = 4000
_MAX_LOCALES = 400
_MAX_DOMAINS = 2000


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (value if isinstance(value, str) else str(value)).strip()
    return text[:limit] or None


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    return None


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


class ApktoolDecodeAnalyzer(Analyzer):
    """Decode an Android package's resources and manifest with apktool."""

    name = "apktool-decode"
    display = "apktool · decode resources"
    stage = Stage.UNPACK
    platforms = (Platform.ANDROID,)
    suffixes = (".apk", ".xapk", ".apkm")
    image = "themob/apktool:1"
    tool = "apktool"
    # apktool spawns a JVM and rewrites every resource; it is the slow half of
    # this stage and needs a longer leash than androguard.
    timeout = 900.0
    license_note = ("apktool is Apache-2.0; invoked as a subprocess in a container "
                    "so hostile input never reaches the engine process.")

    # A JVM rewriting a large resource table needs more than the 2g default.
    memory = "3g"

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        from ..sandbox.runner import _safe_mount_name

        container_sample = f"{CONTAINER_INPUT}/{_safe_mount_name(target.sample_path.name)}"
        # The decoded tree is an artifact, not raw tool output, so it is written
        # straight into artifacts/apktool/ rather than under raw/.
        artifact_dir = workspace.artifact_dir("apktool")

        result = sandbox.run(
            self.image,
            [container_sample],
            sample=target.sample_path,
            output_dir=artifact_dir,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
        )
        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "apktool.json"
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
            base.error = _text(payload.get("error")) or "apktool reported a failure"
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

        decoded = _text(payload.get("decoded_dir"), 128)
        artifact_root = f"artifacts/apktool/{decoded}" if decoded else "artifacts/apktool"
        result.artifacts.append(artifact_root)

        meta = _mapping(payload, "meta")
        inventory = _mapping(payload, "inventory")
        resources = _mapping(payload, "resources")

        package = _text(payload.get("package"), 255)
        if package and not _PACKAGE_RE.match(package):
            package = None
        key = package or target.fallback_app_key

        manifest = _text(payload.get("manifest_path"), 512)
        assets = [a for a in (payload.get("assets") or [])
                  if isinstance(a, str)][:_MAX_ASSETS]
        locales = [locale for locale in (resources.get("locales") or [])
                   if isinstance(locale, str)][:_MAX_LOCALES]

        result.entities.append(self.entity(
            EntityType.APP, key, target,
            label=package or target.name or key,
            package=package,
            # Where the decoded tree lives, so later stages and the UI can find
            # it without re-deriving the path.
            decoded_dir=artifact_root,
            # The worker reports paths relative to its /output mount, which is
            # this project's artifacts/apktool/ directory.
            decoded_manifest=f"artifacts/apktool/{manifest}" if manifest else None,
            manifest_decoded=bool(payload.get("manifest_parsed")),
            apktool_version=_text(payload.get("tool_version"), 64),
            apktool_meta_version=_text(meta.get("apktool_version"), 64),
            is_framework_apk=_flag(meta.get("is_framework_apk")),
            shared_library=_flag(meta.get("shared_library")),
            sparse_resources=_flag(meta.get("sparse_resources")),
            do_not_compress=[_text(x, 128) for x in (meta.get("do_not_compress") or [])
                             if isinstance(x, str)][:200],
            decoded_file_count=_number(inventory.get("file_count")),
            decoded_bytes=_number(inventory.get("decoded_bytes")),
            resource_directories=(resources.get("directories")
                                  if isinstance(resources.get("directories"), dict)
                                  else {}),
            locales=locales,
            locale_count=_number(resources.get("locale_count")),
            assets=assets,
            asset_count=len(assets),
            network_security_config=self._network_security_config(payload),
        ))
        return result

    @staticmethod
    def _network_security_config(payload: dict[str, Any]) -> dict[str, Any] | None:
        """The declared network policy, recorded verbatim for the auditor.

        No judgement here: this records *what the app declares*. Whether
        permitting cleartext for a domain is a finding depends on which domain,
        and that is stage 6's call.
        """
        raw = payload.get("network_security_config")
        if not isinstance(raw, dict):
            return None
        if raw.get("unresolved"):
            return {"reference": _text(raw.get("reference"), 255), "unresolved": True}

        configs: list[dict[str, Any]] = []
        for entry in (raw.get("configs") or [])[:500]:
            if not isinstance(entry, dict):
                continue
            domains = [d for d in (entry.get("domains") or [])
                       if isinstance(d, str)][:_MAX_DOMAINS]
            pins = [p for p in (entry.get("pins") or []) if isinstance(p, str)][:2000]
            configs.append({
                "scope": _text(entry.get("scope"), 32),
                "domains": [d[:255] for d in domains],
                "cleartext_permitted": _flag(entry.get("cleartext_permitted")),
                "pin_count": len(pins),
                "trust_anchors": [t for t in (entry.get("trust_anchors") or [])
                                  if isinstance(t, str)][:64],
            })
        return {
            "path": _text(raw.get("path"), 512),
            "configs": configs,
            "parse_error": _text(raw.get("parse_error"), 300),
        }
