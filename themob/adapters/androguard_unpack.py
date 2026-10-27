"""androguard unpack: the first adapter, and the shape every other one follows.

Stage 1 of the pipeline (*unpack & inventory*): it reads the manifest, signing
block and file inventory and turns them into the graph's founding entities,
the App, its Components, Permissions, DeepLinks and NativeLibs, wired together
with typed edges.

It deliberately emits **no findings**. "Debuggable is on", "allowBackup is on",
"this Provider is exported" are conclusions, and conclusions belong to the
config auditor (stage 6), which reads these entities. Keeping inventory and
judgement in separate stages is what lets a finding cite an entity instead of
re-parsing the manifest.

Everything below ``_normalize`` treats the worker's JSON as untrusted: it was
produced by a parser that just chewed on a hostile file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..model.entities import Entity
from ..model.enums import ComponentKind, EdgeType, EntityType, Platform, Stage
from ..sandbox.runner import (CONTAINER_INPUT, SandboxRunner, SandboxResult,
                              with_limits)
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

# A Java/Kotlin fully-qualified class name. Anything else in a component's
# android:name is malformed: a real manifest cannot produce it.
_CLASS_RE = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
# Android permission names are dotted identifiers too, but vendors are creative,
# so this is deliberately looser than _CLASS_RE.
_PERMISSION_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z_][\w]*(\.[A-Za-z_0-9][\w]*)*$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]{0,63}$")

# Upper bounds mirroring the worker's own caps. Belt and braces: the worker is
# in the sandbox, but the engine still refuses to be flooded by it.
_MAX_COMPONENTS = 5000
_MAX_PERMISSIONS = 2000
_MAX_DEEP_LINKS = 2000
_MAX_NATIVE_LIBS = 2000
_MAX_TEXT = 4096

_KIND_MAP = {
    "activity": ComponentKind.ACTIVITY,
    "service": ComponentKind.SERVICE,
    "receiver": ComponentKind.RECEIVER,
    "provider": ComponentKind.PROVIDER,
}


# --------------------------------------------------------------------- coercion

def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    """A bounded string, or None. Never raises on odd input."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
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


def _items(payload: dict[str, Any], key: str, cap: int) -> list[dict[str, Any]]:
    """A bounded list of dicts from an untrusted document."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [item for item in raw[:cap] if isinstance(item, dict)]


def _qualify(name: str, package: str) -> str:
    """Resolve a manifest class name, which may be relative to the package."""
    if name.startswith("."):
        return f"{package}{name}" if package else name.lstrip(".")
    if "." not in name and package:
        return f"{package}.{name}"
    return name


# ---------------------------------------------------------------------- adapter

class AndroguardUnpackAnalyzer(Analyzer):
    """Manifest, signing block and file inventory of an Android package."""

    name = "androguard-unpack"
    display = "androguard · unpack & inventory"
    stage = Stage.UNPACK
    platforms = (Platform.ANDROID,)
    suffixes = (".apk", ".xapk", ".apkm")
    image = "themob/androguard:1"
    tool = "androguard"
    timeout = 300.0
    license_note = ("androguard is Apache-2.0; still invoked as a subprocess in a "
                    "container so hostile input never reaches the engine process.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        raw_dir = workspace.raw_dir(self.name)
        container_sample = f"{CONTAINER_INPUT}/{_container_name(target.sample_path)}"

        result = sandbox.run(
            self.image,
            [container_sample],
            sample=target.sample_path,
            output_dir=raw_dir,
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
        )
        return self._to_raw_result(result, workspace, raw_dir)

    def _to_raw_result(self, result: SandboxResult, workspace: Workspace,
                       raw_dir: Path) -> RawResult:
        """Persist the tool's output verbatim, then try to parse it."""
        raw_path: str | None = None
        if result.stdout:
            target_file = raw_dir / "androguard.json"
            try:
                target_file.write_bytes(result.stdout)
                raw_path = workspace.relative(target_file)
            except OSError:            # provenance is nice to have, not required
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
            base.error = _text(payload.get("error")) or "androguard reported a failure"
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
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        payload = raw.payload
        app_doc = payload.get("app") if isinstance(payload.get("app"), dict) else {}

        app = self._app_entity(app_doc, payload, target)
        result.entities.append(app)
        app_ref = EntityRef.of(app)
        package = app.attributes.get("package") or ""

        self._add_permissions(payload, target, app_ref, result)
        components = self._add_components(payload, target, app_ref, package, result)
        self._add_deep_links(payload, target, package, components, result)
        self._add_native_libs(payload, target, app_ref, result)
        return result

    # -- entity builders ------------------------------------------------------

    def _app_entity(self, app_doc: dict[str, Any], payload: dict[str, Any],
                    target: Target) -> Entity:
        package = _text(app_doc.get("package"), 255)
        if package and not _PACKAGE_RE.match(package):
            package = None
        # Without a package name there is no natural key, so fall back to the
        # sample hash: the node still anchors the graph and stays stable.
        key = package or target.fallback_app_key

        certificates = [c for c in _items(payload, "certificates", 16)]
        inventory = payload.get("inventory") if isinstance(payload.get("inventory"), dict) else {}
        dex = _items(payload, "dex", 64)

        return self.entity(
            EntityType.APP, key, target,
            label=_text(app_doc.get("app_name")) or package or target.name or key,
            package=package,
            version_name=_text(app_doc.get("version_name"), 128),
            version_code=_text(app_doc.get("version_code"), 64),
            min_sdk=_number(app_doc.get("min_sdk")),
            target_sdk=_number(app_doc.get("target_sdk")),
            max_sdk=_number(app_doc.get("max_sdk")),
            main_activity=_text(app_doc.get("main_activity"), 512),
            application_class=_text(app_doc.get("app_class"), 512),
            debuggable=_flag(app_doc.get("debuggable")),
            allow_backup=_flag(app_doc.get("allow_backup")),
            uses_cleartext_traffic=_flag(app_doc.get("uses_cleartext_traffic")),
            network_security_config=_text(app_doc.get("network_security_config"), 512),
            backup_agent=_text(app_doc.get("backup_agent"), 512),
            test_only=_flag(app_doc.get("test_only")),
            has_code=_flag(app_doc.get("has_code")),
            signing=app_doc.get("signing") if isinstance(app_doc.get("signing"), dict) else {},
            certificates=[{
                "sha256": _text(c.get("sha256"), 64),
                "subject": _text(c.get("subject"), 512),
                "issuer": _text(c.get("issuer"), 512),
                "not_before": _text(c.get("not_before"), 64),
                "not_after": _text(c.get("not_after"), 64),
                "signature_algorithm": _text(c.get("signature_algorithm"), 64),
                "hash_algorithm": _text(c.get("hash_algorithm"), 64),
                "self_signed": _flag(c.get("self_signed")),
            } for c in certificates],
            dex_count=len(dex),
            file_count=_number(inventory.get("file_count")),
            uncompressed_bytes=_number(inventory.get("uncompressed_bytes")),
            sample_sha256=target.sha256,
            sample_name=target.name,
            analyzer_version=_text(payload.get("tool_version"), 64),
        )

    def _add_permissions(self, payload: dict[str, Any], target: Target,
                         app_ref: EntityRef, result: AnalyzerResult) -> None:
        declared = {
            name: doc for doc in _items(payload, "declared_permissions", _MAX_PERMISSIONS)
            if (name := _valid(_text(doc.get("name"), 255), _PERMISSION_RE))
        }
        requested = {
            name: doc for doc in _items(payload, "permissions", _MAX_PERMISSIONS)
            if (name := _valid(_text(doc.get("name"), 255), _PERMISSION_RE))
        }

        # A component can gate access behind a permission the app never
        # requests: android:permission on a Receiver naming a platform
        # permission the *caller* must hold. That permission is part of the
        # attack surface, so it needs a node; without one the edge from the
        # component dangles and the orchestrator drops it.
        enforced = self._component_enforced_permissions(payload)

        for name in sorted(set(declared) | set(requested) | enforced):
            definition = declared.get(name, {})
            request = requested.get(name, {})
            entity = self.entity(
                EntityType.PERMISSION, name, target,
                label=name.rsplit(".", 1)[-1],
                requested=name in requested,
                declared_by_app=name in declared,
                protection_level=_text(definition.get("protection_level"), 128),
                permission_group=_text(definition.get("permission_group"), 255),
                max_sdk=_number(request.get("max_sdk")),
                custom=not name.startswith("android.permission."),
                # True when the only reason we know of it is that a component
                # enforces it: the app neither requests nor defines it.
                enforced_by_component=(name in enforced and name not in requested
                                       and name not in declared),
            )
            result.entities.append(entity)
            ref = EntityRef.of(entity)
            if name in requested:
                result.edges.append(EdgeSpec(app_ref, ref, EdgeType.REQUESTS_PERMISSION))
            if name in declared:
                result.edges.append(EdgeSpec(app_ref, ref, EdgeType.DECLARES,
                                             {"role": "defines"}))

    @staticmethod
    def _component_enforced_permissions(payload: dict[str, Any]) -> set[str]:
        """Every permission named by a component's permission attributes."""
        found: set[str] = set()
        for doc in _items(payload, "components", _MAX_COMPONENTS):
            for key in ("permission", "read_permission", "write_permission"):
                name = _valid(_text(doc.get(key), 255), _PERMISSION_RE)
                if name:
                    found.add(name)
        return found

    def _add_components(self, payload: dict[str, Any], target: Target,
                        app_ref: EntityRef, package: str,
                        result: AnalyzerResult) -> dict[str, EntityRef]:
        """Component entities keyed by their fully-qualified class name."""
        refs: dict[str, EntityRef] = {}
        for doc in _items(payload, "components", _MAX_COMPONENTS):
            raw_name = _text(doc.get("name"), 512)
            if not raw_name:
                continue
            name = _qualify(raw_name, package)
            if not _CLASS_RE.match(name) or name in refs:
                continue
            kind = _KIND_MAP.get(_text(doc.get("kind")) or "")
            if kind is None:
                continue

            filters = [f for f in (doc.get("intent_filters") or [])
                       if isinstance(f, dict)][:64]
            exported = _flag(doc.get("exported"))
            entity = self.entity(
                EntityType.COMPONENT, name, target,
                label=name.rsplit(".", 1)[-1],
                kind=kind.value,
                exported=bool(exported),
                # Absent android:exported is itself interesting (it is mandatory
                # from target SDK 31), so keep the distinction for the auditor.
                exported_declared=_flag(doc.get("exported_declared")),
                enabled=_flag(doc.get("enabled")),
                permission=_text(doc.get("permission"), 255),
                read_permission=_text(doc.get("read_permission"), 255),
                write_permission=_text(doc.get("write_permission"), 255),
                grant_uri_permissions=_flag(doc.get("grant_uri_permissions")),
                authorities=_text(doc.get("authorities"), 1024),
                process=_text(doc.get("process"), 255),
                target_activity=_text(doc.get("target_activity"), 512),
                is_alias=(_text(doc.get("tag")) == "activity-alias"),
                intent_filter_count=len(filters),
                intent_filters=_clean_filters(filters),
            )
            result.entities.append(entity)
            ref = EntityRef.of(entity)
            refs[name] = ref

            result.edges.append(EdgeSpec(app_ref, ref, EdgeType.DECLARES))
            if exported:
                result.edges.append(EdgeSpec(app_ref, ref, EdgeType.EXPORTS))
            # A component-level permission is a real relationship in the graph:
            # "reaching this component requires holding that permission".
            for permission in _component_permissions(entity.attributes):
                result.edges.append(EdgeSpec(
                    ref, EntityRef(EntityType.PERMISSION, permission),
                    EdgeType.REQUESTS_PERMISSION, {"scope": "component"}))
        return refs

    def _add_deep_links(self, payload: dict[str, Any], target: Target, package: str,
                        components: dict[str, EntityRef],
                        result: AnalyzerResult) -> None:
        seen: set[str] = set()
        for doc in _items(payload, "deep_links", _MAX_DEEP_LINKS):
            scheme = _valid(_text(doc.get("scheme"), 64), _SCHEME_RE)
            if not scheme:
                continue
            host = _text(doc.get("host"), 255)
            port = _text(doc.get("port"), 8)
            path = (_text(doc.get("path"), 1024) or _text(doc.get("path_prefix"), 1024)
                    or _text(doc.get("path_pattern"), 1024) or "")
            authority = host or ""
            if host and port:
                authority = f"{host}:{port}"
            key = f"{scheme}://{authority}{path}"
            if key in seen:
                continue
            seen.add(key)

            entity = self.entity(
                EntityType.DEEP_LINK, key, target,
                label=key,
                scheme=scheme, host=host, port=port, path=path,
                path_prefix=_text(doc.get("path_prefix"), 1024),
                path_pattern=_text(doc.get("path_pattern"), 1024),
                mime_type=_text(doc.get("mime_type"), 255),
                auto_verify=_flag(doc.get("auto_verify")),
                browsable=_flag(doc.get("browsable")),
                # A custom scheme with no verification is the hijackable case;
                # the auditor decides, this just records what was declared.
                web_scheme=scheme in ("http", "https"),
            )
            result.entities.append(entity)

            component = _qualify(_text(doc.get("component"), 512) or "", package)
            owner = components.get(component)
            if owner is not None:
                result.edges.append(EdgeSpec(owner, EntityRef.of(entity),
                                             EdgeType.DECLARES, {"via": "intent-filter"}))

    def _add_native_libs(self, payload: dict[str, Any], target: Target,
                         app_ref: EntityRef, result: AnalyzerResult) -> None:
        seen: set[str] = set()
        for doc in _items(payload, "native_libs", _MAX_NATIVE_LIBS):
            path = _text(doc.get("path"), 1024)
            if not path or path in seen:
                continue
            seen.add(path)
            entity = self.entity(
                EntityType.NATIVE_LIB, path, target,
                label=_text(doc.get("name"), 255) or path.rsplit("/", 1)[-1],
                arch=_text(doc.get("arch"), 64),
                size=_number(doc.get("size")),
            )
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.EMBEDS))


# ----------------------------------------------------------------------- helpers

def _valid(value: str | None, pattern: re.Pattern[str]) -> str | None:
    return value if value and pattern.match(value) else None


def _container_name(path: Path) -> str:
    """Must match the sandbox's own mount-name sanitisation."""
    from ..sandbox.runner import _safe_mount_name
    return _safe_mount_name(path.name)


def _component_permissions(attributes: dict[str, Any]) -> Iterable[str]:
    """Every permission a component gates access behind, deduplicated."""
    out: list[str] = []
    for key in ("permission", "read_permission", "write_permission"):
        value = attributes.get(key)
        if value and _PERMISSION_RE.match(value) and value not in out:
            out.append(value)
    return out


def _clean_filters(filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bound and type-check intent filters before they are stored as JSON."""
    cleaned: list[dict[str, Any]] = []
    for filt in filters:
        actions = [a for a in (filt.get("actions") or []) if isinstance(a, str)][:64]
        categories = [c for c in (filt.get("categories") or []) if isinstance(c, str)][:64]
        cleaned.append({
            "actions": [a[:255] for a in actions],
            "categories": [c[:255] for c in categories],
            "auto_verify": _flag(filt.get("auto_verify")),
        })
    return cleaned
