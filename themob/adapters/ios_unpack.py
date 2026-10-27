"""iOS unpack: the Info.plist, framework and Mach-O inventory of an .ipa.

Stage 1 (unpack & inventory), the iOS counterpart of androguard. It reads the
worker's JSON and founds the graph: the App node (carrying the Info.plist facts
the iOS auditor will judge in M3), the embedded frameworks and dylibs as LIBRARY
nodes, and the main Mach-O as a NATIVE_LIB node (carrying the hardening flags the
Mach-O findings adapter turns into findings in M2).

It emits no findings itself: inventory and judgement live in separate stages, the
same split androguard and the config auditor keep, so a finding can cite an
entity instead of re-opening the package.

Everything below :meth:`normalize` treats the worker's JSON as untrusted: it was
produced by a parser that just chewed on a hostile file.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..model.entities import Entity
from ..model.enums import EdgeType, EntityType, Platform, Stage
from ..sandbox.runner import (CONTAINER_INPUT, SandboxResult, SandboxRunner,
                              _safe_mount_name, with_limits)
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, EdgeSpec,
                   EntityRef, RawResult, Target)

# A bundle identifier is reverse-DNS-ish; a URL scheme is an RFC-3986 scheme.
_BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,254}$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]{0,63}$")

_MAX_FRAMEWORKS = 2000
_MAX_SCHEMES = 512
_MAX_DEEP_LINKS = 512
_MAX_ENTITLEMENTS = 128
_MAX_TEXT = 4096

# URL schemes that are not an app-specific entry point: a deep-link node for one
# would be noise, and none of them should appear in CFBundleURLTypes anyway.
_WELL_KNOWN_SCHEMES = frozenset({
    "http", "https", "mailto", "tel", "telprompt", "sms", "facetime",
    "facetime-audio", "maps", "itms", "itms-apps", "itms-services"})


def _text(value: Any, limit: int = _MAX_TEXT) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = value if isinstance(value, str) else str(value)
    return text.strip()[:limit] or None


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


class IosUnpackAnalyzer(Analyzer):
    """Info.plist facts, embedded frameworks, and the main Mach-O of an iOS app."""

    name = "ios-unpack"
    display = "iOS · unpack & inventory"
    stage = Stage.UNPACK
    platforms = (Platform.IOS,)
    suffixes = (".ipa",)
    image = "themob/ios-unpack:1"
    tool = "ios-unpack"
    timeout = 300.0
    license_note = ("plistlib is the standard library; lief (Apache-2.0) runs "
                    "only inside the worker container, never imported here.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        raw_dir = workspace.raw_dir(self.name)
        container_sample = f"{CONTAINER_INPUT}/{_safe_mount_name(target.sample_path.name)}"
        result = sandbox.run(
            self.image,
            [container_sample],
            sample=target.sample_path,
            # The bundle is decoded to artifacts/ios so the secrets and
            # dependency scanners have a tree to walk, exactly as apktool's
            # decoded tree serves them on Android. The JSON summary still goes
            # to raw/ for provenance.
            output_dir=workspace.artifacts_root / "ios",
            limits=with_limits(sandbox, timeout_s=self.timeout,
                               memory=self.memory),
        )
        return self._to_raw_result(result, workspace, raw_dir)

    def _to_raw_result(self, result: SandboxResult, workspace: Workspace,
                       raw_dir) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = raw_dir / "ios-unpack.json"
            try:
                target_file.write_bytes(result.stdout)
                raw_path = workspace.relative(target_file)
            except OSError:
                raw_path = None

        base = RawResult(analyzer=self.name, raw_path=raw_path,
                         stderr=result.stderr[:_MAX_TEXT],
                         exit_code=result.exit_code,
                         duration_s=result.duration_s)

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
        if result.timed_out or result.truncated:
            base.error = result.error
        elif not payload.get("ok"):
            base.error = _text(payload.get("error")) or "the iOS worker reported a failure"
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
        schemes = self._schemes(app_doc)

        app = self._app_entity(app_doc, target, schemes)
        result.entities.append(app)
        app_ref = EntityRef.of(app)

        self._add_frameworks(payload, target, app_ref, result)
        self._add_macho(payload, target, app_ref, result)
        self._add_deep_links(schemes, target, app_ref, result)
        return result

    # -- entity builders ------------------------------------------------------

    @staticmethod
    def _schemes(app_doc: dict[str, Any]) -> list[str]:
        """The validated, deduplicated custom URL schemes from CFBundleURLTypes."""
        schemes: list[str] = []
        for scheme in (app_doc.get("url_schemes") or []):
            value = _text(scheme, 128)
            if value and _SCHEME_RE.match(value) and value not in schemes:
                schemes.append(value)
            if len(schemes) >= _MAX_SCHEMES:
                break
        return schemes

    @staticmethod
    def _entitlements(raw: Any) -> dict[str, Any]:
        """A bounded, scalar-and-list view of the profile's entitlements.

        The worker already bounded this; the adapter re-bounds it because worker
        output is untrusted, and drops anything the auditor's checks cannot read
        (nested dicts) so a node attribute never carries an arbitrary structure.
        """
        if not isinstance(raw, dict):
            return {}
        out: dict[str, Any] = {}
        for key, value in list(raw.items())[:_MAX_ENTITLEMENTS]:
            name = _text(key, 128)
            if not name:
                continue
            if isinstance(value, bool):
                out[name] = value
            elif isinstance(value, (int, float)):
                out[name] = value
            elif isinstance(value, str):
                out[name] = value[:512]
            elif isinstance(value, list):
                out[name] = [v[:512] for v in value if isinstance(v, str)][:64]
        return out

    def _app_entity(self, app_doc: dict[str, Any], target: Target,
                    schemes: list[str]) -> Entity:
        bundle_id = _text(app_doc.get("bundle_id"), 255)
        if bundle_id and not _BUNDLE_RE.match(bundle_id):
            bundle_id = None
        key = bundle_id or target.fallback_app_key

        ats_doc = app_doc.get("ats") if isinstance(app_doc.get("ats"), dict) else {}
        ats = {
            "arbitrary_loads": bool(ats_doc.get("arbitrary_loads")),
            "arbitrary_loads_web": bool(ats_doc.get("arbitrary_loads_web")),
            "arbitrary_loads_media": bool(ats_doc.get("arbitrary_loads_media")),
            "exception_domains": [d for d in (ats_doc.get("exception_domains") or [])
                                  if isinstance(d, str)][:256],
            "insecure_domains": [d for d in (ats_doc.get("insecure_domains") or [])
                                 if isinstance(d, str)][:256],
        } if ats_doc else {}

        return self.entity(
            EntityType.APP, key, target,
            label=_text(app_doc.get("name")) or bundle_id or target.name or key,
            bundle_id=bundle_id,
            version_name=_text(app_doc.get("version"), 128),
            version_code=_text(app_doc.get("build"), 64),
            min_os=_text(app_doc.get("min_os"), 32),
            platform_name=_text(app_doc.get("platform"), 32),
            executable=_text(app_doc.get("executable"), 255),
            # The Info.plist facts the iOS auditor (M3) judges.
            url_schemes=schemes,
            ats=ats,
            file_sharing=_flag(app_doc.get("file_sharing")),
            supports_document_browser=_flag(app_doc.get("supports_document_browser")),
            # Entitlement facts from embedded.mobileprovision, also for M3.
            entitlements=self._entitlements(app_doc.get("entitlements")),
            get_task_allow=_flag(app_doc.get("get_task_allow")),
            provisions_devices=_flag(app_doc.get("provisions_devices")),
            team_id=_text(app_doc.get("team_id"), 64),
            aps_environment=_text(app_doc.get("aps_environment"), 32),
            sample_sha256=target.sha256,
            sample_name=target.name,
        )

    def _add_deep_links(self, schemes: list[str], target: Target,
                        app_ref: EntityRef, result: AnalyzerResult) -> None:
        """Each custom URL scheme is a deep-link entry point.

        CFBundleURLSchemes are always custom (universal links use the
        associated-domains entitlement, not this list), so every one is a scheme
        any other installed app can also register. The node records it, the
        auditor (M3) decides it is hijackable. Mirrors androguard, which founds
        the Android DEEP_LINK nodes in the unpack stage for the auditor to judge.
        """
        seen: set[str] = set()
        for scheme in schemes[:_MAX_DEEP_LINKS]:
            if scheme in _WELL_KNOWN_SCHEMES:
                continue
            key = f"{scheme}://"
            if key in seen:
                continue
            seen.add(key)
            entity = self.entity(
                EntityType.DEEP_LINK, key, target,
                label=key, scheme=scheme, host=None, path="",
                web_scheme=False, source="CFBundleURLTypes")
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.DECLARES, {"via": "CFBundleURLTypes"}))

    def _add_frameworks(self, payload: dict[str, Any], target: Target,
                        app_ref: EntityRef, result: AnalyzerResult) -> None:
        items = payload.get("frameworks")
        if not isinstance(items, list):
            return
        seen: set[str] = set()
        for doc in items[:_MAX_FRAMEWORKS]:
            if not isinstance(doc, dict):
                continue
            path = _text(doc.get("path"), 1024)
            if not path or path in seen:
                continue
            seen.add(path)
            entity = self.entity(
                EntityType.LIBRARY, path, target,
                label=_text(doc.get("name")) or path.rsplit("/", 1)[-1],
                kind=_text(doc.get("kind"), 32))
            result.entities.append(entity)
            result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                         EdgeType.EMBEDS))

    def _add_macho(self, payload: dict[str, Any], target: Target,
                   app_ref: EntityRef, result: AnalyzerResult) -> None:
        macho = payload.get("macho")
        if not isinstance(macho, dict):
            return
        path = _text(macho.get("path"), 1024)
        if not path:
            return
        archs = [a for a in (macho.get("archs") or []) if isinstance(a, str)][:16]
        size = macho.get("size")
        entity = self.entity(
            EntityType.NATIVE_LIB, path, target,
            label=_text(macho.get("name")) or path.rsplit("/", 1)[-1],
            arch=", ".join(archs) or None,
            archs=archs,
            # The hardening flags M2 turns into findings, like nativelib does for
            # Android ELF .so files.
            hardening={
                "pie": _flag(macho.get("pie")),
                "encrypted": _flag(macho.get("encrypted")),
                "signed": _flag(macho.get("signed")),
                "stack_canary": _flag(macho.get("stack_canary")),
                "arc": _flag(macho.get("arc")),
                "nx": _flag(macho.get("nx")),
            },
            size=size if isinstance(size, int) else None,
            sha256=_text(macho.get("sha256"), 64),
        )
        result.entities.append(entity)
        result.edges.append(EdgeSpec(app_ref, EntityRef.of(entity),
                                     EdgeType.EMBEDS))
