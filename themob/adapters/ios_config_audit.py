"""iOS Info.plist and entitlements audit: findings from the graph, no container.

The iOS counterpart of config-audit. ios-unpack put the Info.plist facts and the
code-signing entitlements on the App node, and founded a DEEP_LINK node for each
custom URL scheme; this adapter judges them:

  * App Transport Security turned off app-wide or for web content, and named
    exception domains that permit cleartext HTTP (MASVS-NETWORK).
  * each custom URL scheme, which any other app can also claim (MASVS-PLATFORM).
  * iTunes / Finder file sharing exposing the Documents directory (MASVS-STORAGE).
  * get-task-allow, which leaves the binary debuggable (MASVS-RESILIENCE).
  * over-broad entitlements: a bare wildcard in keychain-access-groups or
    associated-domains.

**It runs no container and reads no sample.** Like config-audit it judges the
graph earlier stages built, so it carries no image and sets ``wants_graph``.
Each check fires only on an unambiguous signal, a flag that is exactly True, a
real domain, or a bare wildcard, so an undetermined or scoped value is never
reported: the auditor never claims a weakness it did not read.
"""
from __future__ import annotations

import json
from typing import Any, Iterator

from ..knowledge import get as weakness
from ..model.entities import Entity
from ..model.enums import EntityType, EvidenceKind, Platform, Stage
from ..model.findings import (Evidence, Finding, FindingSource, Location,
                              Remediation, RemediationStep)
from ..sandbox.runner import SandboxRunner
from ..storage.workspace import Workspace
from .base import (AnalysisContext, Analyzer, AnalyzerResult, RawResult, Target)

_MAX_TEXT = 2048
_MAX_CHECKS = 512
_MAX_DEEP_LINKS = 512


def _clip(value: Any, limit: int = _MAX_TEXT) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


def _has_bare_wildcard(values: Any) -> bool:
    """A bare wildcard (``*`` or a ``prefix:*`` with no domain), not a scoped one.

    ``keychain-access-groups: ["*"]`` and ``associated-domains: ["applinks:*"]``
    are over-broad; ``applinks:*.example.com`` is a scoped subdomain wildcard and
    is left alone, so a legitimate named domain is not flagged.
    """
    if not isinstance(values, list):
        return False
    for value in values:
        if not isinstance(value, str):
            continue
        token = value.strip()
        if token == "*" or token.endswith(":*"):
            return True
    return False


class IosConfigAuditAnalyzer(Analyzer):
    """Judge the iOS Info.plist facts and entitlements the unpacker recovered."""

    name = "ios-config-audit"
    display = "iOS · Info.plist & entitlements"
    stage = Stage.CONFIG_AUDIT
    platforms = (Platform.IOS,)
    image = ""                      # reads the graph, not the sample
    tool = "ios-config-audit"
    wants_graph = True
    license_note = ("themob's own auditor. It reads the Info.plist and "
                    "entitlement facts the iOS unpack stage put on the graph; no "
                    "third-party tool and no container.")

    # -- run ------------------------------------------------------------------

    def run(self, target: Target, workspace: Workspace,
            sandbox: SandboxRunner | None = None,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        if context is None or context.is_empty:
            base.error = ("nothing to audit: run the iOS unpack stage first so "
                          "the Info.plist is in the graph")
            return base

        app = context.app
        if app is None or app.type is not EntityType.APP:
            apps = context.of_type(EntityType.APP)
            app = apps[0] if apps else None
        if app is None:
            base.error = "no App node in the graph; the iOS unpack stage found none"
            return base

        deep_links = context.of_type(EntityType.DEEP_LINK)
        checks = list(self._audit(app, deep_links))[:_MAX_CHECKS]
        payload: dict[str, Any] = {
            "ok": True,
            "tool": self.tool,
            "app_key": app.key,
            "checks": checks,
            "counts": {"deep_links": len(deep_links), "findings": len(checks)},
        }

        try:
            path = workspace.raw_dir(self.name) / "ios-config-audit.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True),
                            encoding="utf-8")
            base.raw_path = workspace.relative(path)
        except OSError:
            base.raw_path = None

        base.payload = payload
        base.ok = True
        return base

    # -- the checks -----------------------------------------------------------

    def _audit(self, app: Entity, deep_links: list[Entity]) -> Iterator[dict[str, Any]]:
        yield from self._audit_ats(app)
        yield from self._audit_schemes(deep_links)
        yield from self._audit_storage(app)
        yield from self._audit_entitlements(app)

    def _audit_ats(self, app: Entity) -> Iterator[dict[str, Any]]:
        ats = app.attributes.get("ats")
        if not isinstance(ats, dict):
            return
        if ats.get("arbitrary_loads") is True:
            yield self._check("ios.ats.arbitrary-loads", app,
                              evidence="NSAllowsArbitraryLoads = true")
        if ats.get("arbitrary_loads_web") is True:
            yield self._check("ios.ats.arbitrary-loads-web", app,
                              evidence="NSAllowsArbitraryLoadsInWebContent = true")
        for domain in (ats.get("insecure_domains") or []):
            name = _clip(domain, 255)
            if name:
                yield self._check("ios.ats.insecure-exception-domain", app,
                                  evidence=f"NSExceptionAllowsInsecureHTTPLoads for {name}",
                                  detail=f"Exception domain: {name}",
                                  discriminator=name)

    def _audit_schemes(self, deep_links: list[Entity]) -> Iterator[dict[str, Any]]:
        for link in deep_links[:_MAX_DEEP_LINKS]:
            # Universal links (web schemes) are not hijackable the same way; iOS
            # CFBundleURLTypes never carries them, but guard anyway.
            if link.attributes.get("web_scheme") is True:
                continue
            scheme = _clip(link.attributes.get("scheme"), 128)
            if not scheme:
                continue
            yield self._check("ios.scheme.hijackable-url-scheme", link,
                              evidence=f"CFBundleURLSchemes declares {scheme}://",
                              discriminator=scheme)

    def _audit_storage(self, app: Entity) -> Iterator[dict[str, Any]]:
        if app.attributes.get("file_sharing") is True:
            yield self._check("ios.sharing.itunes-file-sharing", app,
                              evidence="UIFileSharingEnabled = true")

    def _audit_entitlements(self, app: Entity) -> Iterator[dict[str, Any]]:
        if app.attributes.get("get_task_allow") is True:
            yield self._check("ios.entitlement.get-task-allow", app,
                              evidence="get-task-allow = true")
        entitlements = app.attributes.get("entitlements")
        if not isinstance(entitlements, dict):
            return
        if _has_bare_wildcard(entitlements.get("keychain-access-groups")):
            yield self._check("ios.entitlement.wildcard-keychain", app,
                              evidence="keychain-access-groups contains a wildcard")
        if _has_bare_wildcard(entitlements.get("com.apple.developer.associated-domains")):
            yield self._check("ios.entitlement.wildcard-associated-domains", app,
                              evidence="associated-domains contains a wildcard")

    @staticmethod
    def _check(weakness_key: str, entity: Entity, *, evidence: str,
               detail: str = "", discriminator: str = "") -> dict[str, Any]:
        """One judgement, in the shape ``normalize`` reads back.

        ``get`` raises on an unknown key, which is deliberate: a typo would
        otherwise reach a report as an unmapped finding with no severity.
        """
        weakness(weakness_key)              # fail fast on an unknown key
        return {
            "weakness": weakness_key,
            "entity_key": entity.key,
            "entity_id": entity.id,
            "entity_type": entity.type.value,
            "file": "Info.plist",
            "evidence": _clip(evidence),
            "detail": _clip(detail),
            "discriminator": _clip(discriminator, 255),
        }

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        result = AnalyzerResult()
        if not raw.ok or not raw.payload:
            return result
        if raw.raw_path:
            result.artifacts.append(raw.raw_path)

        checks = raw.payload.get("checks")
        if not isinstance(checks, list):
            return result

        for check in checks[:_MAX_CHECKS]:
            if not isinstance(check, dict):
                continue
            finding = self._finding(check, raw)
            if finding is not None:
                result.findings.append(finding)
        return result

    def _finding(self, check: dict[str, Any], raw: RawResult) -> Finding | None:
        key = check.get("weakness")
        if not isinstance(key, str):
            return None
        try:
            spec = weakness(key)
        except KeyError:
            return None

        location = Location(file=_clip(check.get("file"), 512) or None)
        evidence_text = _clip(check.get("evidence"))
        detail = _clip(check.get("detail"))

        # Fingerprint is the canonical weakness plus where; the discriminator
        # separates distinct instances at one location (each exception domain,
        # each URL scheme) so they do not collapse into a single finding.
        fingerprint = Finding.compute_fingerprint(
            key, location, _clip(check.get("discriminator"), 255))

        description = spec.description
        if detail:
            description = f"{description}\n\n{detail}"

        entity_id = check.get("entity_id")
        return Finding(
            fingerprint=fingerprint,
            weakness_key=key,
            title=spec.title,
            description=description,
            severity=spec.severity,
            # A declaration read out of the Info.plist or the signed profile is a
            # fact, not an inference, so confident. Whether the exposure matters
            # in context is what the manual-validation workflow is for.
            confidence=0.95,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET, value=evidence_text,
                               artifact_path=raw.raw_path)] if evidence_text else [],
            entity_ids=[entity_id] if isinstance(entity_id, str) and entity_id else [],
            sources=[FindingSource(tool=self.tool, rule=key,
                                   raw_ref=raw.raw_path)],
            remediation=Remediation(
                summary=spec.remediation,
                steps=[RemediationStep(text=spec.remediation)],
                references=list(spec.references)),
        )
