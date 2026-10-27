"""MobSF: a second opinion, not a second scanner.

MobSF finds much of what themob already finds. That is the point. Locked
decision 11 keeps it arms-length (its own container, its published REST API,
never imported or vendored), and the keying scheme turns the overlap into
evidence: when MobSF and the config auditor report the same weakness at the same
place, they merge into one finding with two sources rather than two findings at
half the confidence each.

**MobSF is not one witness.** It is a manifest reader, a pattern matcher over
decompiled code, and a certificate parser wearing a single name. Reporting all
of that as "mobsf" would inflate confidence precisely where it should be
discounted: its manifest findings agree with the config auditor because both
read the same manifest, not because two independent techniques converged. So
each section reports as ``mobsf/<section>`` and the voting model treats
``mobsf/manifest`` as the same method as ``config-audit``. See
``normalize/voting.py``.

**What it deliberately does not do.** A MobSF finding with no canonical weakness
key does not become a finding here. Inventing a key for it would put a
non-canonical identity into the fingerprint scheme, and two tools would stop
merging on the weakness they actually agree about. Those are counted, named in
the raw artifact, and reported as coverage MobSF has that themob has not mapped
yet, which is a truthful statement and a to-do list.

**The network.** MobSF is the one analyzer that cannot run with the network off,
because it is a server. It runs on an internal Docker network with no gateway,
and the HTTP client is another container on that same network, so the engine
process never opens a socket to it. See ``sandbox/service.py`` for why that is
stronger than publishing a port, not weaker.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Any

from ..knowledge import Weakness, get as weakness
from ..model.enums import (EntityType, EvidenceKind, Platform, Severity, Stage)


# How long the service may take to boot before the client ever talks to it.
# MobSF runs Django migrations on every cold start, and on a busy machine that
# has been seen past five minutes, so the window is generous. The service
# container must therefore outlive boot *and* the scan that follows, which is
# why its wall-clock ceiling is this plus the scan timeout, not the scan timeout
# alone. Tying the scan timeout to the container lifetime (an earlier mistake)
# let a lowered scan timeout kill MobSF before it had finished starting.
_MOBSF_READY_TIMEOUT_S = 900.0


def _mobsf_timeout() -> float:
    """The MobSF scan ceiling, in seconds (env THEMOB_MOBSF_TIMEOUT).

    MobSF is the slowest analyzer by far and the one most likely to fail: it is
    a whole server scanning the package, and on a memory-pressed host it can run
    for many minutes before timing out, which reads as the tool hanging. The
    default is lowered from half an hour to ten minutes so a stuck scan fails
    while the operator is still watching, and raised with the env var for the
    rare large package that legitimately needs longer.
    """
    try:
        return max(60.0, float(os.environ.get("THEMOB_MOBSF_TIMEOUT", "600")))
    except ValueError:
        return 600.0
from ..model.findings import Evidence, Finding, FindingSource, Location
from ..normalize.voting import METHODS
from ..sandbox.runner import SandboxResult, SandboxRunner, with_limits
from ..sandbox.service import SandboxService, ServiceError, ServiceSpec
from ..storage.workspace import Workspace
from .base import AnalysisContext, Analyzer, AnalyzerResult, Availability, RawResult
from ..orchestrator.intake import Target

logger = logging.getLogger(__name__)

_MAX_TEXT = 4000

# The service image, pulled and pinned (workers/mobsf/image.txt), and the client
# that speaks to it. Both must be present for this analyzer to be available.
SERVICE_IMAGE = "themob/mobsf:1"
CLIENT_IMAGE = "themob/mobsf-client:1"

# MobSF's own rule ids, mapped onto themob's canonical weakness keys, and onto
# the *place* the config auditor would report the same thing.
#
# The key alone is not enough. A fingerprint is
# ``sha256(weakness_key + location + discriminator)``, so a MobSF finding that
# names the same weakness at a different location does not merge with the
# auditor's: it becomes a second finding, and the report shows the same problem
# twice at half the confidence each. That is worse than not running MobSF, and
# it is the exact failure the canonical keying scheme exists to prevent, one
# level down.
#
# So every entry declares a scope, which is how the location is rebuilt:
#
#   APP        the auditor reports this on the manifest with no component
#   COMPONENT  the auditor reports it on the manifest, scoped to a component
#   None       themob cannot reconstruct the auditor's location for this rule,
#              so the finding is counted and dropped rather than emitted as a
#              near-duplicate. Honest, and visible in the coverage attribute.
#
# The manifest path is the auditor's default (config_audit._MANIFEST) and is
# asserted equal to it by a test, so the two cannot drift apart silently.
APP = "app"
COMPONENT = "component"
MANIFEST_FILE = "AndroidManifest.xml"

_MANIFEST_KEYS: dict[str, tuple[str, str | None]] = {
    # Rule ids read off a live MobSF v4.3.2, not transcribed from memory. Every
    # id guessed the first time round was wrong, which is what the probe in
    # tools/ is for.
    "allowbackup_not_set": ("android.config.backup-allowed", APP),
    "allowbackup_enabled": ("android.config.backup-allowed", APP),
    "clear_text_traffic": ("android.network.cleartext-permitted", APP),
    "app_is_debuggable": ("android.config.debuggable", APP),
    "vulnerable_os_version": ("android.platform.min-sdk-unsupported", APP),
    # MobSF reports the component type and then its name, and the name is empty
    # when it could not resolve one. COMPONENT scope requires a real name, so
    # an unresolved one is dropped rather than filed against the type.
    "exported_intent_filter_exists": (
        "android.ipc.component-exported-unprotected", COMPONENT),
    "explicitly_exported": (
        "android.ipc.component-exported-unprotected", COMPONENT),
    "exported_provider": ("android.ipc.provider-exported-unprotected", COMPONENT),
    "exported_protected_permission_normal": (
        "android.ipc.custom-permission-weak-protection", COMPONENT),
}
_CERTIFICATE_KEYS: dict[str, tuple[str, str | None]] = {
    "signed_v1_only": ("android.integrity.v1-signature-only", APP),
}
# The auditor reports these against the network security config file it parsed,
# whose path MobSF does not hand back. Mapped so the coverage is recorded, and
# scoped None so they are counted rather than emitted as a near-duplicate of a
# finding themob already has from a source that read the file itself.
_NETWORK_KEYS: dict[str, tuple[str, str | None]] = {
    "1": ("android.network.cleartext-permitted", APP),
    "2": ("android.network.cleartext-permitted-for-domain", None),
    "3": ("android.network.user-ca-trusted", None),
    "4": ("android.network.user-ca-trusted", None),
}
# semgrep reports these against the class and method it parsed. MobSF gives a
# file path at best, so the same reasoning applies: counted, not duplicated.
_CODE_KEYS: dict[str, tuple[str, str | None]] = {
    "android_md5": ("android.crypto.weak-hash", None),
    "android_sha1": ("android.crypto.weak-hash", None),
    "android_aes_ecb": ("android.crypto.weak-cipher-mode", None),
}

_SECTION_KEYS: dict[str, dict[str, tuple[str, str | None]]] = {
    "manifest": _MANIFEST_KEYS,
    "network": _NETWORK_KEYS,
    "code": _CODE_KEYS,
    "certificate": _CERTIFICATE_KEYS,
}

# MobSF's severity words, in themob's ramp. "high" from a scanner that never ran
# the app is not our CRITICAL: the scorer raises for reachability later, and a
# tool arriving pre-escalated would double-count that.
_SEVERITY = {
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "info": Severity.INFO,
    "secure": Severity.INFO,
    "good": Severity.INFO,
    "hotspot": Severity.LOW,
}

# What one MobSF section is worth on its own. Lower than the config auditor's
# 0.95 for the same weakness: the auditor read the manifest out of the graph it
# built, while this is a second program's opinion about a file themob did not
# watch it parse.
_CONFIDENCE = 0.8


class MobSFScanAnalyzer(Analyzer):
    """Runs MobSF as a service and merges what it says with what we found."""

    name = "mobsf-scan"
    display = "MobSF"
    stage = Stage.SAST
    platforms = (Platform.ANDROID,)
    suffixes = (".apk",)
    image = CLIENT_IMAGE
    timeout = _mobsf_timeout()
    memory = "2g"
    tool = "mobsf"
    license_note = (
        "MobSF is GPL-3.0. It runs as its own container and is reached only "
        "over its published REST API: never imported, never vendored, and its "
        "output format is not re-implemented here (locked decision 11)."
    )

    # The service needs far more than a one-shot worker, and it is a server
    # rather than a parser, so its ceilings are its own.
    service_memory = "4g"
    service_cpus = 2.0

    def __init__(self, service: SandboxService | None = None) -> None:
        self._service = service

    # -- capability -----------------------------------------------------------

    def availability(self, sandbox: Any = None) -> str:
        """Both images, not just the client's.

        The base class checks :attr:`image` alone, which would report ready
        with no server to talk to, and the failure would arrive as an empty
        scan: the shape of "no findings" that this codebase keeps refusing.
        """
        state = super().availability(sandbox)
        if state != Availability.READY:
            return state
        try:
            if not sandbox.has_image(SERVICE_IMAGE):
                return Availability.NO_IMAGE
        except Exception:                    # noqa: BLE001, availability never raises
            return Availability.NO_SANDBOX
        return Availability.READY

    # -- execution ------------------------------------------------------------

    def service_spec(self, sandbox: SandboxRunner, api_key: str) -> ServiceSpec:
        """How MobSF is started. One definition, so tests cannot drift from it.

        The profile is deliberately weaker than a worker's, and the reasons are
        in ``sandbox/service.py``: this is somebody else's image, it ships its
        own unprivileged user and owns its home directory, and a read-only root
        with a tmpfs over that home masks the installation outright. What still
        holds is everything that carries the containment: no route off the
        host, all capabilities dropped, no-new-privileges, memory and pid
        ceilings, and no mount of the sample at all, because the client hands it
        the bytes over HTTP.
        """
        return ServiceSpec(
            image=SERVICE_IMAGE,
            port=8000,
            env={"MOBSF_API_KEY": api_key},
            ready_argv=["python", "-c",
                        "import urllib.request;"
                        "urllib.request.urlopen('http://127.0.0.1:8000/', "
                        "timeout=5)"],
            ready_timeout_s=_MOBSF_READY_TIMEOUT_S,
            # The container must live long enough to boot and then run the whole
            # scan, so its ceiling is the boot window plus the scan timeout. Not
            # the scan timeout alone: that killed the server mid-boot once the
            # scan timeout was lowered.
            limits=with_limits(sandbox, memory=self.service_memory,
                               cpus=self.service_cpus,
                               timeout_s=_MOBSF_READY_TIMEOUT_S + self.timeout),
            user=None,
            read_only=False,
        )

    def run(self, target: Target, workspace: Workspace, sandbox: SandboxRunner,
            context: AnalysisContext | None = None) -> RawResult:
        base = RawResult(analyzer=self.name)

        sample = workspace.stored_input()
        if sample is None or not sample.is_file():
            base.error = "no stored sample to scan"
            return base

        # A fresh key per run, so a key never outlives the container that used
        # it and nothing on the host has to hold a long-lived credential.
        api_key = secrets.token_hex(32)
        service = self._service or SandboxService(sandbox)

        spec = self.service_spec(sandbox, api_key)

        try:
            with service.running(spec) as handle:
                result = service.client_run(
                    handle, CLIENT_IMAGE, [],
                    sample=sample,
                    env={"THEMOB_MOBSF_URL": handle.url,
                         "THEMOB_MOBSF_KEY": api_key},
                    limits=with_limits(sandbox, timeout_s=self.timeout,
                                       memory=self.memory),
                )
        except ServiceError as exc:
            base.error = str(exc)[:_MAX_TEXT]
            return base

        return self._to_raw_result(result, workspace)

    def _to_raw_result(self, result: SandboxResult,
                       workspace: Workspace) -> RawResult:
        raw_path: str | None = None
        if result.stdout:
            target_file = workspace.raw_dir(self.name) / "mobsf.json"
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
        # Mirror every other adapter: ok stays False until the run is confirmed
        # good, so a successful scan is marked ok and its findings persist. The
        # missing line here reported even a clean MobSF run as a failure.
        if result.timed_out or result.truncated:
            base.error = result.error or "MobSF did not finish"
        elif not payload.get("ok"):
            base.error = str(payload.get("error") or "MobSF reported a failure")
        elif result.error and not result.ok:
            base.error = result.error
        else:
            base.ok = True
        return base

    # -- normalize ------------------------------------------------------------

    def normalize(self, raw: RawResult, target: Target) -> AnalyzerResult:
        out = AnalyzerResult()
        payload = raw.payload if isinstance(raw.payload, dict) else {}
        sections = payload.get("sections")
        if not isinstance(sections, dict):
            return out

        unmapped: list[str] = []
        unreachable: list[str] = []
        for section, items in sections.items():
            mapping = _SECTION_KEYS.get(str(section))
            if mapping is None or not isinstance(items, list):
                continue
            reporter = f"{self.tool}/{section}"
            for item in items:
                if not isinstance(item, dict):
                    continue
                rule = str(item.get("rule") or "")
                entry = mapping.get(rule)
                if entry is None:
                    unmapped.append(f"{section}:{rule}")
                    continue
                key, scope = entry
                if scope is None:
                    # Mapped, but themob cannot rebuild the location the tool
                    # that owns this weakness would use, so emitting it would
                    # duplicate rather than corroborate.
                    unreachable.append(f"{section}:{rule}")
                    continue
                finding = self._finding(key, scope, reporter, item, raw)
                if finding is not None:
                    out.findings.append(finding)

        # The App node carries what MobSF saw, the way every other adapter
        # records its own coverage. Unmapped rules are stated rather than
        # silently dropped: "MobSF saw 14 things themob has no key for" is a
        # to-do list, and leaving it out would make the overlap look total when
        # it is not.
        distinct = sorted(set(unmapped))
        not_merged = sorted(set(unreachable))
        out.entities.append(self.entity(
            EntityType.APP, target.fallback_app_key, target,
            label=target.name or target.fallback_app_key,
            mobsf_scan={
                "tool_version": payload.get("tool_version") or None,
                "findings": len(out.findings),
                "unmapped": distinct[:200],
                "unmapped_count": len(distinct),
                # Recognised, but not emitted, because themob could not put it
                # where the finding it would merge with already sits.
                "not_mergeable": not_merged[:200],
                "not_mergeable_count": len(not_merged),
                "truncated": bool(payload.get("truncated")),
            },
        ))
        if distinct:
            logger.info("mobsf: %d rule(s) with no canonical key: %s",
                        len(distinct), ", ".join(distinct[:10]))
        if not_merged:
            logger.info("mobsf: %d rule(s) dropped rather than duplicated: %s",
                        len(not_merged), ", ".join(not_merged[:10]))
        return out

    def _finding(self, key: str, scope: str, reporter: str, item: dict,
                 raw: RawResult) -> Finding | None:
        spec: Weakness | None = weakness(key)
        if spec is None:                     # a key was removed from the pack
            logger.warning("mobsf: unknown weakness key %r, dropping", key)
            return None

        targets = [str(t).strip() for t in (item.get("targets") or [])
                   if str(t).strip()][:20]
        component = _component(targets) if scope == COMPONENT else None
        if scope == COMPONENT and component is None:
            # MobSF names the component type before its name ("Activity", then
            # "com.example.shop.MainActivity") and leaves the name empty when it
            # could not resolve one. Filing the finding against "Activity" would
            # put it somewhere the auditor's finding is not, so it would report
            # the same problem twice instead of merging. Dropped, and counted.
            return None
        location = Location(file=MANIFEST_FILE, component=component)

        evidence_text = str(item.get("description") or item.get("title") or "")[:800]
        severity = _SEVERITY.get(str(item.get("severity", "")).lower(),
                                 spec.severity)

        return Finding(
            # The discriminator is empty, matching the config auditor: the
            # weakness and the place are the identity, and MobSF's own prose
            # about it is evidence, not part of who the finding is.
            fingerprint=Finding.compute_fingerprint(key, location, ""),
            weakness_key=key,
            title=spec.title,
            description=str(item.get("description") or spec.description)[:2000],
            severity=severity,
            confidence=_CONFIDENCE,
            masvs_category=spec.masvs_category,
            masvs_control=spec.masvs_control,
            maswe_id=spec.maswe_id,
            mobile_top10=spec.mobile_top10,
            cwe=spec.cwe,
            location=location,
            evidence=[Evidence(kind=EvidenceKind.SNIPPET, value=evidence_text,
                               artifact_path=raw.raw_path)] if evidence_text else [],
            sources=[FindingSource(tool=reporter, rule=str(item.get("rule") or ""))],
        )


def _component(targets: list[str]) -> str | None:
    """The fully qualified component name among MobSF's target strings.

    A dot is the discriminator: "Activity" is a type and
    "com.example.shop.MainActivity" is a place. Requiring one rather than
    taking the first entry is what keeps a finding from being filed against a
    component that does not exist.
    """
    for candidate in targets:
        if "." in candidate and not candidate.endswith((".java", ".kt", ".xml")):
            return candidate
    return None


def known_reporters() -> set[str]:
    """Every reporter name this adapter can emit.

    Used by the tripwire test: a section whose reporter is not in the voting
    model would be treated as an independent method, which is the one mistake
    the qualified names exist to prevent.
    """
    return {f"mobsf/{section}" for section in _SECTION_KEYS}


def mapped_keys() -> set[str]:
    """Every canonical weakness key this adapter recognises."""
    return {key for mapping in _SECTION_KEYS.values()
            for key, _scope in mapping.values()}


def emitted_keys() -> set[str]:
    """The subset it will actually emit, which is what can merge."""
    return {key for mapping in _SECTION_KEYS.values()
            for key, scope in mapping.values() if scope is not None}
