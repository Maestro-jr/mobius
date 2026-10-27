"""The assistant core: themob.assist (license gate, briefing, honest grounding).

These use a stub LLM, so no network and no key are needed. The point to prove is
that the assistant is gated by a real signed licence, that it is honest when there
is nothing to explain, and that it only ever puts the real findings in front of
the model, never anything invented.
"""
from __future__ import annotations

import pytest

from themob import _signing
from themob.assist import core
from themob.assist import license as licensing
from themob.audit.attestation import Attestation, AuditTrail
from themob.model.entities import Entity
from themob.model.enums import EntityType, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.orchestrator.intake import intake
from themob.storage.db import open_database
from themob.storage.repositories import Repositories

_FP = "d" * 64


class _StubLlm:
    def __init__(self, reply: str = "Here is your prioritised fix plan.") -> None:
        self.reply = reply
        self.prompt = ""
        self.system = ""

    def complete(self, system: str, prompt: str) -> str:
        self.system, self.prompt = system, prompt
        return self.reply


@pytest.fixture(autouse=True)
def _no_license_env(monkeypatch):
    """Keep the developer's own licence and model keys out of these tests."""
    for name in ("THEMOB_LICENSE", "THEMOB_LICENSE_PUBKEY", "THEMOB_LLM_PROVIDER",
                 "THEMOB_LLM_MODEL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                 "GOOGLE_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY",
                 "MISTRAL_API_KEY", "CEREBRAS_API_KEY", "METERLESS_RUNTIME_TOKEN"):
        monkeypatch.delenv(name, raising=False)


def _license(tmp_path) -> None:
    private, public = _signing.generate_keypair()
    (tmp_path / "license.pub").write_bytes(public)
    (tmp_path / "license.key").write_text(
        licensing.issue(private, "Dev Co", "standard", 365), encoding="utf-8")


def _seed(sample_apk, tmp_path, *, with_findings: bool = True) -> str:
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        audit = AuditTrail(repos.audit)
        result = intake(sample_apk, repos, audit, root=tmp_path)
        audit.record_attestation(result.project, Attestation(
            target_name="sample.apk", target_sha256=result.sha256,
            operator="t@l", engagement_ref="ENG-1", attested=True), repos.projects)
        pid = result.project.id
        if with_findings:
            secret = repos.entities.upsert(pid, Entity(
                type=EntityType.SECRET, platform=Platform.ANDROID,
                key="AKIAEXAMPLE", label="AKIAEXAMPLE"))
            repos.findings.upsert(pid, Finding(
                fingerprint=_FP, title="Hardcoded AWS access key",
                severity=Severity.CRITICAL, confidence=0.9,
                masvs_control="MASVS-CODE-4",
                sources=[FindingSource(tool="gitleaks", rule="aws")],
                entity_ids=[secret.id]))
        return pid
    finally:
        database.close_all()


# ------------------------------------------------------------------ license

def test_license_round_trip_and_rejections(tmp_path) -> None:
    private, public = _signing.generate_keypair()
    token = licensing.issue(private, "Dev Co")
    assert licensing.verify(token, public).valid

    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert not licensing.verify(tampered, public).valid

    _p2, other = _signing.generate_keypair()
    assert not licensing.verify(token, other).valid

    expired = licensing.issue(private, "Dev Co", days=-1)
    assert not licensing.verify(expired, public).valid


def test_check_reads_the_home_files(tmp_path) -> None:
    assert not licensing.check(tmp_path).valid       # nothing configured yet
    _license(tmp_path)
    status = licensing.check(tmp_path)
    assert status.valid and status.licensee == "Dev Co"


def test_status_reports_license_and_model_readiness(tmp_path) -> None:
    state = core.status(tmp_path)
    assert state["enforced"] is False        # licensing is off by default
    assert state["licensed"] is True
    assert state["llm_ready"] is False        # no provider key is set
    assert state["provider"] == ""


# ------------------------------------------------------------------ assistant

def test_ask_is_licence_gated_only_when_enforcement_is_on(
        sample_apk, tmp_path, monkeypatch) -> None:
    """Off by default (the pitch build); still works when turned back on."""
    monkeypatch.setattr(core, "ENFORCE_LICENSE", True)
    pid = _seed(sample_apk, tmp_path)         # no licence files under tmp_path
    refused = core.ask(tmp_path, pid, "explain", client=_StubLlm())
    assert "error" in refused and "licensed" in refused["error"]
    _license(tmp_path)                        # now a valid licence
    assert "answer" in core.ask(tmp_path, pid, "explain", client=_StubLlm())


def test_ask_is_honest_when_there_are_no_findings(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path, with_findings=False)
    out = core.ask(tmp_path, pid, client=_StubLlm())
    assert "answer" in out and "no findings" in out["answer"].lower()


def test_ask_grounds_only_in_the_real_findings(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    stub = _StubLlm()
    out = core.ask(tmp_path, pid, "what are my worst issues?", client=stub)
    assert "answer" in out, out
    assert out["grounded_on"] >= 1
    # The real finding, and only real data, is what the model was given.
    assert "Hardcoded AWS access key" in stub.prompt
    assert "MASVS-CODE-4" in stub.prompt
    assert "ground every statement" in stub.system.lower()


def test_briefing_covers_every_weakness_with_counts(sample_apk, tmp_path) -> None:
    """A weakness found many times must be conveyed in full by a group with a
    count, not dropped by a flat top-N cut (the bug: 46 secrets, 0 mentioned).
    And a secret's raw value must never be shipped to the model."""
    from themob.model.enums import EvidenceKind
    from themob.model.findings import Evidence

    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        audit = AuditTrail(repos.audit)
        pid = intake(sample_apk, repos, audit, root=tmp_path).project.id
        for i in range(20):
            repos.findings.upsert(pid, Finding(
                fingerprint=f"{i:064x}",
                weakness_key="android.secrets.service-api-key",
                title="Third-party service API key is hardcoded",
                severity=Severity.HIGH, confidence=0.7,
                sources=[FindingSource(tool="apkleaks", rule="x")],
                evidence=[Evidence(kind=EvidenceKind.SNIPPET,
                                   value="apikey: SUPERSECRETVALUE123",
                                   redacted=False)]))
        repos.findings.upsert(pid, Finding(
            fingerprint="f" * 64,
            weakness_key="android.network.cleartext-endpoint",
            title="Cleartext endpoint", severity=Severity.HIGH, confidence=0.9,
            sources=[FindingSource(tool="apktool", rule="y")]))
    finally:
        database.close_all()

    briefing, error = core._briefing(tmp_path, pid)
    assert error == ""
    assert briefing["total_findings"] == 21
    groups = {g["weakness"]: g for g in briefing["weakness_groups"]}
    assert groups["android.secrets.service-api-key"]["count"] == 20
    assert groups["android.network.cleartext-endpoint"]["count"] == 1

    blob = core._prompt(briefing, "explain")
    assert "SUPERSECRETVALUE123" not in blob        # the raw secret stays local
    assert "android.secrets.service-api-key" in blob
    assert '"count":20' in blob                      # the full scope is conveyed


# -------------------------------------------------------------- provider layer

def test_make_client_without_a_key_names_the_options() -> None:
    from themob.assist import llm

    client, error = llm.make_client()
    assert client is None
    assert "key" in error.lower()


def test_make_client_rejects_an_unknown_provider() -> None:
    from themob.assist import llm

    client, error = llm.make_client(provider="nope")
    assert client is None and "unknown" in error.lower()


def test_a_free_provider_key_is_auto_detected(monkeypatch) -> None:
    """Setting GROQ_API_KEY selects groq; the OpenAI SDK may be absent here, so
    this asserts the selection, not a live client."""
    from themob.assist import llm

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    assert llm.current_provider() == "groq"
