"""The MCP tool layer: :mod:`themob.mcp.tools`.

These call the plain functions directly, with a throwaway project store and a
stubbed sandbox for the one tool that would otherwise need Docker. The server
binding in :mod:`themob.mcp.server` is a thin wrapper over these, so testing
here covers the behaviour; one test confirms the server registers the catalog.

The gate is the thing to prove: an agent-driven call cannot analyze without an
attestation, and the gated tools record one to the hash-chained trail.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from themob.audit.attestation import Attestation, AuditTrail
from themob.mcp import tools
from themob.model.entities import Edge, Entity
from themob.model.enums import (EdgeType, EntityType, Platform, Severity, Stage)
from themob.model.findings import Finding, FindingSource
from themob.orchestrator.intake import intake
from themob.storage.db import open_database
from themob.storage.repositories import Repositories

_FP = "a" * 64


def _seed(sample_apk: Path, tmp_path: Path, *, authorized: bool = True) -> str:
    """Ingest a sample into ``tmp_path`` and add a two-node graph with one
    finding. The database is closed before returning, so a tool opens it fresh.
    """
    database = open_database(tmp_path / "themob.db")
    try:
        repos = Repositories(database)
        audit = AuditTrail(repos.audit)
        result = intake(sample_apk, repos, audit, root=tmp_path)
        if authorized:
            audit.record_attestation(result.project, Attestation(
                target_name="sample.apk", target_sha256=result.sha256,
                operator="tester@lab", engagement_ref="ENG-1", attested=True),
                repos.projects)
        pid = result.project.id

        app = repos.entities.upsert(pid, Entity(
            type=EntityType.APP, platform=Platform.ANDROID,
            key="com.example.shop", label="shop",
            attributes={"package": "com.example.shop", "debuggable": True}))
        secret = repos.entities.upsert(pid, Entity(
            type=EntityType.SECRET, platform=Platform.ANDROID,
            key="AKIAEXAMPLE", label="AKIAEXAMPLE", attributes={"provider": "aws"}))
        repos.edges.upsert(pid, Edge(src_id=app.id, dst_id=secret.id,
                                     type=EdgeType.EVIDENCES))
        repos.findings.upsert(pid, Finding(
            fingerprint=_FP, title="Hardcoded AWS access key",
            severity=Severity.CRITICAL, confidence=0.9,
            masvs_control="MASVS-CODE-4",
            sources=[FindingSource(tool="gitleaks", rule="aws")],
            entity_ids=[secret.id]))
        return pid
    finally:
        database.close_all()


def _stub_pipeline():
    """A one-analyzer registry and an available sandbox, so no Docker is used."""
    from themob.adapters.base import (Analyzer, AnalyzerRegistry,
                                       AnalyzerResult, RawResult)
    from themob.sandbox.runner import SandboxRunner

    class _Stub(Analyzer):
        name = "stub"
        stage = Stage.UNPACK
        image = ""                     # no container, so always READY

        def run(self, target, workspace, sandbox, context=None) -> RawResult:
            return RawResult(analyzer=self.name, ok=True, payload={})

        def normalize(self, raw, target) -> AnalyzerResult:
            return AnalyzerResult(entities=[Entity(
                type=EntityType.APP, platform=Platform.ANDROID,
                key="com.example.shop", label="shop")])

    class _OkSandbox(SandboxRunner):
        def is_available(self) -> bool:
            return True

    registry = AnalyzerRegistry()
    registry.register(_Stub())
    return registry, _OkSandbox()


# --------------------------------------------------------------- read-only

def test_list_projects_and_overview(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    projects = tools.list_projects(tmp_path)["projects"]
    assert any(p["id"] == pid and p["authorized"] for p in projects)

    ov = tools.overview(tmp_path, pid)
    assert ov["findings"] == 1
    assert ov["highest_severity"] == "critical"
    assert ov["top_findings"][0]["title"] == "Hardcoded AWS access key"
    assert ov["application"].get("debuggable") is True


def test_findings_list_and_one_in_full(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    listed = tools.list_findings(tmp_path, pid, severity="critical")
    assert listed["count"] == 1

    full = tools.get_finding(tmp_path, pid, _FP[:12])     # a prefix is enough
    assert full["title"] == "Hardcoded AWS access key"
    assert full["standards"]["masvs"] == "MASVS-CODE-4"
    assert "gitleaks" in full["tools"]

    assert "error" in tools.list_findings(tmp_path, pid, severity="nope")
    assert "error" in tools.get_finding(tmp_path, pid, "doesnotexist")


def test_graph_and_entity(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    graph = tools.graph(tmp_path, pid)
    assert graph["entities"] == 2
    assert graph["counts_by_type"].get("secret") == 1

    secrets = tools.graph(tmp_path, pid, type="secret")["of_type"]
    assert len(secrets) == 1
    ent = tools.get_entity(tmp_path, pid, secrets[0]["id"])
    assert ent["type"] == "secret" and ent["connections"] >= 1

    assert "error" in tools.graph(tmp_path, pid, type="nonsense")
    assert "error" in tools.get_entity(tmp_path, pid, "nope")


def test_section_and_queries(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    section = tools.get_section(tmp_path, pid, "secrets")
    assert section["section"] == "secrets"
    assert any(f["title"] == "Hardcoded AWS access key"
               for f in section["findings"])
    assert "error" in tools.get_section(tmp_path, pid, "nonsense")

    queries = tools.list_queries(tmp_path)
    assert queries["builtin"], "there should be built-in queries"
    result = tools.run_query(tmp_path, pid, queries["builtin"][0]["key"])
    assert "summary" in result
    assert "error" in tools.run_query(tmp_path, pid, "no-such-query")


def test_audit_and_code_empty_state(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    audit = tools.audit(tmp_path, pid, verify=True)
    assert audit["chain_ok"] is True and audit["entries"]

    # No jadx run yet, so no decompiled sources: an honest message, not a crash.
    assert "error" in tools.list_code(tmp_path, pid)


def test_no_project_is_a_clean_error(tmp_path) -> None:
    assert "error" in tools.overview(tmp_path)
    assert tools.list_projects(tmp_path)["projects"] == []


# --------------------------------------------------------------- gated

def test_authorize_refuses_without_an_attestation(sample_apk, tmp_path) -> None:
    out = tools.authorize_target(tmp_path, sample_path=str(sample_apk),
                                 engagement_ref="ENG-9", attested=False)
    assert "error" in out and "attested" in out["error"]
    assert tools.list_projects(tmp_path)["projects"] == [], "nothing was ingested"


def test_authorize_refuses_without_an_engagement(sample_apk, tmp_path) -> None:
    out = tools.authorize_target(tmp_path, sample_path=str(sample_apk),
                                 engagement_ref="", attested=True)
    assert "error" in out and "engagement" in out["error"]


def test_authorize_records_the_attestation(sample_apk, tmp_path) -> None:
    out = tools.authorize_target(tmp_path, sample_path=str(sample_apk),
                                 engagement_ref="ENG-9", operator="me@lab",
                                 attested=True)
    assert "project" in out and out["project"]["authorized"] is True
    actions = [e["action"] for e in tools.audit(tmp_path, out["project"]["id"])["entries"]]
    assert any("authorized" in a for a in actions)


def test_analyze_refuses_an_unauthorized_project(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path, authorized=False)
    assert "error" in tools.analyze(tmp_path, pid)


def test_analyze_runs_with_a_stub_sandbox(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    registry, sandbox = _stub_pipeline()
    out = tools.analyze(tmp_path, pid, _registry=registry, _sandbox=sandbox)
    assert "error" not in out, out
    assert "state" in out and "failed" in out


def test_record_verdict_needs_a_reason_to_suppress(sample_apk, tmp_path) -> None:
    pid = _seed(sample_apk, tmp_path)
    refused = tools.record_verdict(tmp_path, pid, _FP, "false-positive")
    assert "error" in refused
    ok = tools.record_verdict(tmp_path, pid, _FP, "confirmed", operator="me@lab")
    assert ok["status"] == "confirmed"
    assert "error" in tools.record_verdict(tmp_path, pid, _FP, "nonsense")


# --------------------------------------------------------------- the server

def test_the_server_registers_the_catalog() -> None:
    from themob.mcp.server import build_server

    names = {t.name for t in asyncio.run(build_server(None).list_tools())}
    for expected in ("list_projects", "overview", "corpus", "list_findings",
                     "get_finding", "get_section", "graph", "get_entity",
                     "list_code", "read_class", "list_queries", "run_query",
                     "audit", "list_analyzers", "doctor", "authorize_target",
                     "analyze", "scan", "record_verdict"):
        assert expected in names, f"{expected} tool is missing"


def test_corpus_tool_summarises_across_projects(sample_apk, tmp_path) -> None:
    _seed(sample_apk, tmp_path)
    result = tools.corpus(tmp_path)
    assert result["projects"] >= 1 and result["findings"] >= 1
    assert isinstance(result["weaknesses"], list)
    # It is cross-project and names no app: no project id or name field.
    assert "application" not in result and "project" not in result
