"""The mobius agent loop, end to end, with each sponsor shown to be load-bearing.

A scripted fake runtime plays the three Nemotron lanes behind the real
Meterless client (so receipts, routes and the sponsor ledger are exercised for
real); the SQLite test double plays Zetaris with the same catalog. The point
of the ablation tests: turn a sponsor off and the answer measurably changes.
"""
from __future__ import annotations

import json
import re

import pytest

from themob.assist.meterless import MeterlessClient
from themob.hmem.scan_memory import ScanMemory
from themob.mobius.agents import Lanes, RoleModels, parse_json
from themob.mobius.datalayer import (DataLayerError, SqliteDataLayer, ZetarisClient,
                                     guard_read_only)
from themob.mobius.loop import Orchestrator, RunOptions, write_run
from themob.mobius.trace import RunTrace, format_ledger

PKG = "com.acme.paymobile"
CVE = "CVE-2021-0341"
MODELS = {"meterless/deep": "nvidia/nemotron-3.5-super-vl-120b-a12b",
          "meterless/fast": "nvidia/nemotron-3.5-lightning-30b-a3b",
          "meterless/judge": "nvidia/nemotron-3.5-judge"}
LANES = Lanes(planner="meterless/deep", executor="meterless/fast", critic="meterless/judge")


def tables(*, advisories: bool = True) -> dict:
    data = {
        "mobius_scan.app": [{
            "run_id": "r1", "package": PKG, "label": "Acme Pay", "version": "4.2.0",
            "platform": "android", "sha256": "ab" * 32,
            "permissions": "android.permission.INTERNET,android.permission.USE_BIOMETRIC",
            "libraries": "okhttp,stripe-android"}],
        "mobius_scan.findings": [
            {"run_id": "r1", "package": PKG, "fingerprint": "f1dep0000000000a",
             "weakness_key": "android.supply-chain.vulnerable-dependency",
             "maswe_id": "MASWE-0076", "title": f"{CVE} in okhttp 3.12.0",
             "severity": "high", "confidence": 0.9, "votes": 1, "tools": "sbom",
             "status": "new", "advisory_id": CVE, "masvs_category": "MASVS-CODE",
             "cwe": "CWE-1395", "location": "pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
             "evidence": "okhttp 3.12.0 matches the advisory", "risk": 7.5},
            {"run_id": "r1", "package": PKG, "fingerprint": "f2clear00000000b",
             "weakness_key": "android.network.cleartext", "maswe_id": "MASWE-0050",
             "title": "Cleartext traffic permitted", "severity": "medium",
             "confidence": 0.6, "votes": 1, "tools": "config_audit", "status": "new",
             "advisory_id": "", "masvs_category": "MASVS-NETWORK", "cwe": "CWE-319",
             "location": "AndroidManifest.xml", "evidence": "usesCleartextTraffic=true",
             "risk": 5.0},
            {"run_id": "r1", "package": PKG, "fingerprint": "f3log000000000c",
             "weakness_key": "android.logging.sensitive", "maswe_id": "MASWE-0001",
             "title": "Sensitive data written to logs", "severity": "medium",
             "confidence": 0.7, "votes": 2, "tools": "semgrep,mobsf", "status": "new",
             "advisory_id": "", "masvs_category": "MASVS-STORAGE", "cwe": "CWE-532",
             "location": "PaymentLogger.java", "evidence": "Log.d(card)", "risk": 4.0},
        ],
        "mobius_scan.entities": [
            {"run_id": "r1", "package": PKG, "entity_id": "e1", "type": "component",
             "key": "com.acme.PayActivity", "label": "PayActivity", "exported": 1,
             "detail": "{}"}],
        "mobius_intel.obligations": [
            {"sector": "fintech", "framework": "PCI DSS v4.0",
             "jurisdiction": "global (card data)", "applies_because": "card data",
             "masvs_categories": "MASVS-STORAGE,MASVS-NETWORK", "certainty": "established"}],
    }
    if advisories:
        data["mobius_intel.kev"] = [{"cve_id": CVE, "vendor": "Square", "product": "OkHttp",
                                     "name": "OkHttp certificate pinning bypass",
                                     "date_added": "2024-05-01", "ransomware": "Unknown",
                                     "action": "Apply updates"}]
        data["mobius_intel.epss"] = [{"cve": CVE, "epss": 0.91, "percentile": 0.99,
                                      "date": "2026-10-25"}]
    return data


class FakeNightshift:
    """Three lanes, scripted. Behaves like a cooperative but fallible Nemotron."""

    def __init__(self, *, verdict_override: str | None = None,
                 executor_never_cites: bool = False) -> None:
        self.verdict_override = verdict_override
        self.executor_never_cites = executor_never_cites
        self.requests: list[dict] = []

    def __call__(self, method, url, headers, body, timeout):
        payload = json.loads(body)
        self.requests.append({"headers": headers, "payload": payload})
        route = payload["model"]
        system = payload["messages"][0]["content"]
        last = payload["messages"][-1]["content"]
        convo = "\n".join(m["content"] for m in payload["messages"])
        reply = self.reply(system, last, convo)
        return 200, {"meterless-lane": route}, json.dumps({
            "model": MODELS[route], "choices": [{"message": {"content": reply}}],
            "usage": {"prompt_tokens": len(convo) // 4, "completion_tokens": len(reply) // 4},
        }).encode()

    def reply(self, system, last, convo) -> str:
        if system.startswith("You are the Planner in mobius, a multi-agent"):
            return json.dumps({
                "sector": {"name": "ecommerce", "confidence": 0.5, "signals": ["pay"]},
                "investigations": [
                    {"id": "I1", "question": "Are bundled dependencies known-exploited?",
                     "why": "a KEV CVE is a ship blocker", "priority": "high",
                     "weakness_keys": ["android.supply-chain.vulnerable-dependency"]},
                    {"id": "I2", "question": "Is cleartext traffic allowed?",
                     "why": "card data in transit", "priority": "high",
                     "weakness_keys": ["android.network.cleartext"]},
                    {"id": "I3", "question": "Does the app log sensitive data?",
                     "why": "PCI forbids it", "priority": "medium",
                     "weakness_keys": ["android.logging.sensitive"]}]})
        if system.startswith("You are the Planner in mobius writing the final verdict"):
            data = json.loads(last.split("\n\nThe Critic rejected")[0])
            accepted = data["accepted_claims"]
            crit = [c["id"] for c in accepted if c["severity"] == "critical"]
            verdict = self.verdict_override or ("block" if crit else
                                                "ship_with_fixes" if accepted else "ship")
            cited = crit or [c["id"] for c in accepted][:1]
            return json.dumps({"verdict": verdict, "headline": f"{verdict} for {data['sector']}",
                               "reasons": [{"text": "evidence-backed risk", "claims": cited}]
                               if cited else [],
                               "obligations": [{"framework": "PCI DSS v4.0", "why": "card data",
                                                "claims": cited}],
                               "next_steps": ["upgrade okhttp"]})
        if system.startswith("You are the senior reviewer"):
            return json.dumps({"decision": "needs_human", "severity": "high",
                               "reason": "the evidence cannot settle it"})
        if system.startswith("You are the Critic"):
            if "Rule checks: all passed" in last:
                return json.dumps({"decision": "accept", "reason": "rows support it"})
            return json.dumps({"decision": "retry", "reason": "rules failed",
                               "hint": "corroborate with another source"})
        if system.startswith("You are the Executor"):
            return self.executor(convo, last)
        raise AssertionError("unexpected system prompt: " + system[:80])

    def executor(self, convo: str, last: str) -> str:
        ids = re.findall(r"\[(tq-\d+)\]", convo)
        inv = re.search(r"Investigation (I\d|M\d)", convo).group(1)
        if self.executor_never_cites and inv == "I2":
            if not ids or "Result:" not in last:
                return json.dumps({"action": "run_sql", "sql":
                                   "SELECT * FROM mobius_scan.findings WHERE 1 = 0"})
            return json.dumps({"action": "claim", "claim": "cleartext is a problem",
                               "severity": "high", "evidence": [], "present": True})
        if "Result:" not in last:
            sql = {
                "I1": "SELECT fingerprint, advisory_id, severity, votes, confidence, title "
                      "FROM mobius_scan.findings WHERE advisory_id <> ''",
                "I2": "SELECT fingerprint, severity, votes, confidence, title FROM "
                      "mobius_scan.findings WHERE weakness_key = 'android.network.cleartext'",
                "I3": "SELECT fingerprint, severity, votes, confidence FROM "
                      "mobius_scan.findings WHERE weakness_key = 'android.logging.sensitive'",
            }[inv]
            return json.dumps({"action": "run_sql", "sql": sql, "purpose": inv})
        qid = ids[-1]
        if inv == "I1":
            return json.dumps({"action": "claim", "claim": f"okhttp 3.12.0 carries {CVE}",
                               "severity": "high", "present": True,
                               "fingerprints": ["f1dep0000000000a"], "evidence": [qid],
                               "confidence": 0.9,
                               "weakness_keys": ["android.supply-chain.vulnerable-dependency"]})
        if inv == "I2":
            corrected = "WEAK_CORROBORATION" in convo
            return json.dumps({"action": "claim",
                               "claim": "the manifest permits cleartext traffic",
                               "severity": "medium" if corrected else "high",
                               "present": True, "fingerprints": ["f2clear00000000b"],
                               "evidence": [qid], "confidence": 0.6,
                               "weakness_keys": ["android.network.cleartext"]})
        if "MEMORY: this weakness was ruled" in convo:
            return json.dumps({"action": "claim", "present": False, "severity": "info",
                               "claim": "nothing new contradicts the owner's ruling",
                               "evidence": [qid], "confidence": 0.8,
                               "weakness_keys": ["android.logging.sensitive"]})
        return json.dumps({"action": "claim", "claim": "card data is logged",
                           "severity": "medium", "present": True,
                           "fingerprints": ["f3log000000000c"], "evidence": [qid],
                           "confidence": 0.7, "weakness_keys": ["android.logging.sensitive"]})


def _run(tmp_path, *, memory_dir=None, fake=None, advisories=True, **options):
    fake = fake or FakeNightshift()
    trace = RunTrace("run-test")
    client = MeterlessClient("http://127.0.0.1:8088", "ns-test", transport=fake)
    models = RoleModels(client, LANES, trace)
    memory = ScanMemory(memory_dir or tmp_path / "hmem")
    data = SqliteDataLayer(tables(advisories=advisories))
    opts = RunOptions(use_advisories=advisories, **options)
    return Orchestrator(data, models, memory, trace, opts).run(PKG), fake


def _seed_memory(path):
    memory = ScanMemory(path)
    memory.remember_sector(PKG, "fintech", confirmed_by="owner",
                           evidence="card payments for SMEs")
    memory.remember_ruling(PKG, "android.logging.sensitive", "false_positive",
                           title="Sensitive data written to logs",
                           reason="the logger is stripped from release builds", by="owner")


# -- the loop -----------------------------------------------------------------------


def test_full_run_reaches_an_evidence_backed_block(tmp_path):
    _seed_memory(tmp_path / "hmem")
    result, fake = _run(tmp_path)
    claims = {c.investigation: c for c in result.claims}
    assert result.verdict["verdict"] == "block"
    assert claims["I1"].exploited and claims["I1"].severity == "critical"
    assert claims["I2"].status == "accepted" and claims["I2"].attempts == 2
    assert claims["I3"].present is False                    # memory narrowed it
    assert result.sector == "fintech" and "memory" in result.sector_source
    kinds = [e.kind for e in result.trace.events]
    assert "retry" in kinds and "upgrade" in kinds and "memory_applied" in kinds


def test_every_model_call_goes_through_nightshift_with_its_lane(tmp_path):
    result, fake = _run(tmp_path)
    for request in fake.requests:
        assert request["headers"]["meterless-app"] == "mobius"
        assert request["headers"]["meterless-scope"] == "user"
        assert request["payload"]["model"] in MODELS
    ledger = result.trace.ledger()["nightshift"]
    assert ledger["requests"] == len(fake.requests) > 5
    assert ledger["nemotron_share"] == 1.0
    assert set(ledger["by_role"]) == {"planner", "executor", "critic"}
    roles = {e.data["role"]: e.data["model"] for e in result.trace.events
             if e.kind == "model_call"}
    assert roles["critic"] != roles["executor"]          # never grades its own work


def test_the_ledger_counts_every_sponsor(tmp_path):
    _seed_memory(tmp_path / "hmem")
    result, _ = _run(tmp_path)
    ledger = result.trace.ledger()
    assert ledger["zetaris"]["queries"] >= 10
    assert "mobius_intel.kev" in ledger["zetaris"]["tables"]
    assert ledger["hmem"]["recalls"] == 1 and ledger["hmem"]["plan_changes"] >= 2
    assert ledger["hmem"]["writes"] >= 1 and ledger["hmem"]["feedback"] >= 1
    assert ledger["loop"]["retries"] >= 1
    text = format_ledger(ledger)
    assert "Zetaris" in text and "H-MEM" in text and "Nemotron handled 100%" in text


def test_the_run_is_written_with_an_explain_why_report(tmp_path):
    _seed_memory(tmp_path / "hmem")
    result, _ = _run(tmp_path)
    out = write_run(result, tmp_path / "out")
    report = (out / "report.md").read_text(encoding="utf-8")
    assert "Block" in report and CVE in report and "SELECT" in report
    assert "What memory contributed" in report
    assert (out / "trace.jsonl").read_text().count("\n") == len(result.trace.events)
    assert json.loads((out / "verdict.json").read_text())["verdict"]["verdict"] == "block"


# -- ablation: each sponsor changes the answer --------------------------------------


def test_without_memory_the_plan_and_answer_change(tmp_path):
    _seed_memory(tmp_path / "hmem")
    with_memory, _ = _run(tmp_path)
    without, _ = _run(tmp_path, use_memory=False)
    assert with_memory.sector == "fintech" and without.sector == "ecommerce"
    logged = {c.investigation: c for c in without.claims}["I3"]
    assert logged.present is True                      # re-litigated without memory
    assert without.trace.ledger()["hmem"]["recalls"] == 0
    assert without.trace.ledger()["hmem"]["plan_changes"] == 0


def test_without_advisories_the_exploited_dependency_is_missed(tmp_path):
    with_kev, _ = _run(tmp_path)
    without, _ = _run(tmp_path, advisories=False)
    dep = {c.investigation: c for c in without.claims}["I1"]
    assert with_kev.verdict["verdict"] == "block"
    assert dep.exploited is False and dep.severity == "high"
    assert without.verdict["verdict"] == "ship_with_fixes"
    assert "mobius_intel.kev" not in without.trace.ledger()["zetaris"]["tables"]


def test_memory_carries_the_verdict_into_the_next_session(tmp_path):
    _run(tmp_path, sector="fintech")                      # operator confirms the sector
    second, _ = _run(tmp_path)
    assert second.verdict.get("prior_verdict") == "block"
    assert second.sector == "fintech" and "owner-confirmed" in second.sector_source


# -- the Critic's backstops -----------------------------------------------------------


def test_critic_overrides_a_verdict_the_evidence_does_not_allow(tmp_path):
    result, _ = _run(tmp_path, fake=FakeNightshift(verdict_override="ship"))
    assert result.verdict["verdict"] == "block"
    assert "critic_override" in result.verdict
    assert "override" in [e.kind for e in result.trace.events]


def test_a_claim_that_never_cites_evidence_escalates_to_a_human(tmp_path):
    result, _ = _run(tmp_path, fake=FakeNightshift(executor_never_cites=True))
    claim = {c.investigation: c for c in result.claims}["I2"]
    assert claim.status == "needs_human" and claim.attempts == 3
    assert result.verdict["needs_human"] == [claim.id]
    assert result.trace.ledger()["loop"]["escalations"] == 1


def test_live_runs_refuse_a_provider_without_lanes():
    with pytest.raises(Exception, match="Meterless"):
        RoleModels(object(), LANES, RunTrace("x"))


# -- the Zetaris contract and the read-only guard ---------------------------------------


@pytest.mark.parametrize("sql", [
    "DROP TABLE mobius_scan.findings", "SELECT 1; DELETE FROM x",
    "CREATE LIGHTNING DATABASE x", "WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a",
    "UPDATE mobius_scan.findings SET status = 'x'"])
def test_agents_cannot_write_through_zetaris(sql):
    with pytest.raises(DataLayerError):
        guard_read_only(sql)


def test_read_only_guard_allows_quoted_keywords():
    assert guard_read_only("SELECT * FROM t WHERE title = 'DROP; DELETE';") \
        == "SELECT * FROM t WHERE title = 'DROP; DELETE'"


def test_zetaris_client_sends_the_guide_contract():
    seen = {}

    def transport(method, url, headers, body, timeout):
        seen.update(method=method, url=url, headers=headers, body=json.loads(body))
        return 200, {}, json.dumps({"columns": ["one"], "data": [[1]]}).encode()

    result = ZetarisClient("http://localhost:8888/api/v1.0/", "zk-test", "1",
                           transport=transport).run("SELECT 1 AS one")
    assert seen["url"] == "http://localhost:8888/api/v1.0/sql-editor/sqls/run"
    assert seen["headers"]["Authorization"] == "Bearer zk-test"
    assert seen["headers"]["X-Org-ID"] == "1"
    assert re.fullmatch(r"[0-9a-f-]{36}", seen["headers"]["X-Request-ID"])
    assert seen["body"]["sql"] == "SELECT 1 AS one" and seen["body"]["source"] == "SqlEditor"
    assert result.records() == [{"one": 1}] and result.source == "zetaris"


@pytest.mark.parametrize("payload,columns,rows", [
    ({"data": [[1, "a"]]}, ["col0", "col1"], [[1, "a"]]),
    ({"data": [{"x": 1}]}, ["x"], [[1]]),
    ({"data": {"columns": [{"name": "x"}], "rows": [[2]]}}, ["x"], [[2]]),
])
def test_zetaris_result_shapes(payload, columns, rows):
    result = ZetarisClient("http://z/api/v1.0", "k", transport=lambda *a: (
        200, {}, json.dumps(payload).encode())).run("SELECT 1")
    assert result.columns == columns and result.rows == rows


def test_zetaris_401_names_the_fix():
    client = ZetarisClient("http://z/api/v1.0", "k",
                           transport=lambda *a: (401, {}, b'{"message": "bad key"}'))
    with pytest.raises(DataLayerError, match="API Tokens"):
        client.run("SELECT 1")


def test_parse_json_tolerates_think_blocks_and_fences():
    assert parse_json('<think>hmm</think>```json\n{"a": 1,}\n```') == {"a": 1}


class DeadExecutorLane(FakeNightshift):
    """The fast lane answers with nothing, as a reasoning lane out of budget does."""

    def __call__(self, method, url, headers, body, timeout):
        payload = json.loads(body)
        if payload["model"] == "meterless/fast":
            self.requests.append({"headers": headers, "payload": payload})
            return 200, {}, json.dumps({"model": MODELS["meterless/fast"],
                                        "choices": [{"message": {"content": ""}}]}).encode()
        return super().__call__(method, url, headers, body, timeout)


def test_a_dead_lane_falls_back_to_another_nemotron_lane(tmp_path):
    _seed_memory(tmp_path / "hmem")
    result, _fake = _run(tmp_path, fake=DeadExecutorLane())
    kinds = [e.kind for e in result.trace.events]
    assert "recover" in kinds and "fallback" in kinds
    assert result.verdict["verdict"] == "block"           # the run still reaches it


class NoLaneAnswers(FakeNightshift):
    def __call__(self, method, url, headers, body, timeout):
        payload = json.loads(body)
        if "Executor" in payload["messages"][0]["content"][:60]:
            return 500, {}, b'{"error":{"message":"upstream down","type":"server"}}'
        return super().__call__(method, url, headers, body, timeout)


def test_when_no_lane_answers_the_investigation_goes_to_a_human(tmp_path):
    result, _fake = _run(tmp_path, fake=NoLaneAnswers())
    assert all(c.status == "needs_human" for c in result.claims)
    assert len({c.id for c in result.claims}) == len(result.claims)
    assert "needs_human" in [e.kind for e in result.trace.events]


SMARTWAY_VOCAB = {"android.secrets.service-api-key": (37, "Third-party service API key is hardcoded"),
                  "android.crypto.weak-cipher-mode": (2, "Cipher used in a mode that leaks"),
                  "android.crypto.weak-hash": (6, "Weak hash"),
                  "android.ipc.component-exported-unprotected": (2, "Component is exported")}


def test_absence_claims_the_scan_contradicts_are_blocked():
    from themob.mobius.agents import Claim, Investigation, absence_issues
    secrets = Investigation("I1", "Does the app embed hardcoded secrets or API keys?",
                            weakness_keys=["hardcoded_secret"])
    claim = Claim("C2", "I1", "No hardcoded secrets found", present=False)
    issues = absence_issues(claim, secrets, SMARTWAY_VOCAB)
    assert [i.code for i in issues] == ["ABSENCE_CONTRADICTED"]
    assert "37 findings under android.secrets.service-api-key" in issues[0].message
    crypto = Investigation("I4", "Are weak cipher modes or broken hash functions used?")
    keys = {i.message.split(" under ")[1].split(" ")[0]
            for i in absence_issues(Claim("C9", "I4", "none", present=False), crypto,
                                    SMARTWAY_VOCAB)}
    assert keys == {"android.crypto.weak-cipher-mode", "android.crypto.weak-hash"}
    # a different topic, a present claim, or a memory ruling check: nothing to object to
    kev = Investigation("I5", "Are bundled dependencies known-exploited (KEV)?")
    assert absence_issues(Claim("C1", "I5", "none", present=False), kev, SMARTWAY_VOCAB) == []
    assert absence_issues(Claim("C3", "I1", "found", present=True), secrets, SMARTWAY_VOCAB) == []
    ruled = Investigation("I6", "Hardcoded secrets?", mode="verify_ruling")
    assert absence_issues(Claim("C4", "I6", "ruling holds", present=False), ruled,
                          SMARTWAY_VOCAB) == []
