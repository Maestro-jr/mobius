"""A full website review through the loop: web tables, web plan, web verdict."""
from __future__ import annotations

import json
import re

from themob.assist.meterless import MeterlessClient
from themob.mobius.agents import Lanes, RoleModels
from themob.mobius.datalayer import SqliteDataLayer
from themob.mobius.loop import Orchestrator, RunOptions
from themob.mobius.trace import RunTrace

MODELS = {"meterless/deep": "nvidia/nemotron-3-ultra-550b-a55b",
          "meterless/fast": "nvidia/nemotron-3.5-lightning-30b-a3b",
          "meterless/judge": "nvidia/nemotron-3.5-bolt-e4b"}
LANES = Lanes(planner="meterless/deep", executor="meterless/fast", critic="meterless/judge")
TARGET = "acme.io"


def web_tables():
    return {
        "mobius_web.assets": [
            {"target": TARGET, "run_id": "web-1", "kind": "domain", "value": TARGET,
             "depth": 0, "sources": "seed", "risk": "", "risk_reason": "", "detail": "{}"},
            {"target": TARGET, "run_id": "web-1", "kind": "subdomain",
             "value": "api.acme.io", "depth": 1, "sources": "crtsh,subfinder",
             "risk": "", "risk_reason": "", "detail": "{}"}],
        "mobius_web.findings": [
            {"target": TARGET, "run_id": "web-1", "fingerprint": "w1secret00000001",
             "kind": "leaked_secret", "category": "Leaked secret",
             "title": "google-api-key exposed in app/config.js",
             "weakness_key": "web.secret.exposed", "severity": "critical",
             "confidence": 0.9, "sources": "gitleaks", "advisory_id": "", "exploited": 0,
             "location": "app/config.js", "evidence": "Live Google API key in repo.",
             "exposed_value": "AIza****34"}],
        "mobius_intel.obligations": [
            {"sector": "ecommerce", "framework": "PCI DSS v4.0",
             "jurisdiction": "global (card data)", "applies_because": "online payments",
             "masvs_categories": "MASVS-STORAGE", "certainty": "established"}],
    }


class WebFake:
    def __init__(self):
        self.requests = []

    def __call__(self, method, url, headers, body, timeout):
        payload = json.loads(body)
        self.requests.append({"headers": headers, "payload": payload})
        system = payload["messages"][0]["content"]
        convo = "\n".join(m["content"] for m in payload["messages"])
        last = payload["messages"][-1]["content"]
        return 200, {}, json.dumps({
            "model": MODELS[payload["model"]],
            "choices": [{"message": {"content": self.reply(system, convo, last)}}],
        }).encode()

    def reply(self, system, convo, last):
        if system.startswith("You are the Planner in mobius, a multi-agent security"):
            assert "WEBSITE" in system          # the web planner prompt, not the app one
            return json.dumps({
                "sector": {"name": "ecommerce", "confidence": 0.8, "signals": ["shop"]},
                "investigations": [
                    {"id": "I1", "question": "Are any secrets leaked on the web surface?",
                     "why": "a live key is a breach", "priority": "high",
                     "weakness_keys": ["web.secret.exposed"]}]})
        if system.startswith("You are the Planner in mobius writing the final verdict"):
            data = json.loads(last.split("\n\nThe Critic")[0])
            crit = any(c["severity"] == "critical" for c in data["accepted_claims"])
            return json.dumps({
                "verdict": "block" if crit else "ship_with_fixes",
                "headline": "A live secret is exposed on the web surface.",
                "reasons": [{"text": "A Google API key is public.", "claims": ["C1"]}],
                "obligations": [], "next_steps": ["rotate the key"]})
        if system.startswith("You are the Executor"):
            ids = re.findall(r"\[(tq-\d+)\]", convo)
            if "Result:" not in last:
                return json.dumps({"action": "run_sql", "purpose": "I1", "sql":
                                   "SELECT fingerprint, severity, title, confidence "
                                   "FROM mobius_web.findings WHERE weakness_key = "
                                   "'web.secret.exposed'"})
            return json.dumps({"action": "claim",
                               "claim": "a Google API key is exposed on acme.io",
                               "severity": "critical", "present": True,
                               "fingerprints": ["w1secret00000001"], "evidence": [ids[-1]],
                               "confidence": 0.9, "weakness_keys": ["web.secret.exposed"]})
        if system.startswith("You are the Critic"):
            return json.dumps({"decision": "accept", "reason": "the row confirms it"})
        raise AssertionError("unexpected system prompt: " + system[:80])


def test_a_website_review_runs_end_to_end_and_blocks_on_a_live_secret(tmp_path):
    fake = WebFake()
    trace = RunTrace("web-run")
    client = MeterlessClient("http://127.0.0.1:8088", "ns-test", transport=fake)
    models = RoleModels(client, LANES, trace)
    from themob.hmem.scan_memory import ScanMemory
    data = SqliteDataLayer(web_tables())
    opts = RunOptions(kind="web", target=TARGET, use_memory=False)
    result = Orchestrator(data, models, ScanMemory(tmp_path / "hmem"), trace, opts).run(TARGET)

    assert result.package == TARGET
    assert result.verdict["verdict"] == "block"
    assert any(c.status == "accepted" and "web.secret.exposed" in c.weakness_keys
               for c in result.claims)
    kinds = [e.kind for e in result.trace.events]
    assert "plan" in kinds
    # the executor queried the web tables, not the app tables
    sql = " ".join(e.data.get("sql", "") for e in result.trace.events if e.kind == "sql")
    assert "mobius_web.findings" in sql and "mobius_scan" not in sql
