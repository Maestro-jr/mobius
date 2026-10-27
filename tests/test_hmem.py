"""H-MEM (Meterless engine): the spec contracts and memory across sessions.

The spec checks mirror the official conformance vectors so they run with no
Node; ``test_official_conformance_suite`` runs the real Meterless runner
against this engine through the TypeScript shim when Node is available.
The scan-memory tests are the feature the engine powers: a later session,
opened fresh on the same directory, knows what an earlier one learned.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from themob.hmem.engine import HMEM, DAY_MS
from themob.hmem.scan_memory import ScanMemory

T0 = 1_750_000_000_000
_ROOT = Path(__file__).resolve().parent.parent
_VECTORS = json.loads((_ROOT / "engines/hmem/conformance/vectors/vectors.json")
                      .read_text(encoding="utf-8"))["sections"]


def _hmem(tmp_path=None, now=T0):
    return HMEM(clock=lambda: now, persist_dir=tmp_path)


# -- the spec, vector by vector -----------------------------------------------

@pytest.mark.parametrize("case", _VECTORS["record-validation"], ids=lambda c: c["id"])
def test_record_validation(case):
    hmem = _hmem()
    try:
        hmem.add(case["input"]["content"], source=case["input"]["source"])
        outcome = "accept"
    except ValueError:
        outcome = "reject"
    assert outcome == case["expect"]


@pytest.mark.parametrize("case", _VECTORS["feedback-deltas"], ids=lambda c: c["id"])
def test_feedback_deltas(case):
    hmem = _hmem()
    m = hmem.add("feedback target record", confidence=case["start"], source="t")
    before = m["accessCount"]
    hmem.feedback(m["id"], case["kind"])
    after = hmem.store.get(m["id"])
    assert after["confidence"] == pytest.approx(case["expectConfidence"], abs=1e-9)
    if "expectAccessDelta" in case:
        assert after["accessCount"] - before == case["expectAccessDelta"]
    if case.get("expectTag"):
        assert case["expectTag"] in after["tags"]


@pytest.mark.parametrize("case", _VECTORS["ranking-order"], ids=lambda c: c["id"])
def test_ranking_order(case):
    hmem = _hmem()
    by_key = {r["key"]: hmem.add(r["content"], confidence=r["confidence"],
                                 layer=r["layer"], source="t") for r in case["records"]}
    for r in case["records"]:
        if r.get("supersededByKey"):
            by_key[r["key"]]["supersededBy"] = by_key[r["supersededByKey"]]["id"]
    order = [m["memory"]["id"] for m in
             hmem.query(case["query"], threshold=0, top_n=10)["memories"]]
    expected = [by_key[k]["id"] for k in case["expectOrder"]]
    assert [i for i in order if i in expected] == expected


def test_sleep_guardrails_protect_derived_records():
    case = _VECTORS["sleep-guardrails"][0]
    now = [T0]
    hmem = HMEM(clock=lambda: now[0])
    by_key = {r["key"]: hmem.add(r["content"], source=r["source"],
                                 derived_from=r.get("derivedFrom"))
              for r in case["records"]}
    now[0] = T0 + case["ageDays"] * DAY_MS
    before = sorted(r["id"] for r in hmem.store.all())
    preview = hmem.sleep.preview()
    assert sorted(r["id"] for r in hmem.store.all()) == before     # preview is pure
    assert by_key["plain"]["id"] in preview["toArchive"]
    assert by_key["derived"]["id"] not in preview["toArchive"]
    report = hmem.sleep.execute(preview)
    assert hmem.store.get(by_key["derived"]["id"]) is not None
    assert report["backupId"]


def test_conflict_resolution_supersedes_and_never_deletes():
    case = _VECTORS["conflict-gate"][0]
    hmem = _hmem()
    a = hmem.add(case["a"]["content"], confidence=case["a"]["confidence"], source="t")
    b = hmem.add(case["b"]["content"], confidence=case["b"]["confidence"], source="t")
    found = hmem.conflicts.scan()
    assert found
    if hmem.conflicts.auto_resolve(found[0]) == "resolved":
        assert hmem.store.get(b["id"])["supersededBy"] == a["id"]
    assert hmem.store.get(a["id"]) and hmem.store.get(b["id"])


def test_ledger_reconstructs_history():
    hmem = _hmem()
    m = hmem.add("audited record", confidence=0.7, source="t")
    hmem.feedback(m["id"], "wrong")
    history = hmem.ledger.history(m["id"])
    assert [h["action"] for h in history] == ["create", "feedback"]
    assert history[-1]["previousState"]["confidence"] == pytest.approx(0.7)
    assert history[-1]["newState"]["confidence"] == pytest.approx(0.5)


def test_dreams_need_approval():
    hmem = _hmem()
    hmem.add("prefer short bullet answers", type="preference", source="t")
    hmem.add("prefer python for scripting", type="preference", source="t")
    count = len(hmem.store.all())
    proposals = hmem.dreaming.dream()
    assert proposals and len(hmem.store.all()) == count
    created = hmem.dreaming.approve(proposals[0]["id"])
    if created:
        assert created["layer"] == "long_term" and created["derivedFrom"]


def test_every_service_survives_a_restart(tmp_path):
    first = _hmem(tmp_path)
    a = first.add("always pin TLS certificates for the payments api", source="t",
                  confidence=0.9)
    first.add("never pin TLS certificates for the payments api", source="t",
              confidence=0.3)
    first.conflicts.scan()
    second = _hmem(tmp_path)                                # a new process
    assert second.store.get(a["id"])["content"].startswith("always")
    assert second.conflicts.queue() or second.conflicts.conflicts
    assert [e["action"] for e in second.ledger.history(a["id"])][0] == "create"


@pytest.mark.skipif(shutil.which("npx") is None, reason="Node/npx not installed")
def test_official_conformance_suite():
    """The Meterless runner, unmodified, driving this engine: 13/13."""
    hmem_dir = _ROOT / "engines" / "hmem"
    if not (hmem_dir / "node_modules" / "tsx").exists():
        pytest.skip("run `npm install` in engines/hmem first")
    proc = subprocess.run("npm run conformance", cwd=hmem_dir, shell=True,
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert "13/13 checks passed" in proc.stdout


# -- the feature: scan memory across sessions ---------------------------------

_PKG = "com.example.bank"


def test_a_new_session_recalls_the_confirmed_sector(tmp_path):
    ScanMemory(tmp_path).remember_sector(_PKG, "fintech", confirmed_by="owner",
                                         evidence="mobile banking for SMEs")
    recall = ScanMemory(tmp_path).recall(_PKG, "is this safe to ship")
    assert recall.confirmed_sector == "fintech"
    assert recall.sector_by_human is True
    assert recall.sector_memory in recall.ids
    assert "fintech" in recall.context


def test_a_human_correction_supersedes_the_agents_guess(tmp_path):
    memory = ScanMemory(tmp_path)
    guess = memory.remember_sector(_PKG, "ecommerce", confirmed_by="planner")
    fixed = memory.remember_sector(_PKG, "fintech", confirmed_by="owner")
    later = ScanMemory(tmp_path)
    assert later.hmem.store.get(guess["id"])["supersededBy"] == fixed["id"]
    assert later.hmem.store.get(fixed["id"])["supersedes"] == guess["id"]
    assert later.recall(_PKG, "sector").confirmed_sector == "fintech"


def test_rulings_and_verdicts_come_back_for_the_same_app_only(tmp_path):
    memory = ScanMemory(tmp_path)
    memory.remember_ruling(_PKG, "android.logging.sensitive", "false_positive",
                           title="Sensitive data in logs", reason="debug build only",
                           by="owner")
    memory.remember_verdict(_PKG, "block", sector="fintech",
                            summary="cleartext traffic to the payments API")
    memory.remember_verdict("com.other.app", "ship", sector="fintech", summary="clean")
    recall = ScanMemory(tmp_path).recall(_PKG, "logging verdict")
    assert recall.prior_verdict == "block"
    assert recall.rulings["android.logging.sensitive"]["status"] == "false_positive"
    assert recall.rulings["android.logging.sensitive"]["human"] is True
    assert all("com.other.app" not in m.content for m in recall.memories)


def test_other_apps_in_the_sector_become_priors(tmp_path):
    memory = ScanMemory(tmp_path)
    memory.remember_sector("com.peer.wallet", "fintech", confirmed_by="owner")
    memory.remember_verdict("com.peer.wallet", "block", sector="fintech",
                            summary="CVE-2023-0001 in okhttp was KEV-listed")
    memory.remember_sector(_PKG, "fintech", confirmed_by="owner")
    recall = ScanMemory(tmp_path).recall(_PKG, "dependency risk")
    assert any("com.peer.wallet" in p.content for p in recall.sector_priors)
    assert "SECTOR MEMORY: fintech" in recall.context


def test_recall_is_audited_and_feedback_moves_confidence(tmp_path):
    memory = ScanMemory(tmp_path)
    record = memory.remember_sector(_PKG, "fintech", confirmed_by="planner")
    memory.recall(_PKG, "sector")
    memory.feedback(record["id"], "wrong")
    later = ScanMemory(tmp_path)
    actions = [e["action"] for e in later.hmem.ledger.history(record["id"])]
    assert actions[:1] == ["create"] and "read" in actions and "feedback" in actions
    assert later.hmem.store.get(record["id"])["confidence"] == pytest.approx(0.4)


def test_an_empty_memory_says_so(tmp_path):
    recall = ScanMemory(tmp_path).recall(_PKG, "anything")
    assert recall.empty and recall.confirmed_sector is None
