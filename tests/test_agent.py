"""The investigation agent: the ReAct loop over themob's read-only tools.

A scripted client stands in for the model, so the tests drive the loop itself:
it runs the tool an ACTION names, feeds the observation back, records the step,
and stops on FINAL or the step cap. Read-only: it reasons over real seeded data
and takes no gated action.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from themob.assist import agent
from themob.model.entities import Entity
from themob.model.enums import EntityType, FindingStatus, Platform, Severity
from themob.model.findings import Finding, FindingSource
from themob.storage.db import open_database
from themob.storage.repositories import Project, Repositories


class _Scripted:
    """A model that replays canned replies and counts the calls."""

    def __init__(self, replies) -> None:
        self._replies = list(replies)
        self.calls = 0
        self.prompts: list[str] = []
        self.budgets: list[int | None] = []

    def complete(self, system: str, prompt: str, *, max_tokens=None) -> str:
        self.calls += 1
        self.prompts.append(prompt)
        self.budgets.append(max_tokens)
        return self._replies.pop(0)


def _seed(home: Path) -> str:
    database = open_database(home / "themob.db")
    try:
        repos = Repositories(database)
        project = Project(name="shop", target_platform=Platform.ANDROID,
                          source_path="shop.apk", source_sha256="a" * 64)
        repos.projects.create(project)
        repos.entities.upsert(project.id, Entity(
            type=EntityType.APP, platform=Platform.ANDROID,
            key="com.example.shop", label="shop",
            attributes={"package": "com.example.shop"}))
        repos.findings.upsert(project.id, Finding(
            fingerprint="b" * 64,
            weakness_key="android.network.cleartext-endpoint",
            title="Cleartext endpoint", severity=Severity.HIGH,
            status=FindingStatus.NEW,
            sources=[FindingSource(tool="t", rule="x")]))
        return project.id
    finally:
        database.close_all()


def test_agent_answers_from_the_primed_overview(tmp_path) -> None:
    """The loop is primed with the real overview and the full weakness scope, so
    the model can answer at once, grounded and complete, without being left to
    skip the tools and guess."""
    _seed(tmp_path)
    client = _Scripted([
        "FINAL: Your worst issue is a cleartext endpoint; move it to HTTPS."])
    result = agent.run(tmp_path, "", "what is my worst issue?", client=client)
    assert "cleartext" in result["answer"].lower()
    assert result["steps"] == [{"tool": "overview", "args": {}},
                               {"tool": "list_findings", "args": {}}]  # primed
    assert client.calls == 1


def test_the_agent_is_primed_with_the_full_weakness_scope(tmp_path) -> None:
    """Even a one-step answer must see every weakness, so the thin answers that
    covered only a finding or two do not recur."""
    _seed(tmp_path)
    client = _Scripted(["FINAL: covered."])
    agent.run(tmp_path, "", "summarise everything", client=client)

    primed = client.prompts[0]
    assert "the full scope" in primed
    assert "weakness_groups" in primed
    assert "android.network.cleartext-endpoint" in primed
    # The final answer gets a real budget, not the old hardcoded 2048 only.
    assert client.budgets[0] is not None and client.budgets[0] >= 2048

    # And when the provider advertises a larger budget, the final answer uses it.
    big = _Scripted(["FINAL: covered."])
    big.max_output_tokens = 8192
    agent.run(tmp_path, "", "summarise everything", client=big)
    assert big.budgets[0] == 8192


def test_agent_digs_deeper_when_it_needs_to(tmp_path) -> None:
    _seed(tmp_path)
    client = _Scripted(['ACTION: list_findings {"severity": "high"}',
                        "FINAL: done"])
    result = agent.run(tmp_path, "", "x", client=client)
    assert any(s["tool"] == "list_findings" for s in result["steps"])
    assert client.calls == 2


def test_agent_recovers_from_an_unknown_tool(tmp_path) -> None:
    _seed(tmp_path)
    client = _Scripted(["ACTION: nonsense {}", "FINAL: done"])
    result = agent.run(tmp_path, "", "x", client=client)
    assert result["answer"] == "done"
    assert any(s["tool"] == "nonsense" for s in result["steps"])   # obs was an error


def test_agent_needs_a_project(tmp_path) -> None:
    open_database(tmp_path / "themob.db").close_all()
    result = agent.run(tmp_path, "", "x", client=_Scripted(["FINAL: no"]))
    assert "error" in result


def test_the_last_step_is_forced_to_answer(tmp_path) -> None:
    """The call count is capped at max_steps; the last call must produce the
    answer, not spend a further call on a wrap-up."""
    _seed(tmp_path)
    client = _Scripted(['ACTION: list_findings {}', "FINAL: capped answer"])
    result = agent.run(tmp_path, "", "x", client=client, max_steps=2)
    assert result["answer"] == "capped answer"
    assert client.calls == 2                  # exactly two model calls, no wrap-up call


def test_still_acting_at_the_cap_is_marked_truncated(tmp_path) -> None:
    _seed(tmp_path)
    client = _Scripted(['ACTION: list_findings {}', 'ACTION: get_section {}'])
    result = agent.run(tmp_path, "", "x", client=client, max_steps=2)
    assert result.get("truncated") is True
    assert client.calls == 2                  # it did not spend a third call


def test_agent_streams_each_step(tmp_path) -> None:
    _seed(tmp_path)
    seen: list = []
    client = _Scripted(['ACTION: list_findings {"severity": "high"}', "FINAL: ok"])
    agent.run(tmp_path, "", "x", client=client,
              on_step=lambda tool, args: seen.append((tool, args)))
    assert seen and seen[0][0] == "list_findings"
    assert seen[0][1] == {"severity": "high"}


def test_agent_returns_validated_proposals(tmp_path) -> None:
    """The agent recommends gated actions in a PROPOSALS block; the engine keeps
    the valid ones (for the operator to approve) and drops the malformed."""
    _seed(tmp_path)
    final = ("FINAL: Here is my analysis.\n\n"
             'PROPOSALS: [{"action":"record_verdict","fingerprint":"bbbb",'
             '"status":"false_positive","reason":"only in a debug build"},'
             '{"action":"rea_prepare","target":"lib/arm64/libx.so",'
             '"reason":"custom crypto"},'
             '{"action":"bogus"},'
             '{"action":"record_verdict","fingerprint":"","status":"confirmed"}]')
    result = agent.run(tmp_path, "", "triage this", client=_Scripted([final]))

    assert result["answer"] == "Here is my analysis."     # PROPOSALS stripped out
    actions = [p["action"] for p in result["proposals"]]
    assert actions == ["record_verdict", "rea_prepare"]   # the two valid ones
    assert result["proposals"][0]["status"] == "false_positive"
    assert result["proposals"][1]["kind"] == "native"


def test_no_proposals_by_default(tmp_path) -> None:
    _seed(tmp_path)
    result = agent.run(tmp_path, "", "x", client=_Scripted(["FINAL: just an answer"]))
    assert result["proposals"] == []
    assert result["answer"] == "just an answer"


def test_a_bare_answer_is_accepted_as_final(tmp_path) -> None:
    """A model that answers directly, without the FINAL tag, is not lost."""
    _seed(tmp_path)
    client = _Scripted(["Here is my plain answer with no directive."])
    result = agent.run(tmp_path, "", "x", client=client)
    assert "plain answer" in result["answer"]
