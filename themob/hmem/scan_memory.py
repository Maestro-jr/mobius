"""What mobius remembers between scans, on top of the H-MEM engine.

Four kinds of memory, each an ordinary H-MEM record identified by tags:

* ``kind:sector``  - what the app is (fintech, health, education...), and who
  said so. A human confirmation outranks the agents' own guess.
* ``kind:verdict`` - the verdict a past run reached, and its top risks.
* ``kind:ruling``  - a weakness ruled false positive / confirmed / accepted for
  this app, and why. The Planner uses these to avoid re-litigating a settled
  question, and the Critic to notice when new evidence contradicts one.
* ``kind:lesson``  - what the Critic learned: a claim that needed more evidence,
  an escalation and how it ended.

A newer memory about the same thing *supersedes* the older one (H-MEM keeps the
old record, penalised in ranking, with the link both ways), so the history of
"we thought fintech, the owner said education" stays inspectable.

Recall is scoped structurally (this package's memories; other apps in the same
sector for cross-app priors) and ranked by the spec's hybrid score, so every
recalled line carries an H-MEM id and a relevance the trace can show.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .engine import HMEM

SECURITY_DOMAINS = {
    "security": (
        "tls", "ssl", "certificate", "pinning", "cleartext", "secret", "key",
        "token", "exported", "permission", "webview", "crypto", "storage",
        "logging", "vulnerable", "cve", "dependency", "verdict", "finding",
        "false", "positive", "exploited", "kev", "epss", "backup", "debuggable",
        "intent", "provider", "risk", "escalated", "evidence"),
    "sector": (
        "fintech", "bank", "banking", "payment", "payments", "wallet", "money",
        "health", "medical", "patient", "education", "school", "student", "kids",
        "children", "government", "ecommerce", "shop", "social", "messaging",
        "sector"),
}
ENTITY_PATTERNS = (
    r"MASWE-\d{4}",
    r"CVE-\d{4}-\d{4,}",
    r"GHSA(?:-[0-9a-z]{4}){3}",
    r"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}\b",          # an app/package id
)
SECTOR_TERMS = ("fintech", "health", "education", "kids", "government",
                "ecommerce", "social", "messaging")
_HUMAN = ("operator", "owner", "user", "human")


def default_memory_dir() -> Path:
    env = os.environ.get("MOBIUS_HMEM_DIR")
    if env:
        return Path(env).expanduser()
    from ..storage.workspace import default_root
    return default_root() / "hmem"


@dataclass
class Recalled:
    id: str
    kind: str
    content: str
    relevance: float
    superseded: bool = False


@dataclass
class Recall:
    """What memory said before this run started, ready for the Planner."""

    package: str
    memories: list[Recalled] = field(default_factory=list)
    context: str = ""                      # the H-MEM reinjection block
    confirmed_sector: str | None = None
    sector_memory: str | None = None       # the H-MEM id behind it
    sector_by_human: bool = False
    prior_verdict: str | None = None
    prior_verdict_memory: str | None = None
    rulings: dict[str, dict] = field(default_factory=dict)   # weakness -> ruling
    sector_priors: list[Recalled] = field(default_factory=list)
    trace: dict = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.memories and not self.sector_priors

    @property
    def ids(self) -> list[str]:
        return [m.id for m in self.memories + self.sector_priors]


def _tag(record: dict, prefix: str) -> str | None:
    for tag in record["tags"]:
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return None


class ScanMemory:
    def __init__(self, persist_dir: str | os.PathLike | None = None, *,
                 clock: Callable[[], int] | None = None, actor: str = "mobius") -> None:
        self.hmem = HMEM(persist_dir=persist_dir or default_memory_dir(), clock=clock,
                         actor=actor, domains=SECURITY_DOMAINS,
                         entity_terms=SECTOR_TERMS, entity_patterns=ENTITY_PATTERNS)

    # -- writing -------------------------------------------------------------

    def _current(self, *tags: str) -> dict | None:
        """The newest live record carrying every tag, if any."""
        live = [r for r in self.hmem.store.all()
                if all(t in r["tags"] for t in tags) and not r.get("supersededBy")]
        return max(live, key=lambda r: (r["timestamp"], int(r["id"].split("-")[1])),
                   default=None)

    def _write(self, content: str, tags: list[str], identity: tuple[str, ...], *,
               type_: str, layer: str, confidence: float, origin: str,
               source: str, run_id: str | None) -> dict:
        previous = self._current(*identity)
        if previous is not None and previous["content"] == content:
            return previous                               # nothing new to say
        now = self.hmem.clock()
        record = self.hmem.add(
            content, source=source, type=type_, layer=layer, tags=tags,
            confidence=confidence, goal_run_id=run_id,
            provenance={"origin": origin, "learnedAt": now, "label": source,
                        **({"refs": [run_id]} if run_id else {})},
            supersedes=previous["id"] if previous else None)
        if previous is not None:
            self.hmem.store.update(previous["id"], {"supersededBy": record["id"]})
        return record

    def remember_sector(self, package: str, sector: str, *, confirmed_by: str,
                        evidence: str = "", run_id: str | None = None) -> dict:
        human = confirmed_by.lower() in _HUMAN
        who = "confirmed by the app owner" if human else f"inferred by {confirmed_by}"
        content = f"{package} is a {sector} app ({who})"
        if evidence:
            content += f": {evidence}"
        return self._write(
            content, ["kind:sector", f"pkg:{package}", f"sector:{sector}",
                      f"by:{'human' if human else 'agent'}"],
            ("kind:sector", f"pkg:{package}"),
            type_="factual", layer="long_term" if human else "working",
            confidence=0.95 if human else 0.6,
            origin="user_correction" if human else "model_response",
            source=f"sector:{confirmed_by}", run_id=run_id)

    def remember_verdict(self, package: str, verdict: str, *, sector: str | None,
                         summary: str, version: str = "",
                         run_id: str | None = None) -> dict:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        content = (f"Scan of {package} {version} on {day}: verdict {verdict}. "
                   f"{summary}").replace("  ", " ")
        tags = ["kind:verdict", f"pkg:{package}", f"verdict:{verdict}"]
        if sector:
            tags.append(f"sector:{sector}")
        record = self.hmem.add(
            content, source="agent:verdict", type="factual", layer="long_term",
            tags=tags, confidence=0.8, goal_run_id=run_id,
            provenance={"origin": "plan_completion", "learnedAt": self.hmem.clock(),
                        "label": "mobius verdict", **({"refs": [run_id]} if run_id else {})})
        return record

    def remember_ruling(self, package: str, weakness_key: str, status: str, *,
                        title: str, reason: str, by: str,
                        sector: str | None = None, run_id: str | None = None) -> dict:
        human = by.lower() in _HUMAN
        content = (f"In {package}, {weakness_key} ({title}) was ruled "
                   f"{status.replace('_', ' ')} by {by}: {reason}")
        tags = ["kind:ruling", f"pkg:{package}", f"weakness:{weakness_key}",
                f"status:{status}"]
        if sector:
            tags.append(f"sector:{sector}")
        return self._write(
            content, tags, ("kind:ruling", f"pkg:{package}", f"weakness:{weakness_key}"),
            type_="factual", layer="long_term" if human else "working",
            confidence=0.9 if human else 0.65,
            origin="user_correction" if human else "model_response",
            source=f"ruling:{by}", run_id=run_id)

    def remember_lesson(self, package: str, lesson: str, *, sector: str | None = None,
                        run_id: str | None = None) -> dict:
        tags = ["kind:lesson", f"pkg:{package}"]
        if sector:
            tags.append(f"sector:{sector}")
        return self.hmem.add(
            lesson, source="agent:critic", type="factual", layer="working",
            tags=tags, confidence=0.6, goal_run_id=run_id,
            provenance={"origin": "model_response", "learnedAt": self.hmem.clock(),
                        "label": "critic lesson"})

    def feedback(self, memory_id: str, kind: str) -> None:
        """helpful / not_helpful / wrong, with the spec's exact deltas."""
        self.hmem.feedback(memory_id, kind)

    # -- reading -------------------------------------------------------------

    def recall(self, package: str, question: str, *, sector: str | None = None,
               top_n: int = 12) -> Recall:
        own = self.hmem.query(
            f"{package} {question}", top_n=top_n, threshold=0.0,
            where=lambda m: f"pkg:{package}" in m["tags"])
        result = Recall(package=package)
        for item in own["memories"]:
            m = item["memory"]
            result.memories.append(Recalled(
                m["id"], _tag(m, "kind:") or "note", m["content"],
                round(item["relevance"], 4), bool(m.get("supersededBy"))))
        live = [i["memory"] for i in own["memories"] if not i["memory"].get("supersededBy")]

        sectors = [m for m in live if "kind:sector" in m["tags"]]
        if sectors:
            best = max(sectors, key=lambda m: ("by:human" in m["tags"], m["timestamp"]))
            result.confirmed_sector = _tag(best, "sector:")
            result.sector_memory = best["id"]
            result.sector_by_human = "by:human" in best["tags"]
        verdicts = [m for m in live if "kind:verdict" in m["tags"]]
        if verdicts:
            last = max(verdicts, key=lambda m: m["timestamp"])
            result.prior_verdict = _tag(last, "verdict:")
            result.prior_verdict_memory = last["id"]
        for m in live:
            if "kind:ruling" in m["tags"]:
                result.rulings[_tag(m, "weakness:")] = {
                    "status": _tag(m, "status:"), "memory": m["id"],
                    "content": m["content"], "human": m["provenance"].get("origin")
                    == "user_correction"}

        lookup_sector = result.confirmed_sector or sector
        context = own["context"]
        if lookup_sector:
            peers = self.hmem.query(
                f"{lookup_sector} app security risks verdict", top_n=5, threshold=0.0,
                where=lambda m: f"sector:{lookup_sector}" in m["tags"]
                and f"pkg:{package}" not in m["tags"] and not m.get("supersededBy"))
            for item in peers["memories"]:
                m = item["memory"]
                result.sector_priors.append(Recalled(
                    m["id"], _tag(m, "kind:") or "note", m["content"],
                    round(item["relevance"], 4)))
            if peers["context"]:
                context = (context + "\n" if context else "") + \
                    peers["context"].replace("[MEMORY CONTEXT]",
                                             f"[SECTOR MEMORY: {lookup_sector}]", 1)
        result.context = context
        result.trace = {"retrievalReason": own["trace"]["retrievalReason"],
                        "strategy": own["trace"]["strategy"],
                        "scores": own["trace"]["scores"]}
        return result
