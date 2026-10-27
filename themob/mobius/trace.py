"""The run trace and the sponsor ledger: how mobius reached its answer.

Every step of a run is an :class:`Event`: which agent acted, what it did, and
which sponsor service did the work, with the reference that proves it (a
Zetaris query id and its SQL, an H-MEM record id, a Nightshift request id and
the model that answered). The trace is written as JSON lines next to the
verdict, and :meth:`RunTrace.ledger` totals it per sponsor, so "mobius depends
on Zetaris, H-MEM and Nemotron" is a count a judge can check, not a claim.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

SPONSORS = ("zetaris", "hmem", "nightshift", "engine")


@dataclass
class Event:
    seq: int
    at_ms: int
    agent: str              # planner / executor / critic / memory / orchestrator
    kind: str               # plan, sql, claim, critique, retry, escalate, recall...
    summary: str
    sponsor: str = "engine"
    ref: str = ""           # query id, memory id, request id
    data: dict = field(default_factory=dict)


class RunTrace:
    def __init__(self, run_id: str, *, clock=None) -> None:
        self.run_id = run_id
        self.events: list[Event] = []
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._listeners: list = []

    def subscribe(self, listener) -> None:
        """Called with each event as it happens (the CLI prints them live)."""
        self._listeners.append(listener)

    def emit(self, agent: str, kind: str, summary: str, *, sponsor: str = "engine",
             ref: str = "", **data) -> Event:
        if sponsor not in SPONSORS:
            raise ValueError(f"unknown sponsor {sponsor!r}")
        event = Event(len(self.events) + 1, self._clock(), agent, kind, summary,
                      sponsor, ref, data)
        self.events.append(event)
        for listener in self._listeners:
            listener(event)
        return event

    def model_call(self, receipt) -> Event:
        """Record one Nightshift request from its receipt."""
        data = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
        status = "ok" if data.get("ok") else f"failed: {data.get('error', '')}"
        return self.emit(data.get("role", "model"), "model_call",
                         f"{data.get('route')} -> {data.get('model')} ({status})",
                         sponsor="nightshift", ref=data.get("request_id", ""), **data)

    # -- totals --------------------------------------------------------------

    def ledger(self) -> dict:
        """Per-sponsor totals: the dependency receipt printed after every run."""
        by = Counter(e.sponsor for e in self.events)
        calls = [e for e in self.events if e.kind == "model_call"]
        answered = [e for e in calls if e.data.get("ok")]   # a failed call has no model
        models = Counter(e.data.get("model", "?") for e in answered)
        nemotron = sum(1 for e in answered if e.data.get("nemotron"))
        sql = [e for e in self.events if e.kind == "sql"]
        tables: set[str] = set()
        for e in sql:
            tables.update(e.data.get("tables", []))
        memory = [e for e in self.events if e.sponsor == "hmem"]
        return {
            "run_id": self.run_id,
            "zetaris": {
                "queries": len(sql),
                "rows": sum(int(e.data.get("row_count", 0)) for e in sql),
                "failed": sum(1 for e in sql if e.data.get("error")),
                "tables": sorted(tables),
            },
            "hmem": {
                "recalls": sum(1 for e in memory if e.kind == "recall"),
                "memories_recalled": sum(len(e.data.get("ids", [])) for e in memory
                                         if e.kind == "recall"),
                "writes": sum(1 for e in memory if e.kind == "remember"),
                "feedback": sum(1 for e in memory if e.kind == "feedback"),
                "plan_changes": sum(1 for e in self.events if e.kind == "memory_applied"),
                "decisions_informed": sum(1 for e in self.events
                                          if e.kind in ("memory_applied", "memory_used")),
            },
            "nightshift": {
                "requests": len(calls),
                "failed": sum(1 for e in calls if not e.data.get("ok")),
                "by_model": dict(models),
                "by_role": dict(Counter(e.data.get("role", "?") for e in calls)),
                "nemotron_share": round(nemotron / len(answered), 3) if answered else 0.0,
                "tokens": sum(int(e.data.get("prompt_tokens", 0))
                              + int(e.data.get("completion_tokens", 0)) for e in calls),
            },
            "loop": {
                "retries": sum(1 for e in self.events if e.kind == "retry"),
                "escalations": sum(1 for e in self.events if e.kind == "escalate"),
                "rejected_claims": sum(1 for e in self.events if e.kind == "reject"),
                "accepted_claims": sum(1 for e in self.events if e.kind == "accept"),
            },
            "events": len(self.events),
            "by_sponsor": dict(by),
        }

    # -- output --------------------------------------------------------------

    def write(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "trace.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(asdict(event), default=str) + "\n")
        (directory / "ledger.json").write_text(
            json.dumps(self.ledger(), indent=2), encoding="utf-8")
        return path


def format_event(event: Event) -> str:
    """One trace line for a terminal: who, which sponsor, what."""
    who = f"{event.agent:<12}"
    via = event.sponsor if not event.ref else f"{event.sponsor} {event.ref[:12]}"
    return f"{event.seq:>3}  {who} [{via:<24}] {event.kind:<14} {event.summary}"


def format_ledger(ledger: dict) -> str:
    z, h, n, loop = ledger["zetaris"], ledger["hmem"], ledger["nightshift"], ledger["loop"]
    models = ", ".join(f"{m} x{c}" for m, c in sorted(n["by_model"].items())) or "none"
    lines = [
        "Sponsor ledger",
        f"  Zetaris     {z['queries']} SQL queries, {z['rows']} rows, "
        f"{z['failed']} failed, over {len(z['tables'])} tables: "
        + (", ".join(z["tables"]) or "none"),
        f"  H-MEM       {h['recalls']} recalls ({h['memories_recalled']} memories), "
        f"{h['decisions_informed']} decisions informed ({h['plan_changes']} plan changes), "
        f"{h['writes']} writes, "
        f"{h['feedback']} feedback updates",
        f"  Nightshift  {n['requests']} requests ({n['failed']} failed), "
        f"{n['tokens']} tokens: {models}",
        f"  NVIDIA      Nemotron handled {round(n['nemotron_share'] * 100)}% of answered requests",
        f"  Loop        {loop['accepted_claims']} accepted, {loop['rejected_claims']} "
        f"rejected, {loop['retries']} retries, {loop['escalations']} escalations",
    ]
    return "\n".join(lines)
