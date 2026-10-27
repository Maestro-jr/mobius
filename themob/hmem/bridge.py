"""A JSON bridge so the official H-MEM conformance runner can drive this engine.

The runner is TypeScript and calls the engine synchronously, so the shim at
``engines/hmem/shim/index.ts`` runs one ``python -m themob.hmem.bridge`` per
call: the request ``{dir, now, op, args}`` arrives on stdin, the engine loads
its persisted state from ``dir`` with the clock pinned to ``now``, runs the one
operation, saves, and prints ``{"ok": result}`` or ``{"error": message}``.
Because the engine persists every service's state, a sequence of separate
processes behaves exactly like one long-lived instance.
"""
from __future__ import annotations

import json
import sys

from .engine import HMEM


def _public(value):
    """Strip embeddings from anything returned to the runner."""
    if isinstance(value, dict):
        return {k: _public(v) for k, v in value.items() if k != "embedding"}
    if isinstance(value, list):
        return [_public(v) for v in value]
    return value


def _add_kwargs(args: dict) -> dict:
    names = {"type": "type", "layer": "layer", "tags": "tags",
             "confidence": "confidence", "provenance": "provenance",
             "chatId": "chat_id", "missionId": "mission_id",
             "goalRunId": "goal_run_id", "supersedes": "supersedes",
             "derivedFrom": "derived_from"}
    return {py: args[js] for js, py in names.items() if args.get(js) is not None}


def run(request: dict):
    now = int(request["now"])
    hmem = HMEM(clock=lambda: now, persist_dir=request["dir"])
    op, args = request["op"], request.get("args") or {}
    if op == "add":
        return hmem.add(args.get("content", ""), source=args.get("source") or "",
                        **_add_kwargs(args))
    if op == "query":
        opts = args.get("opts") or {}
        return hmem.query(args["query"], top_n=opts.get("topN"),
                          threshold=opts.get("threshold"), chat_id=opts.get("chatId"))
    if op == "feedback":
        return hmem.feedback(args["id"], args["kind"])
    if op == "store.get":
        return hmem.store.get(args["id"])
    if op == "store.all":
        return hmem.store.all()
    if op == "store.update":
        return hmem.store.update(args["id"], args["patch"])
    if op == "ledger.history":
        return hmem.ledger.history(args["id"])
    if op == "ledger.stats":
        return hmem.ledger.stats()
    if op == "sleep.preview":
        return hmem.sleep.preview()
    if op == "sleep.execute":
        return hmem.sleep.execute(args.get("preview"))
    if op == "conflicts.scan":
        return hmem.conflicts.scan()
    if op == "conflicts.autoResolve":
        return hmem.conflicts.auto_resolve(args["conflict"])
    if op == "dreaming.dream":
        return hmem.dreaming.dream()
    if op == "dreaming.approve":
        return hmem.dreaming.approve(args["id"])
    raise ValueError(f"unknown H-MEM bridge op {op!r}")


def main() -> int:
    try:
        result = run(json.loads(sys.stdin.read()))
        sys.stdout.write(json.dumps({"ok": _public(result)}))
    except Exception as exc:                                  # noqa: BLE001
        sys.stdout.write(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
