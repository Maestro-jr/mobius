"""H-MEM: hierarchical memory across sessions (a Meterless Engine).

mobius's own Python implementation of the H-MEM spec (Meterless
``engines/hmem/AGENTS.md``), ported from the Apache-2.0 reference so its
arithmetic is identical, and verified by the official conformance runner
through ``engines/hmem/shim/index.ts`` (see ``engines/hmem/README.md``).

What the spec fixes, and this keeps exactly:

* a record with no ``source`` is rejected by construction (section 2);
* retrieval is the canonical hybrid score, confidence multiplied after the
  sum, threshold 0.35 on the final score, top 5 (section 6.1);
* feedback deltas are helpful +0.05 (+1 access), not_helpful -0.03,
  wrong -0.20 plus a ``review`` tag (section 9.2);
* every mutation lands in an append-only trust ledger (section 9.1);
* conflicts mark the loser ``supersededBy`` and never delete, and auto-resolve
  only at decision confidence >= 0.70 (section 10);
* dream proposals never materialize before approval (section 7.4);
* sleep is preview-first, backs up before it acts, and never archives a
  superseding, derived or hub record (section 8).

What mobius adds: the whole engine state, including the conflict queue, the
pending dream proposals and the sleep backups, persists to one directory, so
memory genuinely survives between scans; and the domain vocabulary and entity
patterns are injectable, so a security engine can classify "this is about a
fintech app's TLS handling" without changing the spec's formulas.

Pure stdlib, Qt-free, deterministic under an injected clock.
"""
from __future__ import annotations

import copy
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

# -- operational defaults (section 13) ---------------------------------------

DEFAULTS = {
    "retrieval_top_n": 5,
    "retrieval_threshold": 0.35,
    "consolidation_days": 7,
    "archive_min_days": 30,
    "archive_max_access": 2,
    "synthesis_cosine": 0.82,
    "dream_cluster_min_size": 2,
    "dream_relatedness": 0.35,
    "max_dream_proposals_per_type": 8,
    "conflict_auto_resolve_gate": 0.7,
    "entity_cap": 10,
    "related_cap": 5,
    "recency_days": 14,
}
FEEDBACK_DELTAS = {"helpful": 0.05, "not_helpful": -0.03, "wrong": -0.2}
DAY_MS = 24 * 60 * 60 * 1000
LAYER_WEIGHT = {"long_term": 1.0, "working": 0.8, "short_term": 0.6}
LEDGER_ACTIONS = frozenset((
    "create", "read", "update", "delete", "feedback", "promote", "demote", "merge",
    "conflict_detected", "conflict_resolved", "sleep_consolidate", "sleep_archive",
    "sleep_synthesize", "dream_proposed", "dream_approved", "dream_rejected",
    "restore"))
_HUB_THRESHOLD = 3

# The spec reference's vocabulary. A caller adds its own on top.
TECH_TERMS = ("react", "python", "typescript", "javascript", "rust", "sqlite",
              "postgres", "indexeddb", "node", "docker", "graphql", "redis",
              "webrtc", "tauri", "electron", "llm", "embedding")
DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "tech": ("code", "bug", "api", "database", "deploy", "framework", "library",
             "server") + TECH_TERMS,
    "work": ("meeting", "deadline", "client", "project", "sprint", "review", "report"),
    "personal": ("family", "hobby", "prefer", "like", "dislike", "morning", "evening"),
}

_CORRECTION = re.compile(
    r"\b(actually|instead|no longer|not anymore|changed to|correction)\b", re.I)
_CAPITALISED = re.compile(r"\b([A-Z][a-zA-Z]{2,})\b")
_NUMBER = re.compile(r"\d+(\.\d+)?")
_OPPOSING_PAIRS = (
    (re.compile(r"\balways\b", re.I), re.compile(r"\bnever\b", re.I)),
    (re.compile(r"\benable[ds]?\b", re.I), re.compile(r"\bdisable[ds]?\b", re.I)),
    (re.compile(r"\bprefer[s]?\b", re.I), re.compile(r"\bavoid[s]?|dislike[s]?\b", re.I)),
    (re.compile(r"\bon\b", re.I), re.compile(r"\boff\b", re.I)),
    (re.compile(r"\byes\b", re.I), re.compile(r"\bno\b", re.I)),
)
_EVENT_TYPE = {"chat_message": "general", "user_correction": "preference",
               "file_save": "factual", "file_open": "general", "file_edit": "factual",
               "model_response": "factual", "plan_completion": "factual"}
_SIGNAL = re.compile(r"\b(prefer|always|never|decided|chose|choose|use|because|"
                     r"instead|must|should|important|remember)\b", re.I)


def clamp01(x: float) -> float:
    return min(1.0, max(0.0, x))


# -- the deterministic embedder (reference embeddings.ts) --------------------

_DIM = 64


def tokenize(text: str) -> list[str]:
    cleaned = re.sub(r"[^a-z0-9\s]", " ", text.lower())
    return [t for t in re.split(r"\s+", cleaned) if len(t) > 1]


def _fnv1a(text: str) -> int:
    h = 0x811C9DC5
    for ch in text:
        h ^= ord(ch)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def embed(text: str) -> list[float]:
    """FNV-1a per token into 64 dims, summed and L2-normalised.

    A pure function of the text, so recall is reproducible on any machine and
    in sample mode. The contract is only ``text -> vector``; a real embedder
    can replace it without touching the formulas.
    """
    vec = [0.0] * _DIM
    for token in tokenize(text):
        h = _fnv1a(token)
        sign = 1 if (h >> 8) % 2 == 0 else -1
        vec[h % _DIM] += sign * (1 + ((h >> 16) % 8) / 8)
    norm = math.sqrt(sum(v * v for v in vec))
    return vec if norm == 0 else [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))     # both are unit length


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / (len(sa) + len(sb) - inter)


def snapshot(record: dict) -> dict:
    """A record without its embedding, for the ledger."""
    return {k: copy.deepcopy(v) for k, v in record.items() if k != "embedding"}


# -- shared state -------------------------------------------------------------

@dataclass
class _Context:
    clock: Callable[[], int]
    actor: str
    persist_dir: Path | None
    domains: dict[str, tuple[str, ...]]
    entity_terms: tuple[str, ...]
    entity_patterns: tuple[re.Pattern, ...]
    save: Callable[[], None] = field(default=lambda: None)


class TrustLedger:
    """Append-only audit ledger (section 9.1). Entries are never rewritten."""

    def __init__(self, ctx: _Context) -> None:
        self._ctx = ctx
        self._entries: list[dict] = []
        self._file = ctx.persist_dir / "ledger.jsonl" if ctx.persist_dir else None
        if self._file and self._file.exists():
            with self._file.open(encoding="utf-8") as handle:
                self._entries = [json.loads(line) for line in handle if line.strip()]

    def log(self, memory_id: str, action: str, actor: str | None = None, *,
            previous_state: dict | None = None, new_state: dict | None = None,
            details: dict | None = None) -> dict:
        if action not in LEDGER_ACTIONS:
            raise ValueError(f"H-MEM: {action!r} is not one of the 17 ledger actions")
        entry: dict = {"memoryId": memory_id, "action": action,
                       "actor": actor or self._ctx.actor,
                       "timestamp": self._ctx.clock()}
        if previous_state is not None:
            entry["previousState"] = previous_state
        if new_state is not None:
            entry["newState"] = new_state
        if details is not None:
            entry["details"] = details
        self._entries.append(entry)
        if self._file:
            with self._file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        return entry

    def history(self, memory_id: str) -> list[dict]:
        return [e for e in self._entries if e["memoryId"] == memory_id]

    def all(self) -> list[dict]:
        return list(self._entries)

    def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for entry in self._entries:
            out[entry["action"]] = out.get(entry["action"], 0) + 1
        return out


class MemoryStore:
    """Tiered storage with enrichment (sections 2, 3 and 5)."""

    def __init__(self, ctx: _Context, ledger: TrustLedger) -> None:
        self._ctx = ctx
        self._ledger = ledger
        self.records: dict[str, dict] = {}
        self.seq = 0

    def add(self, content: str, *, source: str, type: str = "general",   # noqa: A002
            layer: str = "working", tags: list[str] | None = None,
            confidence: float | None = None, provenance: dict | None = None,
            chat_id: str | None = None, mission_id: str | None = None,
            goal_run_id: str | None = None, supersedes: str | None = None,
            derived_from: list[str] | None = None) -> dict:
        if not source or not source.strip():
            raise ValueError("H-MEM: a memory record with no source must be "
                             "rejected by construction (AGENTS.md section 2)")
        now = self._ctx.clock()
        self.seq += 1
        record_id = f"mem-{self.seq}"
        tags = list(tags or [])
        domain = self.classify_domain(content, tags, type)
        record = {
            "id": record_id, "content": content, "type": type, "layer": layer,
            "timestamp": now, "lastAccessed": now, "accessCount": 0, "tags": tags,
            "embedding": embed(content),
            "confidence": clamp01(0.7 if confidence is None else confidence),
            "source": source,
            "provenance": provenance or {"origin": "manual", "learnedAt": now,
                                         "label": source},
            "chatId": chat_id, "missionId": mission_id, "goalRunId": goal_run_id,
            "domain": domain, "namespace": self._namespace(domain, type),
            "entities": self.extract_entities(content), "relatedTo": [],
            "supersedes": supersedes, "supersededBy": None,
            "derivedFrom": derived_from,
        }
        self._discover_relationships(record)
        self.records[record_id] = record
        self._ledger.log(record_id, "create", new_state=snapshot(record))
        self._ctx.save()
        return record

    def get(self, record_id: str) -> dict | None:
        return self.records.get(record_id)

    def all(self) -> list[dict]:
        return list(self.records.values())

    def update(self, record_id: str, patch: dict) -> dict:
        record = self._must(record_id)
        previous = snapshot(record)
        record.update(patch)
        self._ledger.log(record_id, "update", previous_state=previous,
                         new_state=snapshot(record))
        self._ctx.save()
        return record

    def delete(self, record_id: str, reason: str) -> None:
        record = self._must(record_id)
        del self.records[record_id]
        self._ledger.log(record_id, "delete", previous_state=snapshot(record),
                         details={"reason": reason})
        self._ctx.save()

    def touch(self, record_id: str) -> None:
        record = self._must(record_id)
        record["lastAccessed"] = self._ctx.clock()
        record["accessCount"] += 1

    def promote(self, record_id: str, layer: str) -> None:
        record = self._must(record_id)
        previous = snapshot(record)
        record["layer"] = layer
        self._ledger.log(record_id, "promote", previous_state=previous,
                         new_state=snapshot(record))
        self._ctx.save()

    def _must(self, record_id: str) -> dict:
        record = self.records.get(record_id)
        if record is None:
            raise KeyError(f"H-MEM: unknown memory id {record_id}")
        return record

    # -- enrichment ---------------------------------------------------------

    def classify_domain(self, content: str, tags: list[str], type_: str) -> str:
        for tag in tags:
            if tag.startswith("project:"):
                return tag[len("project:"):]
            if tag.startswith("tech:"):
                return "tech"
        tokens = set(tokenize(content))
        best, best_score = "general", 0
        for domain, keywords in self._ctx.domains.items():
            score = sum(1 for kw in keywords if kw in tokens)
            if domain == "personal" and type_ in ("personal", "preference"):
                score += 1
            if score > best_score:
                best, best_score = domain, score
        return best if best_score > 0 else "general"

    @staticmethod
    def _namespace(domain: str, type_: str) -> str:
        bucket = ("profile" if type_ in ("preference", "personal")
                  else "facts" if type_ == "factual" else "notes")
        return f"{domain}/{bucket}"

    def extract_entities(self, content: str) -> list[str]:
        entities: dict[str, None] = {}
        for token in tokenize(content):
            if token in self._ctx.entity_terms:
                entities[token] = None
        for pattern in self._ctx.entity_patterns:
            for match in pattern.finditer(content):
                entities[match.group(0).lower()] = None
        for match in _CAPITALISED.finditer(content):
            norm = match.group(1).lower()
            if norm not in ("the", "this", "that", "with"):
                entities[norm] = None
        return list(entities)[:DEFAULTS["entity_cap"]]

    def _discover_relationships(self, record: dict) -> None:
        for other in self.records.values():
            if len(record["relatedTo"]) >= DEFAULTS["related_cap"]:
                break
            shared = [e for e in other["entities"] if e in record["entities"]]
            sim = cosine(record["embedding"], other["embedding"])
            if not record["supersedes"] and sim > 0.85 \
                    and _CORRECTION.search(record["content"]):
                record["supersedes"] = other["id"]
                continue
            if shared and other["domain"] == record["domain"]:
                record["relatedTo"].append(other["id"])
                if len(other["relatedTo"]) < DEFAULTS["related_cap"] \
                        and record["id"] not in other["relatedTo"]:
                    other["relatedTo"].append(record["id"])     # bidirectional


class MemoryRetrieval:
    """Hybrid ranking and reinjection (section 6), feedback (section 9.2)."""

    def __init__(self, ctx: _Context, store: MemoryStore, ledger: TrustLedger) -> None:
        self._ctx, self._store, self._ledger = ctx, store, ledger

    def _score(self, m: dict, q_embedding, q_tokens, q_entities, q_domain) -> float:
        semantic = clamp01(cosine(q_embedding, m["embedding"]))
        keyword = jaccard(q_tokens, tokenize(m["content"]))
        tag = jaccard(q_tokens, [t.lower() for t in m["tags"]])
        domain = 1 if m["domain"] == q_domain else 0
        entity = jaccard(q_entities, m["entities"])
        layer = LAYER_WEIGHT[m["layer"]]
        age_days = (self._ctx.clock() - m["lastAccessed"]) / DAY_MS
        recency = math.exp(-age_days / DEFAULTS["recency_days"])
        superseded = 1 if m.get("supersededBy") else 0
        raw = (0.35 * semantic + 0.2 * keyword + 0.1 * tag + 0.1 * domain
               + 0.15 * entity + 0.05 * layer + 0.05 * recency - 0.2 * superseded)
        return clamp01(raw) * m["confidence"]

    def query(self, query: str, *, top_n: int | None = None,
              threshold: float | None = None, chat_id: str | None = None,
              where: Callable[[dict], bool] | None = None) -> dict:
        q_embedding = embed(query)
        q_tokens = tokenize(query)[:8]
        q_entities = self._store.extract_entities(query)
        q_domain = self._store.classify_domain(query, [], "general")
        threshold = DEFAULTS["retrieval_threshold"] if threshold is None else threshold
        top_n = DEFAULTS["retrieval_top_n"] if top_n is None else top_n
        scored = []
        for m in self._store.all():
            if chat_id and m.get("chatId") and m["chatId"] != chat_id:
                continue
            if where is not None and not where(m):
                continue
            score = self._score(m, q_embedding, q_tokens, q_entities, q_domain)
            if score >= threshold:
                scored.append({"memory": m, "relevance": score})
        scored.sort(key=lambda r: (-r["relevance"], r["memory"]["id"]))
        top = scored[:top_n]
        for item in top:
            self._store.touch(item["memory"]["id"])
            self._ledger.log(item["memory"]["id"], "read", details={"query": query})
        if top:
            self._ctx.save()
        if len(top) <= 1:
            strategy = "minimal"
        elif any(t["memory"]["type"] in ("personal", "preference") for t in top):
            strategy = "personal"
        else:
            strategy = "comprehensive"
        return {
            "memories": top,
            "context": self.format_reinjection(top),
            "trace": {
                "retrievalReason": f'hybrid ranking for "{query}" (domain: {q_domain})',
                "strategy": strategy,
                "scores": {t["memory"]["id"]: round(t["relevance"], 4) for t in top},
            },
        }

    @staticmethod
    def format_reinjection(items: list[dict]) -> str:
        if not items:
            return ""
        by_domain: dict[str, list[dict]] = {}
        for item in items:
            by_domain.setdefault(item["memory"]["domain"], []).append(item)
        lines = ["[MEMORY CONTEXT]"]
        for domain in sorted(by_domain):
            lines.append(f"## {domain}")
            for item in by_domain[domain]:
                m = item["memory"]
                marker = {"long_term": "LT", "working": "WK"}.get(m["layer"], "ST")
                ents = f" (entities: {', '.join(m['entities'])})" if m["entities"] else ""
                lines.append(f"- [{marker}] {m['content']}{ents} <{m['id']}>")
        lines.append("[/MEMORY CONTEXT]")
        return "\n".join(lines)

    def feedback(self, memory_id: str, kind: str) -> None:
        if kind not in FEEDBACK_DELTAS:
            raise ValueError(f"H-MEM: unknown feedback kind {kind!r}")
        m = self._store.get(memory_id)
        if m is None:
            raise KeyError(f"H-MEM: unknown memory id {memory_id}")
        previous = snapshot(m)
        if kind == "helpful":
            m["accessCount"] += 1
        m["confidence"] = clamp01(m["confidence"] + FEEDBACK_DELTAS[kind])
        if kind == "wrong" and "review" not in m["tags"]:
            m["tags"].append("review")
        self._ledger.log(memory_id, "feedback", previous_state=previous,
                         new_state=snapshot(m),
                         details={"kind": kind, "delta": FEEDBACK_DELTAS[kind]})
        self._ctx.save()


class ConflictDetection:
    """Contradiction scan and the 0.70 auto-resolve gate (section 10)."""

    def __init__(self, ctx: _Context, store: MemoryStore, ledger: TrustLedger) -> None:
        self._ctx, self._store, self._ledger = ctx, store, ledger
        self.conflicts: list[dict] = []
        self.seq = 0

    def scan(self) -> list[dict]:
        found = []
        records = self._store.all()
        for i, a in enumerate(records):
            for b in records[i + 1:]:
                conflict = self._check(a, b)
                if conflict:
                    found.append(conflict)
                    self.conflicts.append(conflict)
                    self._ledger.log(conflict["memoryA"], "conflict_detected", details={
                        "with": conflict["memoryB"], "reason": conflict["reason"],
                        "confidence": conflict["confidence"]})
        if found:
            self._ctx.save()
        return found

    def _check(self, a: dict, b: dict) -> dict | None:
        if a["id"] in (b.get("supersedes"), b.get("supersededBy")) \
                or b["id"] in (a.get("supersedes"), a.get("supersededBy")):
            return None                          # an intended replacement
        sim = cosine(a["embedding"], b["embedding"])
        reason, confidence = "", 0.0
        for p, q in _OPPOSING_PAIRS:
            if (p.search(a["content"]) and q.search(b["content"])) or \
                    (q.search(a["content"]) and p.search(b["content"])):
                if sim > 0.5:
                    reason = "opposing phrase pair on similar content"
                    confidence = 0.5 + 0.3 * sim
        if not reason and sim > 0.8:
            nums_a = [m.group(0) for m in _NUMBER.finditer(a["content"])]
            nums_b = [m.group(0) for m in _NUMBER.finditer(b["content"])]
            if nums_a and nums_b and ",".join(nums_a) != ",".join(nums_b):
                reason = "high-similarity conflicting numeric values"
                confidence = 0.55 + 0.25 * sim
        if not reason:
            return None
        if any(e in b["entities"] for e in a["entities"]):
            confidence += 0.1
        if a["domain"] == b["domain"]:
            confidence += 0.05
        if b["id"] in a["relatedTo"]:
            confidence -= 0.1
        self.seq += 1
        return {"id": f"conflict-{self.seq}", "memoryA": a["id"], "memoryB": b["id"],
                "reason": reason, "confidence": clamp01(confidence),
                "resolved": False, "resolution": None}

    def auto_resolve(self, conflict: dict) -> str:
        conflict = self._own(conflict)
        a = self._store.get(conflict["memoryA"])
        b = self._store.get(conflict["memoryB"])
        now = max(1, self._ctx.clock())

        def score_of(m: dict) -> float:
            origin = (m.get("provenance") or {}).get("origin")
            return (0.3 * (m["lastAccessed"] / now)
                    + 0.2 * min(1, m["accessCount"] / 10)
                    + 0.25 * m["confidence"]
                    + 0.1 * min(1, len(m["content"]) / 200)
                    + 0.15 * (1 if origin == "user_correction" else 0.5))
        sa, sb = score_of(a), score_of(b)
        margin = abs(sa - sb) / max(sa, sb)
        decision = clamp01(conflict["confidence"] * 0.6 + margin * 0.8)
        if decision < DEFAULTS["conflict_auto_resolve_gate"]:
            return "queued"
        winner, loser = (a, b) if sa >= sb else (b, a)
        previous = snapshot(loser)
        loser["supersededBy"] = winner["id"]          # kept, penalised, never deleted
        conflict["resolved"] = True
        conflict["resolution"] = "keep_a" if winner["id"] == conflict["memoryA"] else "keep_b"
        self._ledger.log(loser["id"], "conflict_resolved", previous_state=previous,
                         new_state=snapshot(loser), details={
                             "conflictId": conflict["id"], "winner": winner["id"],
                             "decisionConfidence": round(decision, 3)})
        self._ctx.save()
        return "resolved"

    def queue(self) -> list[dict]:
        return [c for c in self.conflicts if not c["resolved"]]

    def _own(self, conflict: dict) -> dict:
        """The stored conflict with this id (a caller may pass a copy)."""
        for stored in self.conflicts:
            if stored["id"] == conflict.get("id"):
                return stored
        return conflict


class SleepCycle:
    """Preview-first consolidation, archival and synthesis (section 8)."""

    def __init__(self, ctx: _Context, store: MemoryStore, ledger: TrustLedger) -> None:
        self._ctx, self._store, self._ledger = ctx, store, ledger
        self.backups: dict[str, dict] = {}
        self.backup_seq = 0

    def preview(self) -> dict:
        now = self._ctx.clock()
        records = self._store.all()
        referenced: set[str] = set()
        for m in records:
            referenced.update(m["relatedTo"])
            if m.get("supersedes"):
                referenced.add(m["supersedes"])
            referenced.update(m.get("derivedFrom") or [])
        to_consolidate = [
            m["id"] for m in records if m["layer"] == "short_term"
            and now - m["lastAccessed"] >= DEFAULTS["consolidation_days"] * DAY_MS]
        to_archive = []
        for m in records:
            old = now - m["timestamp"] >= DEFAULTS["archive_min_days"] * DAY_MS
            low = m["accessCount"] <= DEFAULTS["archive_max_access"]
            if not (old and low and m["id"] not in referenced):
                continue
            if m.get("supersedes") or (m.get("derivedFrom") or []) \
                    or len(m["relatedTo"]) >= _HUB_THRESHOLD:
                continue                             # the three guardrails
            to_archive.append(m["id"])
        to_synthesize: list[list[str]] = []
        used: set[str] = set()
        for i, first in enumerate(records):
            if first["id"] in used:
                continue
            group = [first]
            for other in records[i + 1:]:
                if other["id"] not in used and cosine(
                        first["embedding"], other["embedding"]) >= DEFAULTS["synthesis_cosine"]:
                    group.append(other)
            if len(group) >= 2:
                used.update(g["id"] for g in group)
                to_synthesize.append([g["id"] for g in group])
        return {"toConsolidate": to_consolidate, "toArchive": to_archive,
                "toSynthesize": to_synthesize}

    def execute(self, preview: dict | None = None) -> dict:
        plan = preview or self.preview()
        self.backup_seq += 1
        backup_id = f"backup-{self.backup_seq}"
        self.backups[backup_id] = {"records": copy.deepcopy(self._store.all()),
                                   "seq": self._store.seq}
        log = [f"backup {backup_id} created"]
        for rid in plan["toConsolidate"]:
            if self._store.get(rid) is None:
                continue
            self._store.promote(rid, "long_term")
            self._ledger.log(rid, "sleep_consolidate",
                             details={"from": "short_term", "to": "long_term"})
            log.append(f"consolidated {rid}")
        for rid in plan["toArchive"]:
            m = self._store.get(rid)
            if m is None:
                continue
            self._ledger.log(rid, "sleep_archive", details={
                "age": self._ctx.clock() - m["timestamp"], "accessCount": m["accessCount"]})
            self._store.delete(rid, "sleep archive")
            log.append(f"archived {rid}")
        synthesized = 0
        for group in plan["toSynthesize"]:
            members = [m for m in (self._store.get(r) for r in group) if m]
            if len(members) < 2:
                continue
            merged = self._store.add(
                "Synthesis: " + " | ".join(m["content"] for m in members),
                type="factual", layer="long_term",
                tags=list(dict.fromkeys(t for m in members for t in m["tags"])),
                confidence=max(m["confidence"] for m in members),
                source="sleep:synthesis",
                provenance={"origin": "sleep_synthesis", "learnedAt": self._ctx.clock(),
                            "label": f"synthesized from {len(members)} memories"},
                derived_from=[m["id"] for m in members])
            self._ledger.log(merged["id"], "sleep_synthesize", details={"sources": group})
            for m in members:
                self._store.delete(m["id"], "merged by sleep synthesis")
            synthesized += 1
            log.append(f"synthesized {merged['id']} from {', '.join(group)}")
        self._ctx.save()
        return {"backupId": backup_id, "consolidated": len(plan["toConsolidate"]),
                "archived": len(plan["toArchive"]), "synthesized": synthesized,
                "actionLog": log}

    def restore(self, backup_id: str) -> None:
        backup = self.backups.get(backup_id)
        if backup is None:
            raise KeyError(f"H-MEM: unknown backup {backup_id}")
        self._store.records = {r["id"]: copy.deepcopy(r) for r in backup["records"]}
        self._store.seq = backup["seq"]
        self._ledger.log("*", "restore", details={"backupId": backup_id})
        self._ctx.save()


class Dreaming:
    """Clustered synthesis behind a human approval boundary (section 7)."""

    def __init__(self, ctx: _Context, store: MemoryStore, ledger: TrustLedger) -> None:
        self._ctx, self._store, self._ledger = ctx, store, ledger
        self.proposals: dict[str, dict] = {}
        self.seq = 0

    @staticmethod
    def _relatedness(a: dict, b: dict) -> float:
        return (0.5 * max(0.0, cosine(a["embedding"], b["embedding"]))
                + 0.2 * jaccard(a["tags"], b["tags"])
                + 0.1 * (1 if a["domain"] == b["domain"] else 0)
                + 0.2 * jaccard(a["entities"], b["entities"]))

    def _cluster(self) -> list[list[dict]]:
        records = self._store.all()
        used: set[str] = set()
        clusters = []
        for seed in records:
            if seed["id"] in used:
                continue
            group = [seed] + [o for o in records if o["id"] != seed["id"]
                              and o["id"] not in used
                              and self._relatedness(seed, o) >= DEFAULTS["dream_relatedness"]]
            if len(group) >= DEFAULTS["dream_cluster_min_size"]:
                used.update(g["id"] for g in group)
                clusters.append(group)
        return clusters

    def dream(self) -> list[dict]:
        created: list[dict] = []
        cap = DEFAULTS["max_dream_proposals_per_type"]

        def propose(**proposal) -> None:
            self.seq += 1
            proposal.update(id=f"dream-{self.seq}", status="proposed")
            self.proposals[proposal["id"]] = proposal
            created.append(proposal)
            self._ledger.log(proposal["id"], "dream_proposed", details={
                "type": proposal["type"], "derivedFrom": proposal["derivedFrom"]})

        for cluster in self._cluster()[:cap]:
            domains = "/".join(dict.fromkeys(m["domain"] for m in cluster))
            propose(type="insight",
                    content=f"Across {len(cluster)} related memories ({domains}): "
                            + " + ".join(m["content"] for m in cluster),
                    derivedFrom=[m["id"] for m in cluster])
        domains_made = 0
        for m in self._store.all():
            if domains_made >= cap:
                break
            if m["domain"] != "general":
                continue
            suggested = self._store.classify_domain(m["content"], m["tags"], m["type"])
            if suggested != "general":
                propose(type="domain",
                        content=f'Reclassify "{m["content"][:60]}" as {suggested}',
                        derivedFrom=[m["id"]], suggestedDomain=suggested)
                domains_made += 1
        by_domain: dict[str, list[dict]] = {}
        for m in self._store.all():
            if m["type"] in ("preference", "personal") \
                    or "event:user_correction" in m["tags"]:
                by_domain.setdefault(m["domain"], []).append(m)
        invariants = 0
        for domain, items in by_domain.items():
            if invariants >= cap:
                break
            if len(items) < 2:
                continue
            propose(type="invariant",
                    content=f"Stable pattern in {domain}: "
                            + "; ".join(m["content"] for m in items),
                    derivedFrom=[m["id"] for m in items])
            invariants += 1
        if created:
            self._ctx.save()
        return created

    def pending(self) -> list[dict]:
        return [p for p in self.proposals.values() if p["status"] == "proposed"]

    def _pending(self, proposal_id: str) -> dict:
        proposal = self.proposals.get(proposal_id)
        if proposal is None or proposal["status"] != "proposed":
            raise KeyError(f"H-MEM: no pending proposal {proposal_id}")
        return proposal

    def approve(self, proposal_id: str) -> dict | None:
        proposal = self._pending(proposal_id)
        proposal["status"] = "approved"
        self._ledger.log(proposal_id, "dream_approved", details={"type": proposal["type"]})
        if proposal["type"] == "domain":
            for rid in proposal["derivedFrom"]:
                if self._store.get(rid) and proposal.get("suggestedDomain"):
                    self._store.update(rid, {"domain": proposal["suggestedDomain"]})
            self._ctx.save()
            return None
        return self._store.add(
            proposal["content"],
            type="factual" if proposal["type"] == "insight" else "preference",
            layer="long_term", tags=[f"dream:{proposal['type']}"], confidence=0.75,
            source="dreaming",
            provenance={"origin": "dream", "learnedAt": self._ctx.clock(),
                        "label": f"approved {proposal['type']} proposal"},
            derived_from=proposal["derivedFrom"])

    def reject(self, proposal_id: str) -> None:
        proposal = self._pending(proposal_id)
        proposal["status"] = "rejected"                    # logged, not materialized
        self._ledger.log(proposal_id, "dream_rejected", details={"type": proposal["type"]})
        self._ctx.save()


def parse_strict_json_array(raw: str) -> list[str]:
    """Tolerant parse of a model's JSON array of memories (section 4.1 step 3)."""
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.I)
    cleaned = re.sub(r"```\s*$", "", cleaned).strip()
    start, end = cleaned.find("["), cleaned.rfind("]")
    if start != -1 and end > start:
        cleaned = cleaned[start:end + 1]
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [x for x in parsed if isinstance(x, str) and len(x.strip()) >= 5]


class MemoryMining:
    """Acquisition with a model-free fallback (section 4)."""

    def __init__(self, ctx: _Context, store: MemoryStore,
                 miner: Callable[[str], str] | None) -> None:
        self._ctx, self._store, self._miner = ctx, store, miner

    def mine_interaction(self, event: str, text: str, *, chat_id: str | None = None,
                         layer: str | None = None) -> list[dict]:
        candidates = self._with_model(event, text) if self._miner else self.model_free(text)
        return [self._store.add(
            content, type=_EVENT_TYPE[event],
            layer=layer or ("working" if self._miner else "short_term"),
            tags=[f"event:{event}"], source=f"interaction:{event}",
            provenance={"origin": event, "learnedAt": self._ctx.clock(),
                        "label": f"mined from {event}"},
            chat_id=chat_id) for content in candidates]

    @staticmethod
    def model_free(text: str) -> list[str]:
        parts = (s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text))
        return [s for s in parts if 20 <= len(s) <= 300 and _SIGNAL.search(s)][:10]

    def _with_model(self, event: str, text: str) -> list[str]:
        prompt = ("Extract durable memories from this "
                  f"{event} as a strict JSON array of strings:\n\n{text}")
        try:
            return parse_strict_json_array(self._miner(prompt))
        except Exception:                                    # noqa: BLE001
            return self.model_free(text)      # graceful degradation (section 1)


class HMEM:
    """The H-MEM facade: ``add``, ``query``, ``feedback`` and the services.

    ``persist_dir`` makes the whole engine durable: ``state.json`` holds the
    records and every service's state, ``ledger.jsonl`` the audit trail.
    """

    def __init__(self, *, clock: Callable[[], int] | None = None,
                 persist_dir: str | os.PathLike | None = None, actor: str = "system",
                 miner: Callable[[str], str] | None = None,
                 domains: dict[str, Iterable[str]] | None = None,
                 entity_terms: Iterable[str] = (),
                 entity_patterns: Iterable[str] = ()) -> None:
        import time
        merged = {k: tuple(v) for k, v in DOMAIN_KEYWORDS.items()}
        for name, words in (domains or {}).items():
            merged[name] = tuple(merged.get(name, ())) + tuple(words)
        directory = Path(persist_dir) if persist_dir else None
        if directory:
            directory.mkdir(parents=True, exist_ok=True)
        self._ctx = _Context(
            clock=clock or (lambda: int(time.time() * 1000)), actor=actor,
            persist_dir=directory, domains=merged,
            entity_terms=TECH_TERMS + tuple(t.lower() for t in entity_terms),
            entity_patterns=tuple(re.compile(p) for p in entity_patterns))
        self.ledger = TrustLedger(self._ctx)
        self.store = MemoryStore(self._ctx, self.ledger)
        self.retrieval = MemoryRetrieval(self._ctx, self.store, self.ledger)
        self.conflicts = ConflictDetection(self._ctx, self.store, self.ledger)
        self.sleep = SleepCycle(self._ctx, self.store, self.ledger)
        self.dreaming = Dreaming(self._ctx, self.store, self.ledger)
        self.mining = MemoryMining(self._ctx, self.store, miner)
        self._load()
        self._ctx.save = self._save

    @property
    def clock(self) -> Callable[[], int]:
        return self._ctx.clock

    def add(self, content: str, **kwargs) -> dict:
        return self.store.add(content, **kwargs)

    def query(self, query: str, **kwargs) -> dict:
        return self.retrieval.query(query, **kwargs)

    def feedback(self, memory_id: str, kind: str) -> None:
        self.retrieval.feedback(memory_id, kind)

    def mine(self, event: str, text: str, **kwargs) -> list[dict]:
        return self.mining.mine_interaction(event, text, **kwargs)

    # -- persistence -------------------------------------------------------

    def _state_file(self) -> Path | None:
        return self._ctx.persist_dir / "state.json" if self._ctx.persist_dir else None

    def _load(self) -> None:
        path = self._state_file()
        if path is None or not path.exists():
            return
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.store.seq = saved.get("seq", 0)
        self.store.records = {r["id"]: r for r in saved.get("records", [])}
        self.conflicts.conflicts = saved.get("conflicts", [])
        self.conflicts.seq = saved.get("conflictSeq", 0)
        self.dreaming.proposals = {p["id"]: p for p in saved.get("proposals", [])}
        self.dreaming.seq = saved.get("dreamSeq", 0)
        self.sleep.backups = saved.get("backups", {})
        self.sleep.backup_seq = saved.get("backupSeq", 0)

    def _save(self) -> None:
        path = self._state_file()
        if path is None:
            return
        state = {
            "seq": self.store.seq,
            "records": sorted(self.store.records.values(), key=lambda r: r["id"]),
            "conflicts": self.conflicts.conflicts,
            "conflictSeq": self.conflicts.seq,
            "proposals": list(self.dreaming.proposals.values()),
            "dreamSeq": self.dreaming.seq,
            "backups": self.sleep.backups,
            "backupSeq": self.sleep.backup_seq,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
        os.replace(tmp, path)
