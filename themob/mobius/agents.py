"""The three agents: Planner, Executor, Critic.

Each role runs on its own Nightshift lane, so the trace shows which model did
what and the Critic never grades its own output:

* **Planner** (deep lane, e.g. Nemotron Super): reads the H-MEM recall and a
  first look at the app through Zetaris, guesses the sector, and writes the
  investigations. Also writes the final verdict and adjudicates escalations.
* **Executor** (fast lane, e.g. Nemotron Lightning): answers one investigation
  with its single tool, ``run_sql`` against Zetaris, and returns a claim that
  cites the query ids it saw.
* **Critic** (judge lane): deterministic evidence rules first (cited queries
  exist and returned rows, high severity is corroborated, a remembered human
  ruling is not silently contradicted, KEV status is re-checked through
  Zetaris), then a model judgement. It accepts, sends the claim back with a
  concrete hint, or escalates.

Every model reply is JSON; one malformed reply is re-asked once (a recovery
the trace records) before the step fails.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .catalog import schema_prompt
from .datalayer import DataLayerError, SqlResult, tables_in
from .trace import RunTrace

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SECTORS = ("fintech", "health", "education", "kids", "ecommerce", "government",
           "social", "general")


# -- talking to the lanes -------------------------------------------------------

@dataclass
class Lanes:
    planner: str
    executor: str
    critic: str

    @classmethod
    def from_env(cls, default: str) -> "Lanes":
        import os
        return cls(os.environ.get("MOBIUS_PLANNER_MODEL") or default,
                   os.environ.get("MOBIUS_EXECUTOR_MODEL") or default,
                   os.environ.get("MOBIUS_CRITIC_MODEL") or default)


class ModelError(RuntimeError):
    pass


def parse_json(text: str) -> dict:
    """The JSON object in a model reply: fences, think blocks and chatter tolerated."""
    cleaned = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    cleaned = re.sub(r"^```(?:json)?\s*|```\s*$", "", cleaned, flags=re.M).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in the reply")
    body = cleaned[start:end + 1]
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        value = json.loads(re.sub(r",\s*([}\]])", r"\1", body))
    if not isinstance(value, dict):
        raise ValueError("the reply is not a JSON object")
    return value


class RoleModels:
    """One Nightshift client per role, each reporting receipts to the trace."""

    def __init__(self, client, lanes: Lanes, trace: RunTrace) -> None:
        if not hasattr(client, "with_route"):
            raise ModelError("mobius agents need the Meterless (Nightshift) provider")
        self.lanes = lanes
        self.trace = trace
        self._clients = {
            "planner": client.with_route(lanes.planner, "planner", sink=trace.model_call),
            "executor": client.with_route(lanes.executor, "executor", sink=trace.model_call),
            "critic": client.with_route(lanes.critic, "critic", sink=trace.model_call),
        }

    # When a lane fails twice, the role borrows another Nemotron lane for that call.
    FALLBACK = {"executor": "planner", "critic": "planner", "planner": "executor"}

    def _chat(self, role: str, messages: list[dict], max_tokens: int) -> str:
        """One reply for ``role``: retry its lane once, then fall back to another lane.

        Reasoning lanes can spend a whole budget thinking and come back empty, and
        any provider can blip; neither may end a run. Each recovery is traced.
        """
        from ..assist.meterless import MeterlessError
        attempts = [(role, max_tokens), (role, max_tokens * 2),
                    (self.FALLBACK[role], max_tokens * 2)]
        last = None
        for i, (lane, budget) in enumerate(attempts):
            try:
                text, _receipt = self._clients[lane].chat(messages, max_tokens=budget)
            except MeterlessError as exc:
                last, text = exc, ""
            if (text or "").strip():
                return text
            if i + 1 < len(attempts):
                to_lane, to_budget = attempts[i + 1]
                kind = "recover" if to_lane == role else "fallback"
                self.trace.emit(role, kind, f"{lane} lane gave no answer ("
                                f"{last or 'empty reply'}); trying the {to_lane} lane "
                                f"with {to_budget} tokens")
        raise ModelError(f"{role}: no lane answered ({last or 'empty replies'})")

    def ask_json(self, role: str, system: str, user: str, *,
                 history: list[dict] | None = None, max_tokens: int = 1800) -> dict:
        messages = [{"role": "system", "content": system}, *(history or []),
                    {"role": "user", "content": user}]
        text = self._chat(role, messages, max_tokens)
        try:
            return parse_json(text)
        except ValueError as exc:
            self.trace.emit(role, "recover", f"reply was not JSON ({exc}); re-asking once")
            messages += [{"role": "assistant", "content": text[:2000]},
                         {"role": "user", "content":
                          "That was not a valid JSON object. Reply with only the JSON "
                          "object, no prose, no code fences."}]
            text = self._chat(role, messages, max_tokens)
            try:
                return parse_json(text)
            except ValueError as again:
                raise ModelError(f"{role} did not return JSON twice: {again}") from again


# -- shared run state ------------------------------------------------------------

@dataclass
class Investigation:
    id: str
    question: str
    why: str = ""
    weakness_keys: list[str] = field(default_factory=list)
    priority: str = "medium"
    mode: str = "investigate"          # or "verify_ruling" (memory settled it before)
    memory_note: str = ""
    origin: str = "planner"            # planner / memory


@dataclass
class Claim:
    id: str
    investigation: str
    text: str
    severity: str = "medium"
    present: bool = True               # False: "looked, and it is not there"
    fingerprints: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)       # query ids
    confidence: float = 0.5
    exploited: bool = False            # KEV-listed advisory, confirmed via Zetaris
    status: str = "proposed"           # accepted / rejected / needs_human
    attempts: int = 1
    critique: list[str] = field(default_factory=list)
    weakness_keys: list[str] = field(default_factory=list)


class QueryBook:
    """Every query this run made through Zetaris, by id: the citation index."""

    def __init__(self, data, trace: RunTrace) -> None:
        self.data = data
        self.trace = trace
        self.results: dict[str, SqlResult] = {}

    def run(self, agent: str, sql: str, purpose: str, *, limit: int = 200) -> SqlResult:
        try:
            result = self.data.sql(sql, limit=limit)
        except DataLayerError as exc:
            self.trace.emit(agent, "sql", f"{purpose}: FAILED {exc}",
                            sponsor="zetaris", sql=sql, error=str(exc),
                            tables=tables_in(sql), row_count=0)
            raise
        self.results[result.query_id] = result
        self.trace.emit(agent, "sql", f"{purpose}: {len(result.rows)} rows",
                        sponsor="zetaris", ref=result.query_id, sql=result.sql,
                        source=result.source, tables=tables_in(result.sql),
                        row_count=len(result.rows), elapsed_ms=result.elapsed_ms)
        return result

    def rows(self, query_ids: list[str]) -> list[dict]:
        out = []
        for qid in query_ids:
            if qid in self.results:
                out.extend(self.results[qid].records())
        return out


# -- Planner ---------------------------------------------------------------------

PLANNER_SYSTEM = f"""You are the Planner in mobius, a multi-agent mobile security reviewer.
Your job: decide what to investigate so the team can answer "is this app safe to ship,
and why", with evidence. You do not query data; an Executor answers each
investigation by running SQL over Zetaris, and a Critic checks every claim.

Rules:
- Pick the app's sector from: {", ".join(SECTORS)}. Use the signals given. If MEMORY
  says the owner confirmed the sector, use that sector.
- Write 2 to 5 investigations, highest risk first. Each is a concrete question the data
  can answer (which findings, are they corroborated by several tools, are vulnerable
  dependencies known-exploited, does an exported component expose the weakness, what
  does the sector's regulation make critical).
- If MEMORY holds a ruling on a weakness (false positive / accepted risk), do not
  re-investigate it from scratch.
- Reply with JSON only:
{{"sector": {{"name": "...", "confidence": 0.0, "signals": ["..."]}},
 "investigations": [{{"id": "I1", "question": "...", "why": "...",
   "weakness_keys": ["..."], "priority": "high|medium|low"}}]}}"""

PLANNER_WEB_SYSTEM = f"""You are the Planner in mobius, a multi-agent security reviewer.
Here the subject is a WEBSITE / external attack surface mapped by a recon run, not a
mobile app. Your job: decide what to investigate so the team can answer "is this web
target safe to release / expose, and why", with evidence. You do not query data; an
Executor answers each investigation with SQL over Zetaris, and a Critic checks every
claim. The data is in mobius_web.assets (hosts, services, tech, URLs, certs, buckets,
repos) and mobius_web.findings (leaked secrets, public buckets, correlated CVEs,
breaches, typosquats), plus mobius_intel.kev / epss / obligations.

Rules:
- Pick the owner's sector from: {", ".join(SECTORS)}. Use the signals given, and any
  MEMORY of an owner-confirmed sector.
- Write 2 to 5 investigations, highest risk first, each a concrete question the data
  can answer: leaked secrets in code/repos, public cloud buckets, a correlated CVE that
  is known-exploited (KEV), subdomain-takeover or breach exposure, lookalike domains,
  what the sector's regulation makes critical.
- Reply with JSON only:
{{"sector": {{"name": "...", "confidence": 0.0, "signals": ["..."]}},
 "investigations": [{{"id": "I1", "question": "...", "why": "...",
   "weakness_keys": ["..."], "priority": "high|medium|low"}}]}}"""

VERDICT_SYSTEM = """You are the Planner in mobius writing the final verdict on whether a
mobile app is safe to ship. Use ONLY the accepted claims given; cite their ids.
Verdicts: "ship" (no material risk), "ship_with_fixes" (fixable issues, none critical),
"block" (a critical or known-exploited issue, or a regulated-data exposure).
Map the sector's obligations to the claims they bear on. Compliance notes are
advisory, never a certification. Reply with JSON only:
{"verdict": "ship|ship_with_fixes|block", "headline": "one sentence",
 "reasons": [{"text": "...", "claims": ["C1"]}],
 "obligations": [{"framework": "...", "why": "...", "claims": ["C1"]}],
 "next_steps": ["..."]}"""

ESCALATION_SYSTEM = """You are the senior reviewer in mobius. A claim failed review
repeatedly. Decide with the evidence shown:
- accept: the rows show the issue is real. If the claim overstated it (severity too
  high, weak corroboration), accept it at the severity the rows do support. An
  overstated real issue is downgraded, never dropped.
- reject: only when the rows show the issue is absent or the claim is false.
- needs_human: the rows cannot settle it either way.
Reply with JSON only:
{"decision": "accept|reject|needs_human", "severity": "critical|high|medium|low|info",
 "reason": "..."}"""


# -- Executor --------------------------------------------------------------------

def executor_system(available: set[str]) -> str:
    return f"""You are the Executor in mobius. You answer ONE investigation about a
mobile app by querying Zetaris with SQL, then make ONE claim backed by the query ids
you received. Tables (Spark SQL dialect; use db.table names exactly):
{schema_prompt(available)}

Each turn reply with JSON only, one of:
{{"action": "run_sql", "sql": "SELECT ...", "purpose": "..."}}
{{"action": "claim", "claim": "what is true, specifically", "present": true,
  "severity": "critical|high|medium|low|info", "fingerprints": ["..."],
  "evidence": ["<query ids you received>"], "confidence": 0.0,
  "weakness_keys": ["..."]}}
Rules: one SELECT per run_sql, no writes; query only the tables listed above (query
ids such as zq-1a2b3c4d are citations for your "evidence" list, never table names); cite
only query ids you were given; cite
finding fingerprints from the rows; set "present": false when the data shows the
issue is absent. Prefer joins across tables (findings with kev / epss / entities)
over guesses."""


def executor_brief(inv: Investigation, *, sector: str | None,
                   critique: list[str], memory: str,
                   vocab: dict[str, tuple[int, str]] | None = None) -> str:
    parts = [f"Investigation {inv.id}: {inv.question}"]
    if vocab:
        parts.append("Weakness keys in this scan (exact values of findings.weakness_key, "
                     "with counts). Filter on these; zero rows for a key not listed here "
                     "proves nothing:\n" + "\n".join(
                         f"- {k} ({n}, e.g. {example[:70]})"
                         for k, (n, example) in vocab.items()))
    if inv.why:
        parts.append(f"Why it matters: {inv.why}")
    if sector:
        parts.append(f"App sector: {sector}")
    if inv.mode == "verify_ruling":
        parts.append("MEMORY: this weakness was ruled on in an earlier review: "
                     f"{inv.memory_note}. Only check whether the data now contradicts "
                     "that ruling (new tool agreement, exported component, KEV). If not, "
                     "claim present=false.")
    if memory:
        parts.append(f"Relevant memory:\n{memory}")
    if critique:
        parts.append("The Critic sent your last claim back. Fix exactly this:\n- "
                     + "\n- ".join(critique))
    return "\n\n".join(parts)


# -- Critic ----------------------------------------------------------------------

CRITIC_SYSTEM = """You are the Critic in mobius. Judge one claim about a mobile app
against the evidence rows shown (they came from Zetaris). Accept only what the rows
support. If the claim overstates, misses corroboration, or cites the wrong rows, send
it back with a concrete hint (which table or join would settle it). Escalate only when
the evidence genuinely conflicts. Reply with JSON only:
{"decision": "accept|retry|escalate", "reason": "...", "hint": "..."}"""


@dataclass
class Issue:
    code: str
    message: str
    blocking: bool = True


_GENERIC = {"android", "ios", "weak", "high", "entropy", "service", "custom", "allowed",
            "protection", "string", "mode", "unsupported", "with", "that", "this", "does",
            "have", "from", "into", "data", "used", "using", "there", "which", "mobile",
            "finding", "findings", "check", "whether", "app's", "apps"}


def _topic_tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9']+", text.lower())
            if len(t) >= 4 and t not in _GENERIC}


def _related(a: str, b: str) -> bool:
    n = min(5, len(a), len(b))
    return a[:n] == b[:n]


def absence_issues(claim: Claim, inv: Investigation,
                   vocab: dict[str, tuple[int, str]]) -> list[Issue]:
    """A "not present" claim the scan contradicts, by the weakness vocabulary.

    The Executor may filter on a weakness name that does not exist, get zero rows
    and conclude absence. Here the topic of the investigation is matched against
    the keys the scan actually has; a matching key with findings blocks the claim.
    A memory ``verify_ruling`` check is exempt: there absence means "the old
    false-positive ruling still holds", not "the scanner saw nothing".
    """
    if claim.present or inv.mode == "verify_ruling" or not vocab:
        return []
    topic = _topic_tokens(" ".join([inv.question, *inv.weakness_keys,
                                    *claim.weakness_keys]))
    issues = []
    for key, (count, example) in vocab.items():
        if count <= 0:
            continue
        key_tokens = _topic_tokens(" ".join(re.split(r"[.\-]", key)))
        if any(_related(k, t) for k in key_tokens for t in topic):
            issues.append(Issue("ABSENCE_CONTRADICTED",
                                f"the scan has {count} findings under {key} (e.g. "
                                f"'{example[:80]}'); query that key before claiming "
                                "absence"))
    return issues


def evidence_issues(claim: Claim, book: QueryBook, rulings: dict[str, dict]) -> list[Issue]:
    """The deterministic half of the Critic: rules the evidence must satisfy."""
    issues: list[Issue] = []
    cited = [q for q in claim.evidence if q in book.results]
    unknown = [q for q in claim.evidence if q not in book.results]
    if unknown:
        issues.append(Issue("UNKNOWN_QUERY", "cites query ids this run never made: "
                            + ", ".join(unknown)))
    if not cited:
        issues.append(Issue("NO_EVIDENCE", "cites no query that ran; run a query and "
                            "cite its id"))
        return issues
    rows = book.rows(cited)
    if claim.present and not rows:
        issues.append(Issue("EMPTY_EVIDENCE", "every cited query returned 0 rows, yet "
                            "the claim says the issue is present"))
        return issues
    seen = {str(r.get("fingerprint", ""))[:16] for r in rows if r.get("fingerprint")}
    missing = [f for f in claim.fingerprints if f[:16] not in seen]
    if seen and missing:
        issues.append(Issue("UNCITED_FINDING", "fingerprints not in the cited rows: "
                            + ", ".join(missing[:5])))
    if not claim.present:
        return issues
    severities = [SEVERITY_RANK.get(str(r.get("severity", "")).lower(), -1) for r in rows]
    top = max(severities, default=-1)
    claimed = SEVERITY_RANK.get(claim.severity, 2)
    if top >= 0 and claimed > top and not claim.exploited:
        issues.append(Issue("SEVERITY_UNSUPPORTED", f"claims {claim.severity} but the "
                            "cited findings top out lower; cite KEV/EPSS or lower it"))
    if claimed >= SEVERITY_RANK["high"] and not claim.exploited:
        votes = [int(r.get("votes") or 0) for r in rows if "votes" in r]
        conf = [float(r.get("confidence") or 0) for r in rows if "confidence" in r]
        if (votes or conf) and max(votes, default=0) < 2 and max(conf, default=0) < 0.8:
            issues.append(Issue("WEAK_CORROBORATION", "high severity rests on a single "
                                "tool with confidence < 0.8; find a second source "
                                "(votes, an exported entity, KEV)"))
    for key in claim.weakness_keys:
        ruling = rulings.get(key)
        if ruling and ruling.get("human") and ruling["status"] in (
                "false_positive", "accepted_risk") and "ruling" not in claim.text.lower():
            issues.append(Issue("CONTRADICTS_RULING", f"{key} was ruled "
                                f"{ruling['status']} by the owner "
                                f"({ruling['memory']}); say what new evidence overturns "
                                "that ruling, or claim present=false"))
    return issues


def advisories_in(rows: list[dict]) -> list[str]:
    ids = {str(r.get("advisory_id") or r.get("cve_id") or r.get("cve") or "").upper()
           for r in rows}
    return sorted(i for i in ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", i))
