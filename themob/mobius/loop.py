"""The mobius run: Planner -> Executor <-> Critic, with retry and escalation.

    recall (H-MEM) -> reconnaissance (Zetaris) -> plan (Planner, deep lane)
      -> memory applied to the plan (sector, rulings, sector priors)
      -> for each investigation:
           Executor (fast lane) runs SQL over Zetaris and claims
           Critic re-checks KEV through Zetaris, applies the evidence rules,
             asks the judge lane; accept / retry with a hint / escalate
           after 2 retries: escalation to the deep lane, which may say
             needs_human
      -> verdict (Planner), checked by the Critic against the accepted claims
      -> memory written back (sector, verdict, lessons, feedback on what helped)

Branches, not a pipeline: the Critic decides whether work goes back, how
often, and when a human must look. Every step is in the :class:`RunTrace`.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..hmem.scan_memory import Recall, ScanMemory
from .agents import (CRITIC_SYSTEM, ESCALATION_SYSTEM, PLANNER_SYSTEM, PLANNER_WEB_SYSTEM,
                     SECTORS,
                     SEVERITY_RANK, VERDICT_SYSTEM, Claim, Investigation, Issue,
                     ModelError, QueryBook, RoleModels, advisories_in,
                     absence_issues, evidence_issues, executor_brief, executor_system)
from .catalog import CATALOG, sector_knowledge
from .datalayer import DataLayerError
from .trace import RunTrace

MAX_INVESTIGATIONS = 5
MAX_EXECUTOR_STEPS = 4
MAX_RETRIES = 2
VERDICTS = ("ship", "ship_with_fixes", "block")


@dataclass
class RunOptions:
    use_memory: bool = True
    use_advisories: bool = True
    sector: str | None = None            # a human's answer: confirmed sector
    operator: str = "operator"
    remember: bool = True
    kind: str = "app"                    # "app" (mobile scan) or "web" (recon)
    target: str = ""                     # the domain, for a web review


@dataclass
class RunResult:
    run_id: str
    package: str
    sector: str
    sector_source: str
    verdict: dict
    investigations: list[Investigation]
    claims: list[Claim]
    recall: Recall | None
    trace: RunTrace
    out_dir: Path | None = None

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "package": self.package, "sector": self.sector,
                "sector_source": self.sector_source, "verdict": self.verdict,
                "investigations": [asdict(i) for i in self.investigations],
                "claims": [asdict(c) for c in self.claims],
                "ledger": self.trace.ledger()}


class Orchestrator:
    def __init__(self, data, models: RoleModels, memory: ScanMemory | None,
                 trace: RunTrace, options: RunOptions | None = None) -> None:
        self.data = data
        self.models = models
        self.memory = memory
        self.trace = trace
        self.options = options or RunOptions()
        self.book = QueryBook(data, trace)
        self.available: set[str] = set()
        self._claim_seq = 0
        self.kind = (options or RunOptions()).kind
        self.vocab: dict[str, tuple[int, str]] = {}   # weakness_key -> (count, example)

    # -- the run -------------------------------------------------------------

    def run(self, package_hint: str | None = None) -> RunResult:
        t = self.trace
        self.kind = self.options.kind
        subject_label = "web target" if self.kind == "web" else "app"
        t.emit("orchestrator", "start", f"run {t.run_id} on {self.data.name} "
               f"({subject_label})"
               + ("" if self.options.use_memory else " (memory OFF)")
               + ("" if self.options.use_advisories else " (advisories OFF)"))
        if self.kind == "web":
            recon = self._web_reconnaissance(self.options.target or package_hint or "")
            package = recon["app"].get("package") or self.options.target or "unknown"
        else:
            recon = self._reconnaissance(package_hint)
            package = recon["app"].get("package") or package_hint or "unknown"
        recall = self._recall(package, recon)
        plan, sector, sector_source = self._plan(package, recon, recall)
        claims: list[Claim] = []
        for inv in plan:
            try:
                claims.append(self._investigate(inv, sector, recall))
            except ModelError as exc:         # every lane failed: a human decides
                self._claim_seq += 1
                claim = Claim(id=f"C{self._claim_seq}", investigation=inv.id,
                              text=f"Not investigated: {exc}", severity="info",
                              status="needs_human", weakness_keys=list(inv.weakness_keys))
                t.emit("orchestrator", "needs_human", f"{inv.id}: {exc}"[:240],
                       claim=asdict(claim))
                claims.append(claim)
        verdict = self._verdict(package, sector, claims, recall, recon)
        self._remember(package, sector, sector_source, verdict, claims, recall, recon)
        t.emit("orchestrator", "done", f"verdict {verdict['verdict']}: "
               f"{verdict.get('headline', '')}")
        return RunResult(t.run_id, package, sector, sector_source, verdict, plan, claims,
                         recall, t)

    # -- step 1: what is there (Zetaris) ------------------------------------

    def _probe(self, table: str) -> bool:
        try:
            self.book.run("executor", f"SELECT * FROM {table} LIMIT 1",
                          f"probe {table}", limit=1)
            return True
        except DataLayerError:
            return False

    def _reconnaissance(self, package_hint: str | None) -> dict:
        tables = [n for n in CATALOG if n.startswith("mobius_scan.")]
        if self.options.use_advisories:
            tables += [n for n in CATALOG if n.startswith("mobius_intel.")]
        else:
            tables.append("mobius_intel.obligations")
        for table in tables:
            if self._probe(table):
                self.available.add(table)
        if "mobius_scan.findings" not in self.available:
            raise DataLayerError("mobius_scan.findings is not reachable through "
                                 f"{self.data.name}; publish the scan first")
        where = f" WHERE package = '{_q(package_hint)}'" if package_hint else ""
        app = self.book.run("executor", f"SELECT * FROM mobius_scan.app{where} LIMIT 1",
                            "the app").records()
        severity = self.book.run(
            "executor", "SELECT severity, COUNT(*) AS n FROM mobius_scan.findings "
            "GROUP BY severity", "findings by severity")
        top = self.book.run(
            "executor",
            "SELECT weakness_key, MAX(title) AS example, COUNT(*) AS n, MAX(votes) AS "
            "max_votes, MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev "
            "FROM mobius_scan.findings GROUP BY weakness_key ORDER BY sev DESC, n DESC "
            "LIMIT 60", "top weaknesses")
        self.vocab = {str(r["weakness_key"]): (int(r.get("n") or 0), str(r.get("example") or ""))
                      for r in top.records() if r.get("weakness_key")}
        exploited = None
        if {"mobius_intel.kev"} <= self.available:
            epss = "mobius_intel.epss" in self.available
            exploited = self.book.run(
                "executor",
                "SELECT f.fingerprint, f.advisory_id, f.title, f.severity, k.name, "
                "k.date_added, k.ransomware"
                + (", e.epss, e.percentile" if epss else "")
                + " FROM mobius_scan.findings f JOIN mobius_intel.kev k "
                "ON f.advisory_id = k.cve_id"
                + (" LEFT JOIN mobius_intel.epss e ON f.advisory_id = e.cve" if epss else ""),
                "known-exploited dependencies (findings x KEV x EPSS)")
        return {"app": app[0] if app else {}, "severity": severity, "top": top,
                "exploited": exploited}

    def _web_reconnaissance(self, target: str) -> dict:
        """The same shape as an app recon, read from the mobius_web.* tables."""
        tables = ["mobius_web.assets", "mobius_web.findings"]
        if self.options.use_advisories:
            tables += [n for n in CATALOG if n.startswith("mobius_intel.")]
        else:
            tables.append("mobius_intel.obligations")
        for table in tables:
            if self._probe(table):
                self.available.add(table)
        if "mobius_web.findings" not in self.available:
            raise DataLayerError("mobius_web.findings is not reachable through "
                                 f"{self.data.name}; run `webscan {target}` first")
        where = f" WHERE target = '{_q(target)}'" if target else ""
        asset_mix = self.book.run(
            "executor", "SELECT kind, COUNT(*) AS n FROM mobius_web.assets"
            + where + " GROUP BY kind ORDER BY n DESC", "web assets by kind")
        app = {"package": target, "label": target, "platform": "web",
               "surface": "web", "asset_kinds": asset_mix.records()}
        severity = self.book.run(
            "executor", "SELECT severity, COUNT(*) AS n FROM mobius_web.findings "
            "GROUP BY severity", "web findings by severity")
        top = self.book.run(
            "executor",
            "SELECT weakness_key, MAX(title) AS example, COUNT(*) AS n, "
            "MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' "
            "THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev FROM mobius_web.findings "
            "GROUP BY weakness_key ORDER BY sev DESC, n DESC LIMIT 60", "top web weaknesses")
        self.vocab = {str(r["weakness_key"]): (int(r.get("n") or 0), str(r.get("example") or ""))
                      for r in top.records() if r.get("weakness_key")}
        exploited = None
        if {"mobius_intel.kev"} <= self.available:
            exploited = self.book.run(
                "executor",
                "SELECT f.fingerprint, f.advisory_id, f.title, f.severity, k.name, "
                "k.date_added FROM mobius_web.findings f JOIN mobius_intel.kev k "
                "ON f.advisory_id = k.cve_id", "known-exploited web CVEs (findings x KEV)")
        return {"app": app, "severity": severity, "top": top, "exploited": exploited}

    # -- step 2: what memory says (H-MEM) -----------------------------------

    def _recall(self, package: str, recon: dict) -> Recall | None:
        if not self.options.use_memory or self.memory is None:
            self.trace.emit("memory", "recall_skipped", "memory is OFF for this run")
            return None
        hint = _signal_sector(recon["app"])[0]
        recall = self.memory.recall(package, "security verdict sector rulings risks",
                                    sector=hint)
        self.trace.emit("memory", "recall",
                        f"{len(recall.memories)} memories for {package}, "
                        f"{len(recall.sector_priors)} sector priors"
                        + (f"; sector {recall.confirmed_sector}"
                           f"{' (owner-confirmed)' if recall.sector_by_human else ''}"
                           if recall.confirmed_sector else "")
                        + (f"; prior verdict {recall.prior_verdict}"
                           if recall.prior_verdict else ""),
                        sponsor="hmem", ref=recall.sector_memory or "",
                        ids=recall.ids, scores=recall.trace.get("scores", {}))
        return recall

    # -- step 3: the plan ---------------------------------------------------

    def _plan(self, package: str, recon: dict, recall: Recall | None):
        signal_sector, hits = _signal_sector(recon["app"])
        prompt = {
            "app": recon["app"],
            "findings_by_severity": recon["severity"].records(),
            "top_weaknesses": recon["top"].records(),
            "known_exploited": recon["exploited"].records() if recon["exploited"] else
            "not available (advisory feeds not in this run)",
            "sector_signals": {"best": signal_sector, "hits": hits},
        }
        web = self.kind == "web"
        subject_word = "web target" if web else "app"
        user = f"Plan the review of this {subject_word}.\n" + json.dumps(prompt, default=str)[:7000]
        if recall and recall.context:
            user += "\n\nMEMORY (H-MEM, from earlier reviews):\n" + recall.context
        reply = self.models.ask_json("planner", PLANNER_WEB_SYSTEM if web else PLANNER_SYSTEM,
                                     user)
        sector_reply = reply.get("sector") or {}
        sector = str(sector_reply.get("name") or signal_sector or "general").lower()
        if sector not in SECTORS:
            sector = "general"
        source = "planner"
        plan = []
        for i, item in enumerate((reply.get("investigations") or [])[:MAX_INVESTIGATIONS]):
            if not isinstance(item, dict) or not item.get("question"):
                continue
            plan.append(Investigation(
                id=str(item.get("id") or f"I{i + 1}"), question=str(item["question"]),
                why=str(item.get("why", "")),
                weakness_keys=[str(k) for k in item.get("weakness_keys") or []],
                priority=str(item.get("priority", "medium"))))
        if not plan:
            raise ModelError("the Planner produced no investigations")
        self.trace.emit("planner", "plan", f"sector {sector} "
                        f"(confidence {sector_reply.get('confidence', '?')}); "
                        f"{len(plan)} investigations",
                        investigations=[asdict(p) for p in plan],
                        signals=sector_reply.get("signals", []))

        # A human's answer on this run outranks everything.
        if self.options.sector:
            if self.options.sector != sector:
                self.trace.emit("orchestrator", "sector", f"operator set sector "
                                f"{self.options.sector} (planner guessed {sector})")
            sector, source = self.options.sector, "operator"
        elif recall:
            sector, source = self._apply_memory(plan, sector, source, recall, recon)
        return plan, sector, source

    def _apply_memory(self, plan, sector, source, recall: Recall, recon):
        """Memory changes the plan, deterministically, and says how."""
        t = self.trace
        if recall.confirmed_sector and recall.sector_by_human:
            if recall.confirmed_sector != sector:
                t.emit("memory", "memory_applied", f"sector {sector} -> "
                       f"{recall.confirmed_sector}: the owner confirmed it in an "
                       "earlier review", sponsor="hmem", ref=recall.sector_memory or "")
            else:
                t.emit("memory", "memory_used", f"sector {sector} matches the owner's "
                       "earlier confirmation", sponsor="hmem", ref=recall.sector_memory or "")
            sector, source = recall.confirmed_sector, "memory (owner-confirmed)"
        for inv in plan:
            for key in inv.weakness_keys:
                ruling = recall.rulings.get(key)
                if ruling and ruling["status"] in ("false_positive", "accepted_risk"):
                    inv.mode = "verify_ruling"
                    inv.memory_note = ruling["content"]
                    t.emit("memory", "memory_applied", f"{inv.id} narrowed to "
                           f"verifying the earlier {ruling['status']} ruling on {key}",
                           sponsor="hmem", ref=ruling["memory"])
                    break
        planned = {k for inv in plan for k in inv.weakness_keys}
        present = {str(r.get("weakness_key")) for r in recon["top"].records()}
        for prior in recall.sector_priors:
            for key in present - planned:
                if key and key in prior.content and len(plan) < MAX_INVESTIGATIONS:
                    plan.append(Investigation(
                        id=f"M{len(plan) + 1}", origin="memory", priority="high",
                        question=f"Does {key} in this app carry the same risk it did "
                                 f"in a peer {sector} app?",
                        why=f"Sector memory: {prior.content[:200]}",
                        weakness_keys=[key]))
                    planned.add(key)
                    t.emit("memory", "memory_applied", f"added an investigation of "
                           f"{key}: a peer {sector} app had it", sponsor="hmem",
                           ref=prior.id)
        return sector, source

    # -- step 4: investigate, critique, retry, escalate ---------------------

    def _investigate(self, inv: Investigation, sector: str, recall: Recall | None) -> Claim:
        critique: list[str] = []
        memory_text = recall.context if recall else ""
        claim = None
        for attempt in range(1, MAX_RETRIES + 2):
            claim = self._execute(inv, sector, critique, memory_text, attempt)
            decision, reasons = self._critique(claim, inv, recall)
            claim.critique.extend(reasons)
            if decision == "accept":
                claim.status = "accepted"
                self.trace.emit("critic", "accept", f"{claim.id} ({claim.severity}"
                                f"{', exploited' if claim.exploited else ''}): "
                                f"{claim.text[:140]}", claim=asdict(claim))
                return claim
            if decision == "retry" and attempt <= MAX_RETRIES:
                critique = list(reasons)
                ran = [f"{q}: {self.book.results[q].sql[:160]} "
                       f"({len(self.book.results[q].rows)} rows)"
                       for q in claim.evidence if q in self.book.results]
                if ran:
                    critique.append("queries you can still cite: " + " | ".join(ran))
                self.trace.emit("critic", "retry", f"{claim.id} back to the Executor: "
                                + "; ".join(reasons)[:240])
                continue
            break
        return self._escalate(claim, inv)

    def _execute(self, inv: Investigation, sector: str, critique: list[str],
                 memory_text: str, attempt: int) -> Claim:
        system = executor_system(self.available)
        brief = executor_brief(inv, sector=sector, critique=critique, memory=memory_text,
                               vocab=self.vocab)
        history: list[dict] = []
        user = brief
        reply: dict = {}
        for step in range(MAX_EXECUTOR_STEPS):
            if step == MAX_EXECUTOR_STEPS - 1:
                user += "\n\nYou are out of queries: make your claim now."
            reply = self.models.ask_json("executor", system, user, history=history)
            if reply.get("action") != "run_sql":
                break
            sql = str(reply.get("sql", ""))
            try:
                result = self.book.run("executor", sql, f"{inv.id}: "
                                       + str(reply.get("purpose") or "query")[:80])
                observation = result.preview()
            except DataLayerError as exc:
                observation = f"SQL ERROR: {exc}. Fix the SQL and try again."
                self.trace.emit("executor", "recover", f"{inv.id}: query failed, the "
                                "Executor gets the error and retries")
            history += [{"role": "user", "content": user},
                        {"role": "assistant", "content": json.dumps(reply)}]
            user = f"Result:\n{observation}"
        self._claim_seq += 1
        claim = Claim(
            id=f"C{self._claim_seq}", investigation=inv.id,
            text=str(reply.get("claim") or "no claim made"),
            severity=str(reply.get("severity") or "medium").lower(),
            present=bool(reply.get("present", True)),
            fingerprints=[str(f) for f in reply.get("fingerprints") or []],
            evidence=[str(e) for e in reply.get("evidence") or []],
            confidence=_float(reply.get("confidence"), 0.5),
            attempts=attempt,
            weakness_keys=[str(k) for k in reply.get("weakness_keys") or inv.weakness_keys])
        if claim.severity not in SEVERITY_RANK:
            claim.severity = "medium"
        self.trace.emit("executor", "claim", f"{claim.id} for {inv.id} (attempt "
                        f"{attempt}): {claim.text[:160]}", claim=asdict(claim))
        return claim

    def _critique(self, claim: Claim, inv: Investigation, recall: Recall | None):
        rulings = recall.rulings if recall else {}
        self._check_exploited(claim)
        issues = evidence_issues(claim, self.book, rulings) + absence_issues(
            claim, inv, self.vocab)
        for issue in issues:
            self.trace.emit("critic", "rule", f"{claim.id}: {issue.code}: {issue.message}")
        evidence = "\n".join(self.book.results[q].preview(limit=8)
                             for q in claim.evidence if q in self.book.results)
        user = (f"Investigation: {inv.question}\nClaim {claim.id}: {claim.text}\n"
                f"present={claim.present} severity={claim.severity} "
                f"exploited={claim.exploited} fingerprints={claim.fingerprints}\n\n"
                f"Evidence rows:\n{evidence or '(none)'}\n\nRule checks: "
                + ("; ".join(f"{i.code}: {i.message}" for i in issues) or "all passed"))
        judged = self.models.ask_json("critic", CRITIC_SYSTEM, user, max_tokens=1500)
        decision = str(judged.get("decision", "retry")).lower()
        reasons = [f"{i.code}: {i.message}" for i in issues if i.blocking]
        if reasons:
            decision = "retry"
        elif decision not in ("accept", "retry", "escalate"):
            decision = "retry"
        if decision != "accept":
            hint = str(judged.get("hint") or judged.get("reason") or "").strip()
            if hint:
                reasons.append(hint)
        self.trace.emit("critic", "critique", f"{claim.id}: {decision}"
                        + (f" ({judged.get('reason', '')[:160]})" if judged.get("reason")
                           else ""), decision=decision, issues=[i.code for i in issues])
        if decision == "escalate":
            return "escalate", reasons or [str(judged.get("reason", "conflicting evidence"))]
        return decision, reasons

    def _check_exploited(self, claim: Claim) -> None:
        """The Critic's own look at KEV, through Zetaris, for cited advisories."""
        if "mobius_intel.kev" not in self.available:
            return
        cves = advisories_in(self.book.rows(claim.evidence))
        if not cves:
            return
        listed = ", ".join(f"'{_q(c)}'" for c in cves[:20])
        result = self.book.run("critic", "SELECT cve_id, name, date_added FROM "
                               f"mobius_intel.kev WHERE cve_id IN ({listed})",
                               f"{claim.id}: KEV re-check of {len(cves)} advisories")
        if result.rows:
            claim.exploited = True
            if claim.present and SEVERITY_RANK.get(claim.severity, 2) < 4:
                self.trace.emit("critic", "upgrade", f"{claim.id}: "
                                f"{', '.join(r['cve_id'] for r in result.records())} "
                                f"is known-exploited (CISA KEV): severity "
                                f"{claim.severity} -> critical", sponsor="zetaris",
                                ref=result.query_id)
                claim.severity = "critical"
            claim.evidence.append(result.query_id)

    def _escalate(self, claim: Claim, inv: Investigation) -> Claim:
        self.trace.emit("critic", "escalate", f"{claim.id} after {claim.attempts} "
                        "attempts goes to the deep lane: " + "; ".join(claim.critique[-3:])[:240])
        evidence = "\n".join(self.book.results[q].preview(limit=8)
                             for q in claim.evidence if q in self.book.results)
        user = (f"Investigation: {inv.question}\nClaim: {claim.text}\nSeverity: "
                f"{claim.severity}\nCritic objections: {claim.critique}\n\n"
                f"Evidence:\n{evidence or '(none)'}")
        ruling = self.models.ask_json("planner", ESCALATION_SYSTEM, user, max_tokens=1500)
        decision = str(ruling.get("decision", "needs_human")).lower()
        if decision == "accept" and not evidence:
            decision = "needs_human"           # no rows, no acceptance, whoever asks
        claim.status = {"accept": "accepted", "reject": "rejected"}.get(decision,
                                                                       "needs_human")
        sev = str(ruling.get("severity", claim.severity)).lower()
        if sev in SEVERITY_RANK and not claim.exploited:
            claim.severity = sev
        kind = {"accepted": "accept", "rejected": "reject"}.get(claim.status, "needs_human")
        self.trace.emit("planner", kind, f"{claim.id} escalation: {claim.status} "
                        f"({str(ruling.get('reason', ''))[:180]})", claim=asdict(claim))
        return claim

    # -- step 5: the verdict ------------------------------------------------

    def _verdict(self, package, sector, claims, recall, recon) -> dict:
        accepted = [c for c in claims if c.status == "accepted" and c.present]
        human = [c for c in claims if c.status == "needs_human"]
        obligations = []
        if "mobius_intel.obligations" in self.available:
            obligations = self.book.run(
                "planner", "SELECT framework, jurisdiction, applies_because, "
                "masvs_categories, certainty FROM mobius_intel.obligations "
                f"WHERE sector = '{_q(sector)}'", f"obligations for {sector}").records()
        floor = _verdict_floor(accepted, human)
        payload = {
            "app": recon["app"], "sector": sector,
            "accepted_claims": [_claim_brief(c) for c in accepted],
            "absent_checked": [_claim_brief(c) for c in claims
                               if c.status == "accepted" and not c.present],
            "needs_human": [_claim_brief(c) for c in human],
            "rejected": [c.id for c in claims if c.status == "rejected"],
            "obligations": obligations,
            "prior_verdict": recall.prior_verdict if recall else None,
        }
        user = json.dumps(payload, default=str)[:9000]
        verdict = self.models.ask_json("planner", VERDICT_SYSTEM, user, max_tokens=2000)
        for round_ in (1, 2):
            problems = _verdict_problems(
                verdict, [c for c in claims if c.status == "accepted"], floor)
            if not problems:
                break
            self.trace.emit("critic", "verdict_check", "; ".join(problems)[:300])
            if round_ == 1:
                self.trace.emit("critic", "retry", "verdict back to the Planner")
                verdict = self.models.ask_json(
                    "planner", VERDICT_SYSTEM, user + "\n\nThe Critic rejected your "
                    "verdict: " + "; ".join(problems), max_tokens=2000)
            else:
                verdict["verdict"] = floor if _rank(verdict.get("verdict")) < _rank(floor) \
                    else verdict.get("verdict", floor)
                if verdict["verdict"] not in VERDICTS:
                    verdict["verdict"] = floor
                verdict.setdefault("critic_override", "; ".join(problems))
                self.trace.emit("critic", "override", f"verdict set to "
                                f"{verdict['verdict']} by the evidence floor")
        verdict["sector"] = sector
        verdict["needs_human"] = [c.id for c in human]
        verdict["evidence_floor"] = floor
        if recall and recall.prior_verdict:
            verdict["prior_verdict"] = recall.prior_verdict
        self.trace.emit("planner", "verdict", f"{verdict['verdict']}: "
                        f"{verdict.get('headline', '')[:200]}", verdict=verdict)
        return verdict

    # -- step 6: remember ---------------------------------------------------

    def _remember(self, package, sector, sector_source, verdict, claims, recall, recon):
        if not (self.options.remember and self.options.use_memory and self.memory):
            return
        t, m, run_id = self.trace, self.memory, self.trace.run_id
        if sector_source == "operator":
            rec = m.remember_sector(package, sector, confirmed_by="owner",
                                    evidence=f"confirmed during run {run_id}", run_id=run_id)
            t.emit("memory", "remember", f"sector {sector} (owner-confirmed)",
                   sponsor="hmem", ref=rec["id"])
        elif not (recall and recall.sector_by_human):
            rec = m.remember_sector(package, sector, confirmed_by="planner",
                                    run_id=run_id)
            t.emit("memory", "remember", f"sector guess {sector} (unconfirmed)",
                   sponsor="hmem", ref=rec["id"])
        top = [c.text for c in claims if c.status == "accepted" and c.present][:3]
        rec = m.remember_verdict(package, verdict["verdict"], sector=sector,
                                 version=str(recon["app"].get("version", "")),
                                 summary="Top risks: " + " | ".join(top) if top
                                 else "No material risk was accepted.", run_id=run_id)
        t.emit("memory", "remember", f"verdict {verdict['verdict']}", sponsor="hmem",
               ref=rec["id"])
        for c in claims:
            if c.status == "needs_human" or (c.attempts > 1 and c.status == "accepted"):
                lesson = (f"In {package}, claim on {', '.join(c.weakness_keys) or c.investigation}"
                          f" took {c.attempts} attempts ({c.status}); the Critic asked: "
                          + "; ".join(c.critique[:2]))
                rec = m.remember_lesson(package, lesson[:400], sector=sector, run_id=run_id)
                t.emit("memory", "remember", f"lesson from {c.id}", sponsor="hmem",
                       ref=rec["id"])
        if recall:
            for key, ruling in recall.rulings.items():
                overturned = any(c.status == "accepted" and c.present and key in
                                 c.weakness_keys for c in claims)
                kind = "wrong" if overturned else "helpful"
                m.feedback(ruling["memory"], kind)
                t.emit("memory", "feedback", f"ruling on {key}: {kind}", sponsor="hmem",
                       ref=ruling["memory"])
            if recall.sector_memory:
                kind = "helpful" if recall.confirmed_sector == sector else "not_helpful"
                m.feedback(recall.sector_memory, kind)
                t.emit("memory", "feedback", f"sector memory: {kind}", sponsor="hmem",
                       ref=recall.sector_memory)


# -- helpers ------------------------------------------------------------------------


def _q(value: str) -> str:
    return str(value).replace("'", "''")


def _float(value, default: float) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _signal_sector(app: dict) -> tuple[str | None, dict[str, list[str]]]:
    """Deterministic sector signals from the app row (package, label, permissions, libs)."""
    haystack = " ".join(str(app.get(k, "")) for k in
                        ("package", "label", "permissions", "libraries")).lower()
    hits: dict[str, list[str]] = {}
    for sector, spec in sector_knowledge()["sectors"].items():
        found = [s for s in spec["signals"] if s.lower() in haystack]
        if found:
            hits[sector] = found
    best = max(hits, key=lambda s: len(hits[s]), default=None)
    return best, hits


def _claim_brief(c: Claim) -> dict:
    return {"id": c.id, "text": c.text, "severity": c.severity, "exploited": c.exploited,
            "evidence": c.evidence, "weakness_keys": c.weakness_keys}


def _rank(verdict) -> int:
    return VERDICTS.index(verdict) if verdict in VERDICTS else -1


def _verdict_floor(accepted: list[Claim], human: list[Claim]) -> str:
    """The least severe verdict the evidence allows."""
    if any(c.exploited or c.severity == "critical" for c in accepted):
        return "block"
    if human or any(SEVERITY_RANK.get(c.severity, 0) >= 2 for c in accepted):
        return "ship_with_fixes"
    return "ship"


def _verdict_problems(verdict: dict, accepted: list[Claim], floor: str) -> list[str]:
    problems = []
    value = verdict.get("verdict")
    if value not in VERDICTS:
        problems.append(f"verdict must be one of {VERDICTS}")
    elif _rank(value) < _rank(floor):
        problems.append(f"verdict {value} is weaker than the evidence allows "
                        f"(at least {floor})")
    ids = {c.id for c in accepted}
    for reason in verdict.get("reasons") or []:
        cited = set(reason.get("claims") or []) if isinstance(reason, dict) else set()
        if not cited & ids:
            text = reason.get("text", "") if isinstance(reason, dict) else str(reason)
            problems.append(f"reason cites no accepted claim: {text[:80]}")
    return problems


def new_run_id() -> str:
    return "run-" + uuid.uuid4().hex[:10]


def write_run(result: RunResult, directory: Path) -> Path:
    """trace.jsonl, ledger.json, verdict.json and the explain-why report."""
    from .report import render_report
    directory.mkdir(parents=True, exist_ok=True)
    result.trace.write(directory)
    (directory / "verdict.json").write_text(json.dumps(result.to_dict(), indent=2,
                                                       default=str), encoding="utf-8")
    (directory / "report.md").write_text(render_report(result), encoding="utf-8")
    result.out_dir = directory
    return directory
