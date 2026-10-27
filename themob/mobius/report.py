"""The explain-why report: verdict -> reasons -> claims -> queries and memories.

Plain Markdown, written next to the trace, so a reviewer can follow any line of
the verdict back to the exact SQL Zetaris ran, the rows it returned, the H-MEM
memories that shaped the plan, and the model that wrote each step.
"""
from __future__ import annotations

from .trace import format_event, format_ledger

_LABEL = {"ship": "Ship", "ship_with_fixes": "Ship with fixes", "block": "Block"}


def render_report(result) -> str:
    v = result.verdict
    claims = {c.id: c for c in result.claims}
    queries = {}
    sql_events = [e for e in result.trace.events if e.kind == "sql" and e.ref]
    for e in sql_events:
        queries[e.ref] = e
    lines = [
        f"# mobius verdict for {result.package}: {_LABEL.get(v['verdict'], v['verdict'])}",
        "",
        v.get("headline", ""),
        "",
        f"Run `{result.run_id}`. Sector: **{result.sector}** (from {result.sector_source})."
        + (f" Previous verdict: {v['prior_verdict']}." if v.get("prior_verdict") else ""),
        "",
        "## Why",
        "",
    ]
    for reason in v.get("reasons") or []:
        if not isinstance(reason, dict):
            continue
        cites = ", ".join(reason.get("claims") or [])
        lines.append(f"- {reason.get('text', '')} (claims: {cites or 'none'})")
    if v.get("critic_override"):
        lines += ["", f"The Critic overrode the Planner's verdict: {v['critic_override']}"]
    if v.get("needs_human"):
        lines += ["", "Needs a human decision: " + ", ".join(v["needs_human"])]

    lines += ["", "## Claims and their evidence", ""]
    for c in result.claims:
        mark = "exploited (CISA KEV), " if c.exploited else ""
        state = "present" if c.present else "checked, not present"
        lines.append(f"### {c.id}: {c.status}, {mark}{c.severity}, {state}")
        lines.append("")
        lines.append(c.text)
        lines.append("")
        lines.append(f"Investigation {c.investigation}, {c.attempts} attempt(s).")
        if c.critique:
            lines.append("Critic notes: " + "; ".join(c.critique[:4]))
        for qid in c.evidence:
            event = queries.get(qid)
            if event is None:
                continue
            lines.append(f"- `{qid}` ({event.data.get('row_count', 0)} rows, "
                         f"{event.data.get('source', '')}): `{event.data.get('sql', '')}`")
        lines.append("")

    memory = [e for e in result.trace.events if e.sponsor == "hmem"]
    lines += ["## What memory contributed (H-MEM)", ""]
    if not memory:
        lines.append("Memory was off for this run.")
    for e in memory:
        lines.append(f"- {e.kind}: {e.summary}" + (f" (`{e.ref}`)" if e.ref else ""))

    obligations = v.get("obligations") or []
    if obligations:
        lines += ["", "## Sector obligations (advisory, review with counsel)", ""]
        for o in obligations:
            if isinstance(o, dict):
                cites = ", ".join(o.get("claims") or [])
                lines.append(f"- **{o.get('framework', '')}**: {o.get('why', '')}"
                             + (f" (claims: {cites})" if cites else ""))
    steps = v.get("next_steps") or []
    if steps:
        lines += ["", "## Next steps", ""] + [f"- {s}" for s in steps]

    lines += ["", "## How the system reached this", "", "```",
              format_ledger(result.trace.ledger()), "```", "", "<details><summary>Full "
              "trace</summary>", "", "```"]
    lines += [format_event(e) for e in result.trace.events]
    lines += ["```", "", "</details>", ""]
    return "\n".join(lines)
