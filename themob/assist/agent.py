"""The investigation agent: a bounded loop over themob's read-only tools.

The product face is "type what you want, the agent investigates and hands back a
grounded answer", run on a background thread by the panel. This module is the
engine: Qt-free, model-agnostic, and read-only. It reasons over the deterministic
findings the engine produced and the local corpus; it never changes a finding,
and in this first cut it takes no gated action. A later version can propose gated
actions (scan, record a verdict, REA) for the operator to approve before acting.

The protocol is ReAct over plain completions, so it runs on any provider,
including the free ones, with no native tool-calling API: the model replies with
either ``ACTION: <tool> <json>`` or ``FINAL: <answer>``, themob runs the tool and
feeds the result back. It is bounded by a step cap, and each observation is
clipped, so a free-tier tokens-per-minute budget is respected (the same limit
that produced the assistant's 413).
"""
from __future__ import annotations

import json
import re
from typing import Callable

from ..mcp import tools

# Conservative for a free tokens-per-minute budget: few calls, small per-call
# reservations, clipped observations. A paid tier can raise the step count.
_MAX_STEPS = 3
_MAX_OBSERVATION = 1000         # clip each tool result: free-tier TPM budget
_FINAL_TOKENS = 2048            # the floor for an answer; the provider's own
                                # budget is used when it is larger
_ACTION_RE = re.compile(r"ACTION:\s*([a-z_]+)\s*(\{[^{}]*\})?", re.IGNORECASE)


# -- the read-only tools the agent may call ---------------------------------

def _overview(home, project, **_):
    return tools.overview(home, project)


def _list_findings(home, project, severity="", status="", **_):
    return tools.list_findings(home, project, severity or None, status or None)


def _get_finding(home, project, fingerprint="", **_):
    return tools.get_finding(home, project, fingerprint)


def _get_section(home, project, section="", **_):
    return tools.get_section(home, project, section)


def _graph(home, project, type="", **_):               # noqa: A002, matches the tool
    return tools.graph(home, project, type=type or None)


def _corpus(home, project, top=50, **_):
    try:
        top = int(top)
    except (TypeError, ValueError):
        top = 50
    return tools.corpus(home, top)


_TOOLS: dict[str, tuple[Callable, str]] = {
    "overview": (_overview, "counts, the app's facts, and the worst findings. no args"),
    "list_findings": (_list_findings,
                      "all findings as short summaries. optional: severity, status"),
    "get_finding": (_get_finding,
                    "one finding in full (standards, location, evidence, fix). "
                    "arg: fingerprint (a prefix is fine)"),
    "get_section": (_get_section,
                    "one section's findings and entities. arg: section "
                    "(e.g. secrets, network, platform, code)"),
    "graph": (_graph,
              "the attack-surface graph. optional: type (e.g. endpoint, deep_link)"),
    "corpus": (_corpus,
               "how this app's weaknesses compare across all your scans. no args"),
}


def _system() -> str:
    catalog = "\n".join(f"- {name}: {desc}" for name, (_fn, desc) in _TOOLS.items())
    return (
        "You are themob's mobile-security investigation agent. The developer "
        "gives you a goal about their own app. themob has already scanned it, "
        "and the OBSERVATIONS below are its real findings. Investigate further "
        "with the tools if needed, then answer.\n\n"
        "Grounding (critical):\n"
        "- Base your answer ONLY on the OBSERVATIONS. Name the specific findings "
        "in the data (their titles and weakness keys). Do NOT list generic "
        "mobile risks or what a typical app might have.\n"
        "- The OBSERVATIONS include 'the full scope': every distinct weakness "
        "with a count. Cover EVERY weakness group in your FINAL answer and use "
        "its count (for example 37 hardcoded keys); do not drop any group.\n"
        "- Never invent a finding, severity or evidence. If the data does not "
        "cover what was asked, say so plainly.\n"
        "- Format for a narrow panel: headings, bulleted or numbered lists, and "
        "fenced code blocks. Do NOT use Markdown tables.\n\n"
        "Tools (all read-only):\n" + catalog + "\n\n"
        "Reply in EXACTLY one of these two forms and nothing else:\n"
        "  ACTION: <tool> <json-args>\n"
        "  FINAL: <your answer in markdown>\n"
        "Use ACTION to get more detail (for example get_finding on a specific "
        "finding), or FINAL when the OBSERVATIONS already answer the goal.\n"
        "Examples:\n"
        '  ACTION: get_finding {"fingerprint": "abc123"}\n'
        '  ACTION: list_findings {"severity": "high"}\n'
        "  FINAL: Your worst issue is the cleartext endpoint ...\n\n"
        "You may RECOMMEND actions themob can take, but you never run them: the "
        "operator approves each. If you recommend any, end your FINAL with a line\n"
        "  PROPOSALS: <json array>\n"
        "where each item is one of:\n"
        '  {"action":"record_verdict","fingerprint":"<fp>","status":'
        '"confirmed|false_positive|accepted_risk","reason":"<why>"}\n'
        '  {"action":"rea_prepare","target":"<native library key>","reason":"<why>"}\n'
        '  {"action":"rescan","reason":"<why>"}\n'
        "Only propose an action grounded in what you found, and only a verdict "
        "whose fingerprint you actually saw. Omit PROPOSALS entirely if none.")


# -- parsing and dispatch ----------------------------------------------------

_VERDICTS = {"confirmed", "false-positive", "false_positive",
             "accepted-risk", "accepted_risk"}
_MAX_PROPOSALS = 6


def _proposals(block: str) -> list[dict]:
    """Validate the model's recommended gated actions. Recorded, never executed:
    the operator approves each in the UI, and the gated tool enforces its own
    gate on top. Anything malformed or unknown is dropped."""
    try:
        raw = json.loads(block)
    except ValueError:
        return []
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw[:_MAX_PROPOSALS]:
        if not isinstance(item, dict):
            continue
        action = item.get("action")
        reason = str(item.get("reason", "")).strip()[:300]
        if action == "record_verdict":
            fingerprint = str(item.get("fingerprint", "")).strip()[:128]
            status = str(item.get("status", "")).strip().lower()
            if not fingerprint or status not in _VERDICTS:
                continue
            out.append({"action": action, "fingerprint": fingerprint,
                        "status": status, "reason": reason})
        elif action == "rea_prepare":
            target = str(item.get("target", "")).strip()[:1024]
            if not target:
                continue
            out.append({"action": action, "kind": "native",
                        "target": target, "reason": reason})
        elif action == "rescan":
            out.append({"action": action, "reason": reason})
    return out


def _split_final(text: str) -> tuple[str, list[dict]]:
    """Separate the markdown answer from a trailing PROPOSALS json array."""
    marker = text.upper().rfind("PROPOSALS:")
    if marker < 0:
        return text.strip(), []
    answer = text[:marker].strip()
    block = text[marker + len("PROPOSALS:"):]
    start, end = block.find("["), block.rfind("]")
    proposals = _proposals(block[start:end + 1]) if 0 <= start < end else []
    return answer, proposals


def _parse(reply: str):
    """``("final", text)`` or ``("action", tool, args)`` or ``None``."""
    text = reply or ""
    upper = text.upper()
    final_at = upper.rfind("FINAL:")
    action_at = upper.rfind("ACTION:")
    if final_at >= 0 and final_at >= action_at:
        return ("final", text[final_at + len("FINAL:"):].strip())
    match = _ACTION_RE.search(text)
    if match:
        args: dict = {}
        if match.group(2):
            try:
                parsed = json.loads(match.group(2))
                args = parsed if isinstance(parsed, dict) else {}
            except ValueError:
                args = {}
        return ("action", match.group(1).lower(), args)
    return None


def _dispatch(home, project: str, tool: str, args: dict) -> str:
    entry = _TOOLS.get(tool)
    if entry is None:
        result = {"error": f"no such tool {tool!r}. available: "
                           + ", ".join(_TOOLS)}
    else:
        try:
            result = entry[0](home, project, **args)
        except Exception as exc:                       # noqa: BLE001
            result = {"error": f"{type(exc).__name__}: {exc}"}
    blob = json.dumps(result, default=str, separators=(",", ":"))
    if len(blob) > _MAX_OBSERVATION:
        blob = blob[:_MAX_OBSERVATION] + " ...[truncated]"
    return blob


def _scope(home, project: str) -> str:
    """Every weakness once, with a count: the full scope, compact. Primed into
    the agent so a brief investigation still covers all of it (the thin answers
    came from the model fetching one or two findings and stopping)."""
    listed = tools.list_findings(home, project).get("findings", [])
    groups: dict[str, dict] = {}
    for summary in listed:
        key = summary.get("weakness_key") or summary.get("title") or "unknown"
        group = groups.setdefault(key, {
            "weakness": key, "title": summary.get("title"),
            "severity": summary.get("severity"), "count": 0})
        group["count"] += 1
    scope = {"total_findings": len(listed),
             "weakness_groups": sorted(groups.values(),
                                       key=lambda g: -g["count"])}
    return json.dumps(scope, default=str, separators=(",", ":"))


def _model_error(exc: Exception) -> dict:
    low = str(exc).lower()
    if any(s in low for s in ("rate_limit", "tokens per minute", "too large",
                              " 413", "413 ")):
        return {"error": ("the model provider's free-tier limit was hit (tokens "
                          "per minute). Wait a minute and retry, or set "
                          "THEMOB_LLM_MODEL=openai/gpt-oss-20b.")}
    return {"error": f"the agent could not reach the model: {exc}"}


# -- the loop ----------------------------------------------------------------

def run(home=None, project: str = "", goal: str = "", *, client=None,
        max_steps: int = _MAX_STEPS, on_step=None) -> dict:
    """Investigate *goal* and return ``{"answer", "steps"}`` or ``{"error"}``.

    ``client`` is any object with ``complete(system, prompt)``; omitted, one is
    built from the configured provider. ``on_step(tool, args)`` is called before
    each tool runs, for a live trace. Read-only: no gated action is taken.
    """
    goal = (goal or "").strip() or "What are my worst issues and how do I fix them?"

    check = tools.overview(home, project)              # project must resolve
    if "error" in check:
        return {"error": check["error"]}

    if client is None:
        from . import llm
        client, key_error = llm.make_client()
        if client is None:
            return {"error": f"the agent needs a model: {key_error}"}

    system = _system()
    # Prime with the real overview so the answer is grounded from the first
    # token: left to choose, a model will skip the tools and answer from general
    # knowledge, which is exactly the hallucination this is built to avoid.
    overview_blob = json.dumps(check, default=str, separators=(",", ":"))
    if len(overview_blob) > _MAX_OBSERVATION:
        overview_blob = overview_blob[:_MAX_OBSERVATION] + " ...[truncated]"
    # Prime with both the overview and the full weakness scope, so the answer is
    # grounded and complete from the first token. The scope is read from
    # list_findings, which the trace reflects.
    transcript = [f"GOAL: {goal}",
                  f"OBSERVATION from overview: {overview_blob}",
                  "OBSERVATION the full scope (every weakness, with counts): "
                  f"{_scope(home, project)}"]
    steps: list[dict] = [{"tool": "overview", "args": {}},
                         {"tool": "list_findings", "args": {}}]
    total = max(1, int(max_steps))
    # The final answer gets the provider's whole budget (Gemini/Claude are large;
    # the hardcoded 2048 was what cut the agent's answers short), the steps stay
    # small so a free tokens-per-minute budget is not spent before the answer.
    final_budget = max(getattr(client, "max_output_tokens", _FINAL_TOKENS),
                       _FINAL_TOKENS)

    # Each iteration is one model call, so the call count is capped at *total*:
    # a free tokens-per-minute budget is spent per call, and a multi-call loop
    # is the quickest way to exhaust it. The last iteration forces a FINAL rather
    # than spending a further call on a wrap-up.
    for step in range(total):
        last = step == total - 1
        hint = ("This is your last step. Give your FINAL answer now, grounded "
                "only in what you have seen." if last
                else "Your move (ACTION or FINAL):")
        prompt = "\n\n".join(transcript) + "\n\n" + hint
        # Every step gets the full budget: the model can answer FINAL at any step
        # (with the scope primed it usually does so at once), and a small reserve
        # on those early steps is exactly what truncated the agent's answers. An
        # ACTION reply is short regardless, so the reservation costs little.
        budget = final_budget
        try:
            reply = client.complete(system, prompt, max_tokens=budget)
        except Exception as exc:                       # noqa: BLE001
            return _model_error(exc)

        parsed = _parse(reply)
        if not last and parsed is not None and parsed[0] == "action":
            _tag, tool, args = parsed
            if on_step is not None:
                try:
                    on_step(tool, args)
                except Exception:                      # noqa: BLE001
                    pass
            observation = _dispatch(home, project, tool, args)
            steps.append({"tool": tool, "args": args})
            transcript.append(f"ACTION: {tool} {json.dumps(args)}")
            transcript.append(f"OBSERVATION: {observation}")
            continue

        raw = parsed[1] if parsed and parsed[0] == "final" else (reply or "").strip()
        answer, proposals = _split_final(raw)
        result = {"answer": answer, "steps": steps, "proposals": proposals}
        if last and parsed is not None and parsed[0] == "action":
            result["truncated"] = True          # it wanted to keep investigating
        return result
