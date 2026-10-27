"""The assistant: explain a project's real findings and coach the fix.

Honest data is the rule, enforced in two places: the briefing is built only from
the findings themob actually produced, and the system prompt tells the model to
ground every statement in that briefing and to say when something was not found
rather than guess. The model never sees anything themob did not find, so it
cannot report a finding that is not real.

Qt-free and model-agnostic. The panel passes a real Claude client; the tests pass
a stub. The license gate and the Claude key are checked here, so the panel only
has to render the state this returns.
"""
from __future__ import annotations

import json

from ..mcp import tools
from . import license as licensing

_SYSTEM = (
    "You are themob's mobile application security assistant, helping a developer "
    "understand and fix the security findings in their own app. You are given, as "
    "JSON, the findings themob's analysis produced. 'weakness_groups' is the "
    "complete list of distinct weaknesses, each with how many times it was found; "
    "'findings' is a sample of them in full detail. Cover EVERY weakness group in "
    "your answer and use its count: when one weakness repeats (for example a key "
    "hardcoded 46 times) say how many and treat them together, and do not silently "
    "drop any group. Ground every statement in this data: explain what each "
    "weakness means in plain language, why it matters, and the concrete steps to "
    "fix it. Do not invent findings, severities or evidence, and never guess or "
    "print a secret's actual value. If the developer asks about something not in "
    "the data, say it was not among the findings rather than guessing. Be specific "
    "and practical: a junior developer should be able to act on your answer.\n\n"
    "Format for a narrow side panel: use short Markdown headings and numbered or "
    "bulleted lists, and put every command, file path, code or config value in "
    "`inline code` or a fenced ``` code block, one command per line. Do NOT use "
    "Markdown tables: the columns collapse here and a command containing a pipe "
    "breaks the layout. Write the same information as a list instead."
)

_DEFAULT_QUESTION = ("Explain these findings in plain language and give me a "
                     "prioritised, step-by-step plan to fix them.")

# The briefing goes in the prompt, and a free provider caps tokens per minute, so
# it stays compact without dropping coverage: every weakness is listed once with
# a count (weakness_groups), and a bounded set is described in full (one exemplar
# per weakness). That is how all 46 of a repeated finding get covered without
# sending 46 near-identical rows.
_MAX_EXEMPLARS = 16
_EVIDENCE_CHARS = 180
_FIX_CHARS = 400

# A secret's raw value must never be shipped to a third-party model, even when
# capture mode kept it locally. These mark a finding as a credential so its
# evidence is withheld from the briefing; the group count and the weakness are
# all the model needs to advise on it.
_SECRET_MARKERS = ("secret", "credential", "api-key", "api_key", "apikey",
                   "token", "high-entropy", "hardcoded", "private-key", "password")


def _is_secret_key(key) -> bool:
    k = (key or "").lower()
    return (k.startswith("android.secrets.") or k.startswith("ios.secrets.")
            or any(m in k for m in _SECRET_MARKERS))

# Licensing is a pitch-stage feature: kept, verified by its own tests and
# reachable through `themob assist`, but not enforced. The final-round build
# flips this to True; with it False the assistant is not licence-gated, so
# nothing has to be rebuilt or restarted when we turn it back on.
ENFORCE_LICENSE = False


def _compact(full: dict) -> dict:
    """A small, prompt-sized view of one finding: enough to explain and fix it."""
    loc = full.get("location") or {}
    where = " / ".join(str(loc[k]) for k in ("file", "class", "method", "component")
                       if loc.get(k))
    evidence = [e for e in (full.get("evidence") or []) if isinstance(e, str)]
    # Withhold a secret's value: the model advises from the weakness and count,
    # not the credential itself, which must not leave the machine.
    if _is_secret_key(full.get("weakness_key")):
        sample = "(value withheld: a hardcoded secret, see the Secrets page)"
    else:
        sample = evidence[0][:_EVIDENCE_CHARS] if evidence else None
    standards = full.get("standards") or {}
    return {
        "key": full.get("weakness_key"),
        "title": full.get("title"),
        "severity": full.get("severity"),
        "masvs": standards.get("masvs"),
        "mobile_top10": standards.get("mobile_top10"),
        "where": where or None,
        "evidence": sample,
        "fix": (full.get("remediation") or "")[:_FIX_CHARS] or None,
    }


def _briefing(home, project: str) -> tuple[dict, str]:
    """``(briefing, error)``: the real findings for a project, nothing invented.

    Covers the whole scan: every distinct weakness is listed once with a count
    (weakness_groups), and a bounded, representative set is described in full
    (findings), one exemplar per weakness first. So a weakness found 46 times is
    conveyed completely without 46 rows, and nothing is dropped the way a flat
    top-N list dropped every secret.
    """
    overview = tools.overview(home, project)
    if "error" in overview:
        return {}, overview["error"]
    listed = tools.list_findings(home, project).get("findings", [])

    groups: dict[str, dict] = {}
    order: list[str] = []
    for summary in listed:
        key = summary.get("weakness_key") or summary.get("title") or "unknown"
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "weakness": key,
                "title": summary.get("title"),
                "severity": summary.get("severity"),
                "count": 0,
                "_example": summary.get("fingerprint"),
            }
            order.append(key)
        group["count"] += 1

    findings = []
    for key in order[:_MAX_EXEMPLARS]:
        fingerprint = groups[key].get("_example")
        if not fingerprint:
            continue
        full = tools.get_finding(home, project, fingerprint)
        if "error" not in full:
            findings.append(_compact(full))

    weakness_groups = [{k: group[k] for k in
                        ("weakness", "title", "severity", "count")}
                       for group in (groups[key] for key in order)]
    return {
        "application": overview.get("application", {}),
        "severity_counts": overview.get("severity_counts", {}),
        "total_findings": len(listed),
        "weakness_groups": weakness_groups,
        "findings": findings,
    }, ""


def _prompt(briefing: dict, question: str) -> str:
    head = ("Here is what themob found in the developer's app, as JSON. "
            "'weakness_groups' is the complete list of weaknesses, each with a "
            "count; 'findings' is a detailed sample. Base your answer only on "
            "this, and account for every group in 'weakness_groups'.\n\n")
    body = json.dumps(briefing, default=str, separators=(",", ":"))
    ask = question.strip() or _DEFAULT_QUESTION
    return f"{head}{body}\n\nThe developer asks: {ask}"


def status(home=None) -> dict:
    """What the panel needs before any model call: licence and model readiness."""
    from . import llm

    if ENFORCE_LICENSE:
        lic = licensing.check(home)
        licensed, reason, licensee, tier = (lic.valid, lic.reason, lic.licensee,
                                            lic.tier)
    else:
        licensed, reason, licensee, tier = True, "licensing is not enforced", "", ""
    # Readiness only: preflight checks the key and the SDK without importing the
    # SDK or building a client, so the status line (shown at window construction)
    # does not pay the multi-second SDK import. The client is built lazily in
    # ask()/the agent, when the model is actually used.
    ready, reason_llm = llm.preflight()
    return {
        "licensed": licensed,
        "license_reason": reason,
        "licensee": licensee,
        "tier": tier,
        "enforced": ENFORCE_LICENSE,
        "provider": llm.current_provider(),
        "llm_ready": ready,
        "llm_reason": reason_llm,
    }


def ask(home=None, project: str = "", question: str = "", *, client=None) -> dict:
    """Answer a developer's question, grounded in the project's real findings.

    ``client`` is any object with ``complete(system, prompt)``; omitted, one is
    built from the configured provider (Claude, or a free one). Returns
    ``{"answer": ...}`` or ``{"error": ...}``. Gated by the licence only when
    enforcement is on, and honest when there is nothing to explain yet.
    """
    if ENFORCE_LICENSE:
        lic = licensing.check(home)
        if not lic.valid:
            return {"error": f"the assistant is a licensed feature: {lic.reason}"}

    briefing, error = _briefing(home, project)
    if error:
        return {"error": error}
    if not briefing.get("total_findings"):
        return {"answer": "There are no findings to explain yet. Authorize and "
                "analyze an app first, then I can walk you through what themob "
                "found and how to fix it."}

    if client is None:
        from . import llm
        client, key_error = llm.make_client()
        if client is None:
            return {"error": f"the assistant needs a model: {key_error}"}

    try:
        answer = client.complete(_SYSTEM, _prompt(briefing, question))
    except Exception as exc:                 # noqa: BLE001
        reason = str(exc)
        low = reason.lower()
        if any(s in low for s in ("rate_limit", "tokens per minute",
                                  "too large", " 413", "413 ")):
            return {"error": (
                "the model provider's free-tier limit was hit (tokens per "
                "minute). Wait a minute and retry, lower THEMOB_LLM_MAX_TOKENS, "
                "or use a smaller model (set THEMOB_LLM_MODEL=openai/gpt-oss-20b).")}
        if any(s in low for s in ("no longer available", "not_found",
                                  "model not found", "unknown model",
                                  "does not exist")):
            return {"error": (
                "the configured model is unavailable: the provider retired or "
                "renamed it. Set THEMOB_LLM_MODEL to a current model name (the "
                "provider's error usually names the replacement), then ask again."
                f"\n\n{reason}")}
        return {"error": f"the assistant could not reach the model: {reason}"}
    return {"answer": answer, "grounded_on": briefing.get("total_findings", 0)}
