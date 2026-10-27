"""The human-readable export: one self-contained HTML file.

Self-contained on purpose. A report is emailed, attached to a ticket and opened
six months later on a machine that has never heard of themob, so it carries its
own styling and references nothing external. No fonts to fetch, no scripts, no
images: a report that needs the network to render is a report that will one day
render blank.

It shares ``app/theme.py`` with the console, which is Qt-free. Two palettes
would drift, and a screenshot from the console pasted next to the report should
not look like two different tools.

The house style holds here as it does in the UI: no bordered cards, hairlines
between sections, sentence case, and colour reserved for the severity ramp,
which stays semantic. A report that colours everything is one where nothing
stands out.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

from ..app import theme
from ..model.enums import Severity
from .model import Report, ReportedFinding, failed_stages

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                   Severity.LOW, Severity.INFO)


def _e(value) -> str:
    """Escape for HTML. Everything in a report came from a hostile package."""
    return escape("" if value is None else str(value), quote=True)


def _css() -> str:
    return f"""
    :root {{ color-scheme: dark; }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0; padding: 40px 48px 72px;
        background: {theme.BG_BASE}; color: {theme.TEXT_BODY};
        font-family: -apple-system, "Segoe UI", Roboto, system-ui, sans-serif;
        font-size: 14px; line-height: 1.55;
        max-width: 1100px;
    }}
    h1 {{ font-size: 26px; font-weight: 600; color: {theme.TEXT_PRIMARY};
         margin: 0 0 4px; }}
    h2 {{ font-size: 15px; font-weight: 600; color: {theme.TEXT_PRIMARY};
         margin: 40px 0 0; }}
    h3 {{ font-size: 14px; font-weight: 600; color: {theme.TEXT_PRIMARY};
         margin: 26px 0 2px; }}
    hr {{ border: 0; border-top: 1px solid {theme.RULE}; margin: 6px 0 14px; }}
    p {{ margin: 6px 0; }}
    .muted {{ color: {theme.TEXT_MUTED}; font-size: 12px; }}
    .mono {{ font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 8px 0 4px; }}
    th {{ text-align: left; font-weight: 400; color: {theme.TEXT_MUTED};
         font-size: 12px; padding: 4px 12px 4px 0;
         border-bottom: 1px solid {theme.RULE}; }}
    td {{ padding: 5px 12px 5px 0; vertical-align: top;
         border-bottom: 1px solid {theme.RULE}; }}
    .facts td:first-child {{ color: {theme.TEXT_MUTED}; width: 190px; }}
    .ramp {{ display: flex; gap: 34px; margin: 14px 0 4px; }}
    .ramp div {{ font-size: 12px; color: {theme.TEXT_MUTED}; }}
    .ramp span {{ display: block; font-size: 22px; font-weight: 500; }}
    .finding {{ margin: 22px 0 0; }}
    .tag {{ font-size: 11px; color: {theme.TEXT_MUTED}; margin-right: 14px; }}
    .exposed {{ color: {theme.WARN}; }}
    /* A hairline rather than a filled block: one ground colour, so nothing on
       the page floats above the rest of it. */
    .evidence {{ border-left: 2px solid {theme.RULE_STRONG}; padding: 2px 0 2px 10px;
                margin: 6px 0; white-space: pre-wrap; word-break: break-all; }}
    .note {{ border-left: 2px solid {theme.RULE_STRONG}; padding-left: 10px;
            margin: 6px 0; }}
    .warn {{ color: {theme.SEVERITY_COLORS[Severity.CRITICAL]}; }}
    """


def _severity_style(severity: Severity) -> str:
    return f"color:{theme.severity_color(severity)}"


def _count(n: int, plural: str) -> str:
    """"3 components", but "1 component".

    The labels come from ``theme`` in their plural form because that is what the
    console's column headers need, and a second map here would be a second place
    for the two to disagree. So the singular is derived from the plural instead.
    """
    label = plural.lower()
    if n == 1:
        if label.endswith("ies"):
            label = label[:-3] + "y"
        elif label.endswith("s") and not label.endswith("ss"):
            label = label[:-1]
    return f"{n} {label}"


def render(report: Report) -> str:
    """The whole report as one HTML document."""
    p = report.provenance
    parts: list[str] = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<title>themob report: {_e(p.package or p.project_name)}</title>",
        f"<style>{_css()}</style></head><body>",
        f"<h1>{_e(p.package or p.project_name)}</h1>",
        f"<p class=\"muted\">Mobile attack surface assessment, "
        f"generated {_e(p.generated_at)}</p>",
    ]
    parts.append(_provenance(report))
    parts.append(_summary(report))
    parts.append(_body(report))
    parts.append(_suppressed(report))
    parts.append("</body></html>")
    return "\n".join(part for part in parts if part)


def _provenance(report: Report) -> str:
    p = report.provenance
    rows = [
        ("Package", p.package or "unknown"),
        ("Version", " ".join(x for x in (p.version_name,
                                         f"({p.version_code})" if p.version_code
                                         else None) if x) or "unknown"),
        ("Platform", p.platform),
        ("SHA-256", p.sha256),
        ("Authorization", p.authorization_ref or "NOT RECORDED"),
        ("Authorized by", p.authorized_by or "NOT RECORDED"),
        ("Authorized at", p.authorized_at or "NOT RECORDED"),
        ("Generated", p.generated_at),
        ("themob", p.themob_version or "unknown"),
    ]
    if p.vuln_db_built:
        age = (f", {p.vuln_db_age_days} day(s) old"
               if p.vuln_db_age_days is not None else "")
        rows.append(("Vulnerability data", f"built {p.vuln_db_built}{age}"))
    if p.tools:
        rows.append(("Tools", ", ".join(f"{k} {v}" for k, v in sorted(p.tools.items()))))

    body = "".join(
        f"<tr><td>{_e(k)}</td><td class=\"mono\">{_e(v)}</td></tr>"
        for k, v in rows)

    out = [f"<h2>Provenance</h2><hr><table class=\"facts\">{body}</table>"]

    # An assessment with no attestation is a legal problem, not a formatting
    # one, so it is stated rather than left to the reader to notice.
    if not p.authorized:
        out.append("<p class=\"warn\">This project carries no authorization "
                   "attestation. Every themob run requires one, so this report "
                   "describes work that should not have happened.</p>")

    out.append(
        f"<p class=\"muted\">Audit trail: {_count(p.audit_entries, 'entries')}, "
        + ("chain verified." if p.audit_chain_ok else
           f"<span class=\"warn\">chain does NOT verify: "
           f"{_e(p.audit_chain_message)}</span>")
        + "</p>")

    failed = failed_stages(report)
    if failed:
        names = ", ".join(_e(s.get("analyzer") or s.get("stage")) for s in failed)
        subject = "it" if len(failed) == 1 else "they"
        out.append(f"<p class=\"warn\">Incomplete coverage: {names} did not "
                   f"finish, so anything {subject} would have found is missing "
                   "from this report.</p>")

    # A dependency scan matched against a stale feed under-reports silently, so
    # the report says so rather than letting "no vulnerable dependencies" stand
    # unqualified.
    if p.vuln_db_stale:
        out.append(f"<p class=\"warn\">The vulnerability database was "
                   f"{p.vuln_db_age_days} days old at scan time. A dependency "
                   "result is only as current as the data it was matched "
                   "against; rebuild the sbom worker to refresh it.</p>")
    return "".join(out)


def _summary(report: Report) -> str:
    cells = "".join(
        f"<div><span style=\"{_severity_style(s)}\">"
        f"{report.counts.get(s.value, 0)}</span>{s.value.title()}</div>"
        for s in _SEVERITY_ORDER)
    out = [f"<h2>Summary</h2><hr><div class=\"ramp\">{cells}</div>"]
    out.append(f"<p class=\"muted\">{_count(report.total, 'findings')} reported"
               + (f", {len(report.suppressed)} dismissed after review"
                  if report.suppressed else "")
               + ".</p>")
    if report.entity_counts:
        listed = ", ".join(_count(n, theme.entity_label(t))
                           for t, n in sorted(report.entity_counts.items()))
        out.append(f"<p class=\"muted\">Attack surface: {_e(listed)}.</p>")
    return "".join(out)


def _body(report: Report) -> str:
    out: list[str] = ["<h2>Findings</h2><hr>"]
    if not report.total:
        out.append("<p class=\"muted\">No findings were reported. That is not "
                   "the same as the app being safe: check the coverage above "
                   "for analyzers that did not run.</p>")
        return "".join(out)

    for section in report.sections:
        if not section.findings:
            continue
        out.append(f"<h3>{_e(section.title)}</h3>")
        out.append(f"<p class=\"muted\">{_e(section.description)}</p>")
        for reported in section.findings:
            out.append(_finding(reported))
    return "".join(out)


def _finding(reported: ReportedFinding) -> str:
    f = reported.finding
    tags = [
        f"<span class=\"tag\" style=\"{_severity_style(f.severity)}\">"
        f"{f.severity.value.title()}</span>",
        f"<span class=\"tag\">{int(round(f.confidence * 100))}% confidence</span>",
    ]
    if f.risk is not None:
        tags.append(f"<span class=\"tag\">risk {f.risk:.0f}</span>")
    if reported.exposed:
        tags.append("<span class=\"tag exposed\">Externally reachable</span>")
    if reported.tools:
        tags.append(f"<span class=\"tag\">{_e(', '.join(reported.tools))}</span>")

    out = [f"<div class=\"finding\"><strong>{_e(f.title)}</strong><br>",
           "".join(tags)]

    if f.score_rationale:
        out.append(f"<p class=\"muted\">Severity {_e(f.score_rationale)}.</p>")
    if f.description:
        out.append(f"<p>{_e(f.description)}</p>")
    if reported.exposure_path:
        out.append("<p class=\"muted\">Reachable via "
                   + _e(" -> ".join(reported.exposure_path)) + "</p>")

    standards = [x for x in (f.masvs_control, f.mobile_top10, f.cwe,
                             f.weakness_key) if x]
    if standards:
        out.append(f"<p class=\"muted mono\">{_e(' · '.join(standards))}</p>")

    for item in f.evidence[:10]:
        out.append(f"<div class=\"evidence mono\">{_e(item.value)}</div>")
        if item.artifact_path:
            out.append(f"<p class=\"muted mono\">{_e(item.artifact_path)}</p>")

    if f.remediation:
        out.append(f"<p><strong>Remediation.</strong> "
                   f"{_e(f.remediation.summary)}</p>")

    for note in reported.notes:
        out.append(f"<div class=\"note\">{_e(note.text)}"
                   f"<div class=\"muted\">{_e(note.author)} · "
                   f"{_e(note.created_at)}</div></div>")

    out.append("</div>")
    return "".join(out)


def _suppressed(report: Report) -> str:
    """Dismissed findings, with the reason each was dismissed.

    In the report rather than dropped from it. A reader has to be able to see
    what was decided not to matter, and who decided it.
    """
    if not report.suppressed:
        return ""
    rows = []
    for reported in report.suppressed:
        reason = reported.notes[-1].text if reported.notes else "no reason recorded"
        who = reported.notes[-1].author if reported.notes else "unknown"
        rows.append(
            f"<tr><td style=\"{_severity_style(reported.finding.severity)}\">"
            f"{reported.finding.severity.value.title()}</td>"
            f"<td>{_e(reported.finding.title)}</td>"
            f"<td>{_e(reported.verdict)}</td>"
            f"<td>{_e(reason)}<div class=\"muted\">{_e(who)}</div></td></tr>")
    return ("<h2>Dismissed after review</h2><hr>"
            "<p class=\"muted\">These were reported by a scanner and judged not "
            "to apply. Every dismissal is in the audit trail.</p>"
            "<table><tr><th>Severity</th><th>Finding</th><th>Verdict</th>"
            "<th>Reason</th></tr>" + "".join(rows) + "</table>")


def write(report: Report, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(report), encoding="utf-8")
    return target
