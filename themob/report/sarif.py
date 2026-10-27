"""SARIF export: themob findings as something a build pipeline understands.

The HTML report is for a person and the JSON is for a diff. SARIF is for a
machine that gates a merge: GitHub code scanning, and every CI system that reads
the format, ingests it and can fail a pull request when a critical finding
appears. It is what turns themob from a thing a tester opens into a control that
runs on every build.

Two SARIF details are load-bearing here:

* **partialFingerprints.** themob already keys every finding by a stable
  fingerprint. Handing that to SARIF as a partial fingerprint is what lets the
  consumer track one finding across runs, so a known, triaged issue does not
  reappear as new the next time the pipeline runs.
* **security-severity.** GitHub ranks and filters by a numeric property, not by
  the SARIF level word. Emitting both means themob's severity ramp survives into
  the code-scanning UI instead of collapsing to error/warning/note.

Written from the assembled :class:`~themob.report.model.Report`, the same object
the HTML and JSON writers use, so a finding reads the same in all three.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import __version__
from ..model.enums import Severity
from ..model.findings import Finding
from .model import Report, ReportedFinding

SARIF_VERSION = "2.1.0"
SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
          "Schemas/sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/Maestro-jr/themob"

# SARIF has three levels. themob has five severities, so the ramp is carried in
# security-severity (a number) and the level is the coarse bucket GitHub needs.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads security-severity as CVSS-like, 0 to 10, and buckets it into
# critical/high/medium/low itself. These match its own thresholds.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def to_sarif(report: Report) -> dict[str, Any]:
    """The whole report as one SARIF log."""
    reported = report.reported
    rules, rule_index = _rules(reported)

    results = [_result(r, rule_index) for r in reported]

    return {
        "version": SARIF_VERSION,
        "$schema": SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "themob",
                    "version": __version__,
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                }
            },
            # What was assessed, so a result is traceable to a build.
            "properties": {
                "package": report.provenance.package,
                "sha256": report.provenance.sha256,
                "generated_at": report.provenance.generated_at,
                "themob_version": report.provenance.themob_version,
                # A consumer gating a build should know if the dependency data
                # was stale when the scan ran.
                "vulnerability_db_built": report.provenance.vuln_db_built,
                "vulnerability_db_stale": report.provenance.vuln_db_stale,
            },
            "results": results,
        }],
    }


def _rules(reported: list[ReportedFinding]) -> tuple[list[dict], dict[str, int]]:
    """One SARIF rule per weakness key seen, and the index results point at.

    A rule per weakness rather than per finding: SARIF separates the definition
    of an issue class from its occurrences, and themob's canonical weakness key
    is exactly that class.
    """
    rules: list[dict] = []
    index: dict[str, int] = {}
    for reported_finding in reported:
        finding = reported_finding.finding
        key = finding.weakness_key or "themob.unknown"
        if key in index:
            continue
        index[key] = len(rules)
        rule: dict[str, Any] = {
            "id": key,
            "name": _pascal(key),
            "shortDescription": {"text": finding.title},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "tags": _tags(finding),
            },
        }
        if finding.description:
            rule["fullDescription"] = {"text": finding.description}
        if finding.remediation:
            rule["help"] = {"text": finding.remediation.summary}
        standards = _standards_uri(finding)
        if standards:
            rule["helpUri"] = standards
        rules.append(rule)
    return rules, index


def _result(reported: ReportedFinding, rule_index: dict[str, int]) -> dict:
    finding = reported.finding
    key = finding.weakness_key or "themob.unknown"

    result: dict[str, Any] = {
        "ruleId": key,
        "ruleIndex": rule_index[key],
        "level": _LEVEL[finding.severity],
        "message": {"text": _message(reported)},
        "locations": [_location(finding)],
        # The stable identity, so a consumer tracks this finding across runs
        # instead of re-reporting a triaged issue as new.
        "partialFingerprints": {"themob/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "confidence": round(finding.confidence, 3),
            "externally_reachable": reported.exposed,
            "reported_by": reported.tools,
        },
    }
    if finding.risk is not None:
        result["properties"]["risk"] = finding.risk
    return result


def _location(finding: Finding) -> dict:
    """A physical location when there is a file, a logical one otherwise.

    Most themob findings are about a manifest fact or a graph entity, not a line
    of code, so a logical location (the component or weakness) is the honest
    answer rather than pointing at a file that does not exist.
    """
    location = finding.location
    if location and location.file:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": location.file},
        }
        if location.line:
            physical["region"] = {"startLine": max(int(location.line), 1)}
        return {"physicalLocation": physical}

    name = None
    if location:
        name = location.component or location.clazz
    return {"logicalLocations": [{
        "name": name or (finding.weakness_key or finding.title),
        "kind": "namespace",
    }]}


def _message(reported: ReportedFinding) -> str:
    finding = reported.finding
    text = finding.title
    if reported.exposed and reported.exposure_path:
        text += " (reachable via " + " -> ".join(reported.exposure_path) + ")"
    elif reported.exposed:
        text += " (externally reachable)"
    return text


def _tags(finding: Finding) -> list[str]:
    tags = ["security"]
    for value in (finding.masvs_control, finding.mobile_top10, finding.cwe,
                  finding.maswe_id):
        if value:
            tags.append(value)
    return tags


def _standards_uri(finding: Finding) -> str | None:
    if finding.cwe and finding.cwe.upper().startswith("CWE-"):
        number = finding.cwe.split("-", 1)[1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    if finding.masvs_control:
        return "https://mas.owasp.org/MASVS/"
    return None


def _pascal(key: str) -> str:
    """A SARIF rule name from a dotted weakness key: readable, no spaces."""
    parts = [segment for chunk in key.split(".") for segment in chunk.split("-")]
    return "".join(part.capitalize() for part in parts if part) or "Unknown"


def write(report: Report, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(to_sarif(report), indent=2, sort_keys=False) + "\n",
        encoding="utf-8")
    return target
