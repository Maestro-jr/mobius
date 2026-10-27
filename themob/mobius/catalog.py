"""The tables mobius serves through Zetaris, and how a scan becomes rows.

Three kinds of source, deliberately fragmented, unified by Zetaris SQL:

* ``mobius_scan.*``  - this app's scan: the app, its findings with their
  cross-tool votes and advisory ids, and its attack-surface entities. Exported
  from the themob store by :func:`export_scan` and published where Zetaris
  can read it (see :mod:`themob.mobius.publish`).
* ``mobius_intel.kev`` / ``mobius_intel.epss`` - public threat intelligence,
  registered in Zetaris as REST tables over the CISA and FIRST APIs.
* ``mobius_intel.obligations`` - the sector -> regulation map
  (``knowledge/sectors.json``), so "a fintech app in Cameroon must..." is a
  join, not something a model remembers.

``CATALOG`` is also the Executor's schema prompt: the model writes SQL against
exactly these names and columns.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..model.enums import EntityType

CATALOG: dict[str, dict] = {
    "mobius_scan.app": {
        "about": "the scanned app (one row per run)",
        "columns": {
            "run_id": "mobius run id", "package": "app id, e.g. com.bank.app",
            "label": "display name", "version": "version name",
            "platform": "android or ios", "permissions": "comma-separated permissions",
            "libraries": "comma-separated bundled library names",
            "sha256": "package hash"},
    },
    "mobius_scan.findings": {
        "about": "security findings, deduplicated across tools",
        "columns": {
            "run_id": "mobius run id", "package": "app id",
            "fingerprint": "stable finding id (cite this)",
            "weakness_key": "canonical weakness (MASWE or internal rule)",
            "maswe_id": "MASWE id", "title": "finding title",
            "severity": "critical/high/medium/low/info",
            "confidence": "0..1, raised when independent tools agree",
            "votes": "number of distinct tools that reported it",
            "tools": "comma-separated tool names",
            "status": "new/confirmed/false_positive/accepted_risk",
            "advisory_id": "CVE/GHSA id for vulnerable-dependency findings, else empty",
            "masvs_category": "MASVS category", "cwe": "CWE id",
            "location": "file / class / component", "evidence": "short evidence text",
            "risk": "engine risk score 0..10"},
    },
    "mobius_scan.entities": {
        "about": "attack-surface entities: components, permissions, endpoints, libraries, secrets",
        "columns": {
            "run_id": "mobius run id", "package": "app id", "entity_id": "id",
            "type": "component/permission/endpoint/library/secret/deep_link/...",
            "key": "natural key (class name, URL, library coordinate)",
            "label": "display name", "exported": "1 if an exported component",
            "detail": "short attributes text"},
    },
    "mobius_intel.kev": {
        "about": "CISA Known Exploited Vulnerabilities catalog (live feed)",
        "columns": {
            "cve_id": "CVE id", "vendor": "vendor", "product": "product",
            "name": "vulnerability name", "date_added": "date added to KEV",
            "ransomware": "known ransomware use", "action": "required action"},
    },
    "mobius_intel.epss": {
        "about": "FIRST EPSS exploit prediction scores for this app's CVEs (live API)",
        "columns": {"cve": "CVE id", "epss": "probability of exploitation in 30 days",
                    "percentile": "percentile rank", "date": "score date"},
    },
    "mobius_intel.obligations": {
        "about": "sector -> regulations and the mobile controls they bear on (advisory)",
        "columns": {
            "sector": "fintech/health/education/kids/ecommerce/government/social/general",
            "framework": "law or standard", "jurisdiction": "where it applies",
            "applies_because": "why this sector triggers it",
            "masvs_categories": "comma-separated MASVS categories it bears on",
            "certainty": "established or verify (check with counsel)"},
    },
    # Web attack surface, from a TOPRECON recon run (see webrecon.py). Present
    # only after a web review; absent on an app-only run, so marked optional.
    "mobius_web.assets": {
        "about": "external web attack surface for one target (hosts, services, "
                 "tech, URLs, certs, buckets, repos)",
        "optional": True, "surface": "web",
        "columns": {
            "target": "the reviewed domain", "run_id": "mobius run id",
            "kind": "domain/subdomain/ip/port/service/web_tech/url/certificate/"
                    "cloud_bucket/code_repo/typosquat/...",
            "value": "the asset (host, URL, coordinate)", "depth": "pivot depth",
            "sources": "comma-separated tools that found it",
            "risk": "critical/high/medium/low/info, if the asset itself is risky",
            "risk_reason": "why it is risky", "detail": "short attributes text"},
    },
    "mobius_web.findings": {
        "about": "security findings on the web target: leaked secrets, public "
                 "buckets, correlated CVEs, takeover candidates, breaches",
        "optional": True, "surface": "web",
        "columns": {
            "target": "the reviewed domain", "run_id": "mobius run id",
            "fingerprint": "stable finding id (cite this)",
            "kind": "leaked_secret/vulnerability/cloud_bucket/breach_record/typosquat",
            "category": "human category", "title": "finding title",
            "weakness_key": "canonical web weakness",
            "severity": "critical/high/medium/low/info",
            "confidence": "0..1, higher when more than one tool agrees",
            "sources": "comma-separated tools", "advisory_id": "CVE id, else empty",
            "exploited": "1 if KEV-listed", "location": "where it was found",
            "evidence": "short evidence text (secrets redacted)",
            "exposed_value": "a discovered secret, redacted for publishing"},
    },
}

# Tables that need not exist for a run to proceed (web tables on an app review,
# and the reverse). `doctor` reports these as skipped rather than failed.
OPTIONAL = {name for name, spec in CATALOG.items() if spec.get("optional")}


def schema_prompt(available: set[str] | None = None) -> str:
    """The catalog as the Executor sees it."""
    lines = []
    for name, spec in CATALOG.items():
        if available is not None and name not in available:
            continue
        cols = ", ".join(f"{c} ({d})" for c, d in spec["columns"].items())
        lines.append(f"- {name}: {spec['about']}. Columns: {cols}")
    return "\n".join(lines)


# -- export --------------------------------------------------------------------

_KNOWLEDGE = Path(__file__).resolve().parents[2] / "knowledge" / "sectors.json"


def sector_knowledge() -> dict:
    return json.loads(_KNOWLEDGE.read_text(encoding="utf-8"))


def obligation_rows() -> list[dict]:
    rows = []
    for sector, spec in sector_knowledge()["sectors"].items():
        for item in spec["obligations"]:
            rows.append({"sector": sector, "framework": item["framework"],
                         "jurisdiction": item["jurisdiction"],
                         "applies_because": item["applies_because"],
                         "masvs_categories": ",".join(item["masvs_categories"]),
                         "certainty": item["certainty"]})
    return rows


def _clip(value, width: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= width else text[:width - 3] + "..."


_SECRET_TOOLS = {"apkleaks", "gitleaks", "secrets"}
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{20,}")


def _mask(token: str) -> str:
    return token[:4] + "****" + token[-2:] if len(token) > 8 else "****"


def redact_evidence(text: str, *, secret: bool) -> str:
    """Evidence fit to leave the machine.

    A secret finding keeps only its label ("Google_API_Key: AIza****xY"); any
    other finding has long opaque tokens masked, so a key quoted in a code
    snippet does not ride along. The full value stays in the local store.
    """
    if secret and ":" in text:
        label, _, value = text.partition(":")
        return f"{label}: {_mask(value.strip())}"
    if secret:
        return _mask(text.strip())
    return _LONG_TOKEN.sub(lambda m: _mask(m.group(0)), text)


def export_scan(repos, project_id: str, run_id: str) -> dict[str, list[dict]]:
    """The ``mobius_scan`` tables for one project, ready to publish."""
    project = repos.projects.get(project_id)
    if project is None:
        raise KeyError(f"no project {project_id}")
    entities = repos.entities.list(project_id)
    app = next((e for e in entities if e.type == EntityType.APP), None)
    package = app.key if app else project.name
    permissions = sorted(e.key for e in entities if e.type == EntityType.PERMISSION)
    libraries = sorted({(e.label or e.key) for e in entities
                        if e.type == EntityType.LIBRARY})
    app_row = {
        "run_id": run_id, "package": package,
        "label": (app.label if app and app.label else project.name),
        "version": str((app.attributes if app else {}).get("version_name", "")),
        "platform": project.target_platform,
        "permissions": _clip(",".join(permissions), 4000),
        "libraries": _clip(",".join(libraries), 4000),
        "sha256": project.source_sha256,
    }
    finding_rows = []
    for f in repos.findings.list(project_id):
        sources = repos.findings.sources(f.id)
        tools = sorted({s.tool for s in sources})
        advisory = next((s.rule for s in sources if s.rule and
                         s.rule.upper().startswith(("CVE-", "GHSA-"))), "")
        loc = f.location
        location = ""
        if loc is not None:
            location = " ".join(str(p) for p in (loc.component, loc.file, loc.clazz,
                                                 loc.line) if p)
        evidence = repos.findings.evidence(f.id)
        secret = bool(_SECRET_TOOLS & set(tools)) or "secret" in (f.weakness_key or "")
        finding_rows.append({
            "run_id": run_id, "package": package, "fingerprint": f.fingerprint[:16],
            "weakness_key": f.weakness_key or "", "maswe_id": f.maswe_id or "",
            "title": _clip(f.title, 200), "severity": f.severity.value,
            "confidence": round(f.confidence, 3), "votes": len(tools),
            "tools": ",".join(tools), "status": f.status.value,
            "advisory_id": advisory.upper() if advisory else "",
            "masvs_category": f.masvs_category.value if f.masvs_category else "",
            "cwe": f.cwe or "", "location": _clip(location, 240),
            "evidence": _clip(redact_evidence(evidence[0].value if evidence else "",
                                              secret=secret), 300),
            "risk": round(f.risk, 2) if f.risk is not None else None,
        })
    entity_rows = []
    for e in entities:
        attrs = dict(e.attributes)
        if e.type == EntityType.SECRET:                # never publish secret material
            attrs = {k: v for k, v in attrs.items() if k in ("rule", "kind", "file")}
        entity_rows.append({
            "run_id": run_id, "package": package, "entity_id": e.id[:12],
            "type": e.type.value, "key": _clip(e.key, 300),
            "label": _clip(e.label or "", 200),
            "exported": 1 if attrs.get("exported") else 0,
            "detail": _clip(redact_evidence(json.dumps(attrs, default=str),
                                            secret=False), 300),
        })
    return {"mobius_scan.app": [app_row], "mobius_scan.findings": finding_rows,
            "mobius_scan.entities": entity_rows}
