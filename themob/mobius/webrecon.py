"""Website attack surface, from TOPRECON, as data mobius can reason over.

mobius reviews mobile apps; TOPRECON (the operator's sibling tool) maps an
organisation's external web surface. To let mobius judge a website the same way
it judges an app, it runs TOPRECON arms-length, exactly as it runs every other
third-party tool: as a subprocess of TOPRECON's own CLI, unmodified, over a
boundary. Nothing here imports TOPRECON.

    python cli.py scan <domain> --type domain --json <out> -y --no-save --quiet

TOPRECON writes an entity graph as JSON. :func:`normalize` turns that graph into
two tables shaped like the rest of the catalog:

* ``mobius_web.assets``   - one row per discovered asset (host, IP, service, web
  technology, URL, certificate, cloud bucket, code repo, typosquat, ...).
* ``mobius_web.findings`` - one row per risk the graph carries (a leaked secret,
  a public bucket, a correlated CVE, a takeover candidate, a breach), in the
  same column vocabulary as ``mobius_scan.findings`` so the agents and the Critic
  need no new rules.

A discovered secret's value is evidence the operator needs to rotate the key, so
the local report keeps it; what is published to S3/Zetaris is always redacted,
the same rule the app scan follows.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .catalog import redact_evidence

# Asset entity types (everything that is a thing on the surface, not a problem).
ASSET_KINDS = {
    "domain", "subdomain", "ip", "asn", "netblock", "dns_record", "certificate",
    "port", "service", "web_tech", "url", "endpoint", "email", "code_repo",
    "whois_record", "company", "mobile_app", "desktop_app", "app_component",
}
# Entity types that are themselves findings, with a default severity when the
# graph node carries none.
FINDING_KINDS = {
    "leaked_secret": "critical", "vulnerability": "high", "cloud_bucket": "high",
    "breach_record": "high", "typosquat": "medium",
}
SECRET_KINDS = {"leaked_secret"}
_SEV = {"critical", "high", "medium", "low", "info"}


class WebReconError(RuntimeError):
    pass


def toprecon_dir() -> Path:
    """Where TOPRECON lives: MOBIUS_TOPRECON_DIR, or the sibling checkout."""
    env = os.environ.get("MOBIUS_TOPRECON_DIR", "").strip()
    candidates = [Path(env)] if env else []
    here = Path(__file__).resolve()
    candidates += [here.parents[3] / "TOPRECON", Path.home() / "Documents"
                   / "GitHub" / "TOPRECON"]
    for path in candidates:
        if (path / "cli.py").is_file():
            return path
    raise WebReconError("TOPRECON not found: set MOBIUS_TOPRECON_DIR to its "
                        "checkout (the folder with cli.py)")


def run_toprecon(target: str, *, active: bool = False, dorks: bool = False,
                 depth: int | None = None, note: str = "", timeout: float = 1800,
                 runner=None) -> dict:
    """Run TOPRECON over a domain and return its JSON graph.

    ``active`` and ``dorks`` stay off by default: a mobius web review is passive
    unless the operator asks otherwise, the same stance TOPRECON takes.
    """
    repo = toprecon_dir()
    out = Path(tempfile.mkdtemp(prefix="mobius-web-")) / "graph.json"
    cmd = [sys.executable, "cli.py", "scan", target, "--type", "domain",
           "--json", str(out), "-y", "--no-save", "--no-banner", "--quiet",
           "--note", note or "mobius web review"]
    if active:
        cmd.append("--active")
    if dorks:
        cmd.append("--dorks")
    if depth is not None:
        cmd += ["--depth", str(depth)]
    run = runner or _subprocess_runner
    code, stderr = run(cmd, repo, timeout)
    if not out.is_file():
        raise WebReconError(f"TOPRECON produced no graph (exit {code}): "
                            f"{stderr[:400]}")
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WebReconError(f"TOPRECON graph was unreadable: {exc}") from exc


def _subprocess_runner(cmd: list[str], cwd: Path, timeout: float) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                              timeout=timeout)                      # noqa: S603
    except subprocess.TimeoutExpired as exc:
        raise WebReconError(f"TOPRECON timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise WebReconError(f"could not launch TOPRECON: {exc}") from exc
    return proc.returncode, proc.stderr or ""


# -- normalise ----------------------------------------------------------------

@dataclass
class WebScan:
    target: str
    run_id: str
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    secrets_local: list[dict] = field(default_factory=list)   # full values, never published

    def tables(self) -> dict[str, list[dict]]:
        return {"mobius_web.assets": self.assets, "mobius_web.findings": self.findings}


def _fingerprint(target: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{target}|{kind}|{value}".encode()).hexdigest()[:16]


def _detail(data: dict) -> str:
    """A short, redacted attributes string for an asset row."""
    keep = {k: v for k, v in data.items()
            if k not in ("sample", "secret", "value", "token", "key", "password")}
    return redact_evidence(json.dumps(keep, default=str)[:300], secret=False)


def normalize(graph: dict, target: str, run_id: str) -> WebScan:
    """TOPRECON's JSON graph -> catalog rows (published copy is redacted)."""
    scan = WebScan(target=target, run_id=run_id)
    for node in graph.get("nodes", []):
        kind = str(node.get("type") or "")
        value = str(node.get("value") or node.get("key") or "")
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        sources = ",".join(str(s) for s in (node.get("sources") or []))
        risk = str(node.get("risk") or "").lower()
        reason = str(node.get("risk_reason") or "")
        if kind in ASSET_KINDS:
            scan.assets.append({
                "target": target, "run_id": run_id, "kind": kind,
                "value": value[:400], "depth": int(node.get("depth") or 0),
                "sources": sources[:200], "risk": risk if risk in _SEV else "",
                "risk_reason": reason[:240], "detail": _detail(data),
            })
        is_secret = kind in SECRET_KINDS
        if kind in FINDING_KINDS or risk in _SEV:
            severity = risk if risk in _SEV else FINDING_KINDS.get(kind, "info")
            raw = str(data.get("sample") or data.get("secret") or value)
            if is_secret:
                scan.secrets_local.append({"target": target, "value": raw,
                                           "where": str(data.get("file") or value),
                                           "rule": str(data.get("rule") or "")})
            # A leaked secret's own value is never a column that leaves the box:
            # the location is where it was found, not the key itself.
            location = (str(data.get("file") or data.get("matched_at") or "repo")
                        if is_secret else value)
            evidence = reason or str(data.get("detail") or data.get("name")
                                     or (location if is_secret else value))
            scan.findings.append({
                "target": target, "run_id": run_id,
                "fingerprint": _fingerprint(target, kind, value),
                "kind": kind, "category": _category(kind, data),
                "title": _title(kind, value if not is_secret else location, data)[:200],
                "weakness_key": _weakness_key(kind, data),
                "severity": severity,
                "confidence": 0.9 if sources.count(",") >= 1 else 0.7,
                "sources": sources[:200],
                "advisory_id": str(data.get("cve") or "").upper(),
                "exploited": 1 if (data.get("kev") in (True, "true", 1)) else 0,
                "location": location[:240],
                "evidence": redact_evidence(evidence[:300], secret=is_secret),
                "exposed_value": redact_evidence(raw[:120], secret=True)
                if is_secret else "",
            })
    scan.assets.sort(key=lambda r: (r["kind"], r["value"]))
    scan.findings.sort(key=lambda r: (_SEVRANK.get(r["severity"], 5), r["kind"]))
    return scan


_SEVRANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _category(kind: str, data: dict) -> str:
    return {"leaked_secret": "Leaked secret", "cloud_bucket": "Public cloud bucket",
            "vulnerability": "Vulnerability", "breach_record": "Breach exposure",
            "typosquat": "Lookalike domain"}.get(kind, kind.replace("_", " ").title())


def _weakness_key(kind: str, data: dict) -> str:
    if kind == "vulnerability" and data.get("cve"):
        return str(data["cve"]).upper()
    return {"leaked_secret": "web.secret.exposed",
            "cloud_bucket": "web.storage.public-bucket",
            "vulnerability": "web.vuln.correlated",
            "breach_record": "web.breach.exposure",
            "typosquat": "web.brand.typosquat"}.get(kind, f"web.{kind}")


def _title(kind: str, value: str, data: dict) -> str:
    if kind == "leaked_secret":
        return f"{data.get('rule') or 'Secret'} exposed in {data.get('file') or value}"
    if kind == "vulnerability":
        return str(data.get("name") or data.get("template") or value)
    if kind == "cloud_bucket":
        return f"Public cloud bucket {value}"
    if kind == "typosquat":
        return f"Lookalike domain {value}"
    if kind == "breach_record":
        return f"Breach exposure {value}"
    return value
