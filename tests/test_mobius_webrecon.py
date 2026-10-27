"""Ingesting a TOPRECON graph into the web catalog, arms-length and redacted."""
from __future__ import annotations

import json

import pytest

from themob.mobius.catalog import CATALOG, OPTIONAL
from themob.mobius.webrecon import (WebReconError, normalize, run_toprecon,
                                    toprecon_dir)

GRAPH = {
    "seed": "acme.io",
    "nodes": [
        {"type": "domain", "value": "acme.io", "key": "domain:acme.io", "depth": 0,
         "sources": ["seed"], "data": {}},
        {"type": "subdomain", "value": "api.acme.io", "depth": 1,
         "sources": ["crtsh", "subfinder"], "data": {"ip": "10.0.0.5"}},
        {"type": "service", "value": "api.acme.io:443 nginx", "depth": 2,
         "sources": ["httpx"], "data": {"port": 443, "product": "nginx"}},
        {"type": "leaked_secret", "value": "AIzaSyDxxxxEXAMPLExxxxEXAMPLExxxx1234",
         "depth": 2, "sources": ["gitleaks"],
         "data": {"rule": "google-api-key", "file": "app/config.js",
                  "sample": "AIzaSyDxxxxEXAMPLExxxxEXAMPLExxxx1234"},
         "risk": "critical", "risk_reason": "Live Google API key in public repo."},
        {"type": "cloud_bucket", "value": "acme-backups", "depth": 2,
         "sources": ["s3scanner"], "data": {"public": True},
         "risk": "high", "risk_reason": "Publicly listable S3 bucket."},
        {"type": "vulnerability", "value": "CVE-2021-0341 @ api.acme.io", "depth": 3,
         "sources": ["nuclei"],
         "data": {"cve": "CVE-2021-0341", "name": "OkHttp cert bypass", "kev": True},
         "risk": "high", "risk_reason": "Correlated CVE."},
        {"type": "typosquat", "value": "acme-io.com", "depth": 1, "sources": ["dnstwist"],
         "data": {}, "risk": "medium", "risk_reason": "Lookalike domain."},
    ],
    "edges": [],
}


def test_catalog_has_optional_web_tables():
    assert "mobius_web.assets" in CATALOG and "mobius_web.findings" in CATALOG
    assert {"mobius_web.assets", "mobius_web.findings"} <= OPTIONAL
    assert CATALOG["mobius_web.findings"]["optional"] is True


def test_normalize_splits_assets_and_findings():
    scan = normalize(GRAPH, "acme.io", "web-1")
    kinds = {a["kind"] for a in scan.assets}
    assert {"domain", "subdomain", "service"} <= kinds
    assert "leaked_secret" not in kinds             # a secret is a finding, not an asset
    finds = {f["kind"]: f for f in scan.findings}
    assert set(finds) == {"leaked_secret", "cloud_bucket", "vulnerability", "typosquat"}
    assert finds["vulnerability"]["advisory_id"] == "CVE-2021-0341"
    assert finds["vulnerability"]["exploited"] == 1
    assert finds["cloud_bucket"]["severity"] == "high"
    # findings sort critical first
    assert scan.findings[0]["severity"] == "critical"


def test_the_published_copy_never_carries_a_raw_secret():
    scan = normalize(GRAPH, "acme.io", "web-1")
    blob = json.dumps(scan.tables())
    assert "AIzaSyDxxxxEXAMPLExxxxEXAMPLExxxx1234" not in blob
    secret = next(f for f in scan.findings if f["kind"] == "leaked_secret")
    assert secret["exposed_value"].startswith("AIza") and "****" in secret["exposed_value"]
    # the full value is kept locally for rotation, never in the published tables
    assert scan.secrets_local[0]["value"] == "AIzaSyDxxxxEXAMPLExxxxEXAMPLExxxx1234"


def test_rows_match_the_catalog_columns():
    scan = normalize(GRAPH, "acme.io", "web-1")
    for name, rows in scan.tables().items():
        allowed = set(CATALOG[name]["columns"])
        for row in rows:
            assert set(row) <= allowed, f"{name} has stray columns {set(row) - allowed}"


def test_run_toprecon_reads_the_json_a_fake_cli_writes(tmp_path, monkeypatch):
    # A fake runner stands in for the TOPRECON subprocess: it writes the graph
    # where the CLI's --json flag points, then reports success.
    import themob.mobius.webrecon as wr
    monkeypatch.setattr(wr, "toprecon_dir", lambda: tmp_path)
    (tmp_path / "cli.py").write_text("# fake", encoding="utf-8")

    def fake_runner(cmd, cwd, timeout):
        out = cmd[cmd.index("--json") + 1]
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(GRAPH, fh)
        return 0, ""

    graph = run_toprecon("acme.io", runner=fake_runner)
    assert graph["seed"] == "acme.io"


def test_run_toprecon_reports_when_no_graph_is_written(tmp_path, monkeypatch):
    import themob.mobius.webrecon as wr
    monkeypatch.setattr(wr, "toprecon_dir", lambda: tmp_path)
    with pytest.raises(WebReconError, match="no graph"):
        run_toprecon("acme.io", runner=lambda cmd, cwd, timeout: (1, "boom"))
