"""Run MobSF against the fixture and print the rule ids it actually emits.

    python tools/probe_mobsf.py

Every rule id in ``adapters/mobsf_scan.py`` was wrong the first time it was
written, because it was written from memory. MobSF renames its rules between
releases, so the mapping is read off a live scan rather than transcribed, and
this is what reads it. Run it after bumping the pinned image in
``workers/mobsf/image.txt`` and correct the mapping from what it prints.
"""
import sys, tempfile, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from themob.adapters.mobsf_scan import MobSFScanAnalyzer, _SECTION_KEYS
from themob.audit.attestation import Attestation, AuditTrail
from themob.orchestrator.intake import intake
from themob.sandbox.runner import SandboxRunner
from themob.storage.db import open_database
from themob.storage.repositories import Repositories
from tests.fixtures.apk import build_apk

tmp = Path(tempfile.mkdtemp(prefix="mobsf-probe-"))
db = open_database(tmp / "t.db")
repos = Repositories(db)
audit = AuditTrail(repos.audit)
apk = build_apk(tmp / "shop.apk")
result = intake(apk, repos, audit, name="Probe", root=tmp / "home")
audit.record_attestation(result.project, Attestation(
    target_name="shop.apk", target_sha256=result.sha256, operator="probe",
    engagement_ref="PROBE", attested=True), repos.projects)

a = MobSFScanAnalyzer()
raw = a.run(result.target, result.workspace, SandboxRunner())
if raw.error:
    print("ERROR:", raw.error[:600]); raise SystemExit(1)

payload = raw.payload
print("mobsf version:", payload.get("tool_version"))
print("app:", payload.get("app"))
print()
for section, items in (payload.get("sections") or {}).items():
    mapping = _SECTION_KEYS.get(section, {})
    print(f"=== {section} ({len(items)} items) ===")
    for it in items:
        rule = it.get("rule", "")
        state = "MAPPED  " if rule in mapping else "unmapped"
        print(f"  {state} {rule}")
        for k, v in it.items():
            if k != "rule":
                print(f"           {k:12} {str(v)[:150]}")

print()
print("=== normalized ===")
norm = a.normalize(raw, result.target)
for f in norm.findings:
    print(f"  {f.severity.value:8} {f.weakness_key:46} {f.sources[0].tool:16} fp={f.fingerprint[:12]}")
cov = norm.entities[0].attributes["mobsf_scan"]
print()
print("  coverage:", {k: v for k, v in cov.items() if k != "unmapped"})
print("  unmapped:", cov["unmapped"])
print("  not mergeable:", cov["not_mergeable"])
