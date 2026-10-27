"""themob gitleaks worker: find secret-shaped strings in what earlier stages produced.

Runs inside a network-less container. ``/scan`` is a read-only mount of the
project's artifacts directory: apktool's decoded resources and assets, and
jadx's decompiled Java. The APK itself is deliberately not mounted, because
nothing here needs it.

Writes one JSON document to stdout and never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

Contract with ``themob/adapters/gitleaks_scan.py``:

    { "ok": bool, "error": str|null, "tool": "gitleaks", "tool_version": str,
      "findings": [ { "rule": str, "description": str, "file": str,
                      "line": int, "match": str, "secret_sha256": str,
                      "entropy": float|null, "tags": [str] } ],
      "scanned": {"files": int, "bytes": int}, "truncated": bool }

The secret value itself is never returned. A pentest console that copies live
credentials into its own database and its own report has created a second place
to leak them from; the SHA-256 is enough to dedupe and to prove a match, and the
tester can read the real value from the artifact the finding cites.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import traceback

SCAN_DIR = "/scan"
REPORT = "/tmp/gitleaks-report.json"

# Caps. gitleaks on a large app can emit tens of thousands of hits, and this
# process is the one holding them in memory before the engine ever sees them.
MAX_FINDINGS = 2000
MAX_STRING = 2048
MAX_MATCH = 200

# A redaction that still lets a human recognise the hit in the cited file.
KEEP_PREFIX = 4
KEEP_SUFFIX = 4

# The operator opt-in, forwarded as an environment variable by the adapter. OFF
# by default: the value is redacted here and never leaves the container. When
# set, the full match is allowed out so the engine can show it behind its
# password gate. Read once at import; the container runs one scan.
CAPTURE_SECRETS = (os.environ.get("THEMOB_CAPTURE_SECRET_VALUES") or "") \
    .strip().lower() in ("1", "true", "yes", "on")


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def redact(secret: str) -> str:
    """Show enough to recognise the hit, never enough to use it."""
    if not secret:
        return ""
    if len(secret) <= KEEP_PREFIX + KEEP_SUFFIX:
        return "*" * len(secret)
    hidden = len(secret) - KEEP_PREFIX - KEEP_SUFFIX
    return secret[:KEEP_PREFIX] + "*" * hidden + secret[-KEEP_SUFFIX:]


def tool_version() -> str:
    try:
        out = subprocess.run(["gitleaks", "version"], capture_output=True,
                             text=True, timeout=30)
        return clip((out.stdout or out.stderr).strip(), 64) or "unknown"
    except Exception:                                   # noqa: BLE001
        return "unknown"


def inventory(root: str):
    """How much there was to look at, for the run record."""
    files = 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            files += 1
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
            if files >= 200000:                         # a hostile tree
                return {"files": files, "bytes": total, "truncated": True}
    return {"files": files, "bytes": total, "truncated": False}


def relative(path: str) -> str:
    """Report paths relative to the scan root, never the container's layout."""
    if not path:
        return ""
    normalised = path.replace("\\", "/")
    prefix = SCAN_DIR.rstrip("/") + "/"
    if normalised.startswith(prefix):
        normalised = normalised[len(prefix):]
    return clip(normalised, 1024)


def run_gitleaks() -> tuple[int, str]:
    """Scan the tree. Exit code 1 means "leaks found", which is not an error."""
    command = [
        "gitleaks", "dir", SCAN_DIR,
        "--report-format", "json",
        "--report-path", REPORT,
        "--no-banner",
        # The tree is not a git repository, and gitleaks must not try to be
        # clever about one. "dir" already implies this; --no-git is not a flag
        # on this subcommand, so nothing else is needed.
        "--exit-code", "1",
        # Deliberately NOT --redact. That masks the value inside gitleaks' own
        # report, and this worker would then redact an already-masked string
        # into a row of asterisks that tells a tester nothing. The report lives
        # in the container's tmpfs, is never mounted out, and dies with the
        # container; redact() below is what decides what actually leaves here.
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=900)
    except subprocess.TimeoutExpired:
        return 124, "gitleaks timed out"
    except OSError as exc:
        return 127, f"gitleaks could not be started: {exc}"
    stderr = clip((completed.stderr or "").strip(), 4000) or ""
    return completed.returncode, stderr


def read_report():
    if not os.path.exists(REPORT):
        return []
    try:
        with open(REPORT, "r", encoding="utf-8", errors="replace") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return []
    return document if isinstance(document, list) else []


def normalise(raw):
    """gitleaks' own record -> themob's bounded shape."""
    findings = []
    truncated = False
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break

        secret = entry.get("Secret") or ""
        if not isinstance(secret, str):
            secret = str(secret)
        match = entry.get("Match") or ""
        if not isinstance(match, str):
            match = str(match)

        line = entry.get("StartLine")
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = None

        entropy = entry.get("Entropy")
        try:
            entropy = round(float(entropy), 3)
        except (TypeError, ValueError):
            entropy = None

        tags = entry.get("Tags") or []
        if not isinstance(tags, list):
            tags = []

        findings.append({
            "rule": clip(entry.get("RuleID"), 128) or "unknown",
            "description": clip(entry.get("Description"), 512) or "",
            "file": relative(entry.get("File") or ""),
            "line": line,
            # Redacted here, and separately fingerprinted. gitleaks' own report
            # holds the value in the clear, which is why it stays in the
            # container's tmpfs and only this redaction leaves.
            "match": redact(clip(match, MAX_MATCH)),
            # The full match leaves only when the operator opted in; otherwise
            # null, and the redaction above is all there is.
            "value": clip(match, MAX_MATCH) if CAPTURE_SECRETS else None,
            "secret_sha256": hashlib.sha256(secret.encode("utf-8",
                                                          "replace")).hexdigest(),
            "entropy": entropy,
            "tags": [clip(t, 64) for t in tags if isinstance(t, str)][:16],
        })
    return findings, truncated


def main() -> int:
    try:
        if not os.path.isdir(SCAN_DIR):
            print(json.dumps({
                "ok": False,
                "error": "nothing to scan: /scan was not mounted",
                "tool": "gitleaks",
            }))
            return 0

        counts = inventory(SCAN_DIR)
        code, stderr = run_gitleaks()

        # 0 = clean, 1 = leaks found. Anything else is a real failure.
        if code not in (0, 1):
            print(json.dumps({
                "ok": False,
                "tool": "gitleaks",
                "tool_version": tool_version(),
                "error": clip(stderr, 2000) or f"gitleaks exited with code {code}",
            }))
            return 0

        findings, truncated = normalise(read_report())
        print(json.dumps({
            "ok": True,
            "error": None,
            "tool": "gitleaks",
            "tool_version": tool_version(),
            "findings": findings,
            "scanned": {"files": counts["files"], "bytes": counts["bytes"]},
            "truncated": truncated or counts["truncated"],
        }))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print(json.dumps({
            "ok": False,
            "tool": "gitleaks",
            "error": clip(f"{type(exc).__name__}: {exc}", 2000),
            "trace": clip(traceback.format_exc(), 4000),
        }))
        return 0


if __name__ == "__main__":
    sys.exit(main())
