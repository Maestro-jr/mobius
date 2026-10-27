"""themob semgrep worker: insecure patterns in the decompiled code.

Runs inside a network-less container. ``/scan`` is a read-only mount of the
project's artifacts directory, which by this stage holds jadx's decompiled Java
and apktool's decoded resources.

Writes one JSON document to stdout and never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

**The rules are baked into the image, and that is load-bearing.** semgrep
resolves a ruleset like ``p/java`` by calling its registry. This container has
no network, so a run configured that way would fail, or worse, run with an
empty ruleset and report a clean bill of health for every app. The rules are
copied in at build time and referenced by path.

Contract with ``themob/adapters/semgrep_scan.py``:

    { "ok": bool, "error": str|null, "tool": "semgrep", "tool_version": str,
      "findings": [ {"rule": str, "weakness": str, "message": str,
                     "file": str, "line": int, "snippet": str,
                     "severity": str, "confidence": str} ],
      "scanned": {"files": int, "rules": int}, "truncated": bool,
      "rule_errors": [str] }
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback

SCAN_DIR = "/scan"
RULES_DIR = "/opt/themob/rules"

MAX_FINDINGS = 2000
MAX_STRING = 2048
MAX_SNIPPET = 400


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def relative(path: str) -> str:
    """Report paths relative to the scan root, never the container's layout."""
    if not path:
        return ""
    normalised = path.replace("\\", "/")
    prefix = SCAN_DIR.rstrip("/") + "/"
    if normalised.startswith(prefix):
        normalised = normalised[len(prefix):]
    return clip(normalised, 1024)


def tool_version() -> str:
    try:
        out = subprocess.run(["semgrep", "--version"], capture_output=True,
                             text=True, timeout=60)
        return clip((out.stdout or out.stderr).strip(), 64) or "unknown"
    except Exception:                                   # noqa: BLE001
        return "unknown"


def count_rules() -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(RULES_DIR):
        total += sum(1 for n in filenames if n.endswith((".yml", ".yaml")))
    return total


def count_files(root: str) -> int:
    total = 0
    for _dirpath, _dirnames, filenames in os.walk(root):
        total += len(filenames)
        if total >= 200000:
            break
    return total


def run_semgrep():
    """Scan with the baked-in rules. Exit 1 means findings, which is not an error."""
    command = [
        "semgrep", "scan",
        "--config", RULES_DIR,
        "--json",
        "--quiet",
        # No registry, no telemetry, no version check. All three would try to
        # reach the network, and there is none.
        "--metrics", "off",
        "--disable-version-check",
        # Decompiled code is not the app's own source, so a .semgrepignore or a
        # .gitignore inside the artifacts tree must not silently drop files.
        "--no-git-ignore",
        "--timeout", "60",
        SCAN_DIR,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=1500)
    except subprocess.TimeoutExpired:
        return None, "semgrep timed out"
    except OSError as exc:
        return None, f"semgrep could not be started: {exc}"

    if completed.returncode not in (0, 1):
        stderr = clip((completed.stderr or "").strip(), 2000)
        return None, stderr or f"semgrep exited with code {completed.returncode}"

    # Exit 1 is ambiguous: semgrep uses it for "findings were found", and Python
    # uses it for an uncaught exception. So the exit code cannot be trusted on
    # its own, and the output is what decides. This previously read
    # ``json.loads(completed.stdout or "{}")``, which turned a crash that
    # printed nothing into a valid empty document, and therefore into a clean
    # scan with no findings. A scanner that reports success after failing to
    # start is worse than one that crashes.
    if not (completed.stdout or "").strip():
        stderr = clip((completed.stderr or "").strip(), 2000)
        return None, ("semgrep produced no output: "
                      + (stderr or f"exit code {completed.returncode}"))
    try:
        document = json.loads(completed.stdout)
    except ValueError as exc:
        return None, f"semgrep output was not JSON: {exc}"
    if not isinstance(document, dict) or "results" not in document:
        return None, "semgrep output had no results key, so the scan did not run"
    return document, None


def rule_id(check_id):
    """The rule's own id, without the path semgrep prefixes onto it.

    Given ``--config /opt/themob/rules``, semgrep reports a rule defined as
    ``themob-weak-cipher-mode`` as ``opt.themob.rules.themob-weak-cipher-mode``.
    That prefix is the container's directory layout, and it has no business in a
    finding record or a report. The prefix is derived from RULES_DIR rather than
    hardcoded, so moving the rules cannot silently reintroduce it.

    Only that exact prefix is stripped. Rule ids legitimately contain dots, so
    taking the last segment would mangle a registry rule such as
    ``java.lang.security.audit.crypto.weak-hash``.
    """
    text = clip(check_id, 128) or "unknown"
    prefix = RULES_DIR.strip("/").replace("/", ".") + "."
    return text[len(prefix):] if text.startswith(prefix) else text


def normalise(document):
    findings = []
    truncated = False
    for result in (document.get("results") or []):
        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}

        start = result.get("start") or {}
        try:
            line = int(start.get("line"))
        except (TypeError, ValueError):
            line = None

        findings.append({
            "rule": rule_id(result.get("check_id")),
            # The canonical weakness key, carried on the rule itself. Without
            # it the adapter has nothing to map on but the rule id, which is
            # exactly the coupling the weakness catalogue exists to avoid.
            "weakness": clip(metadata.get("themob-weakness"), 128) or "",
            "message": clip(extra.get("message"), 1200) or "",
            "file": relative(result.get("path") or ""),
            "line": line,
            "snippet": clip((extra.get("lines") or "").strip(), MAX_SNIPPET),
            "severity": clip(extra.get("severity"), 32) or "INFO",
            "confidence": clip(metadata.get("confidence"), 32) or "",
        })
    return findings, truncated


def prepare_home() -> None:
    """Recreate the directories semgrep expects under a writable home.

    The image makes these at build time, but the sandbox mounts a fresh tmpfs
    over /tmp, so at run time they are gone. semgrep's OCaml core reads
    XDG_CONFIG_HOME on startup and aborts with a Sys_error if it is missing;
    the Python side creates a log directory under HOME before it reads a file.
    Either failure exits 1 with no output, which is indistinguishable from
    "found nothing" unless the caller checks the output rather than the code.
    """
    for variable, fallback in (("XDG_CONFIG_HOME", "/tmp/.config"),
                               ("XDG_CACHE_HOME", "/tmp/.cache"),
                               ("HOME", "/tmp")):
        path = os.environ.get(variable) or fallback
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass
    settings = os.environ.get("SEMGREP_SETTINGS_FILE")
    if settings:
        try:
            os.makedirs(os.path.dirname(settings), exist_ok=True)
        except OSError:
            pass


def main() -> int:
    try:
        prepare_home()
        if not os.path.isdir(SCAN_DIR):
            print(json.dumps({
                "ok": False,
                "error": "nothing to scan: /scan was not mounted",
                "tool": "semgrep",
            }))
            return 0

        rules = count_rules()
        if not rules:
            # Refusing beats running clean. An empty ruleset finds nothing and
            # looks exactly like a clean app.
            print(json.dumps({
                "ok": False,
                "error": f"no rules found in {RULES_DIR}; the image was built "
                         "without its rule pack",
                "tool": "semgrep",
                "tool_version": tool_version(),
            }))
            return 0

        document, error = run_semgrep()
        findings, truncated = ([], False) if document is None \
            else normalise(document)

        rule_errors = []
        if document is not None:
            for entry in (document.get("errors") or [])[:20]:
                if isinstance(entry, dict):
                    rule_errors.append(clip(entry.get("message"), 300) or "")

        print(json.dumps({
            "ok": error is None,
            "error": error,
            "tool": "semgrep",
            "tool_version": tool_version(),
            "findings": findings,
            "scanned": {"files": count_files(SCAN_DIR), "rules": rules},
            "truncated": truncated,
            "rule_errors": [e for e in rule_errors if e],
        }))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print(json.dumps({
            "ok": False,
            "tool": "semgrep",
            "error": clip(f"{type(exc).__name__}: {exc}", 2000),
            "trace": clip(traceback.format_exc(), 4000),
        }))
        return 0


if __name__ == "__main__":
    sys.exit(main())
