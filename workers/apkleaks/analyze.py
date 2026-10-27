"""themob apkleaks worker: Android-specific secrets, URIs and endpoints.

Runs inside a network-less container. The APK is mounted read-only at /input.
apkleaks disassembles it with the jadx baked into this image and greps the
result with its own pattern set.

Why this runs jadx a second time when the pipeline already has jadx output:
apkleaks takes an APK and nothing else, and reimplementing it against our tree
would mean forking its rules instead of invoking the tool. The cost is one more
decompile; the alternative is maintaining somebody else's regex set by hand.

What it adds over gitleaks: gitleaks matches provider credential formats but
will not match a secret sitting between XML tags, and res/values/strings.xml is
exactly where an Android app keeps an API key. apkleaks greps decoded resources
too, so the two are complements rather than duplicates.

Writes one JSON document to stdout and never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

Contract with ``themob/adapters/apkleaks_scan.py``:

    { "ok": bool, "error": str|null, "tool": "apkleaks", "tool_version": str,
      "package": str|null,
      "results": [ { "rule": str, "credential": bool, "count": int,
                     "matches": [ { "value": str|null, "preview": str,
                                    "sha256": str } ] } ],
      "truncated": bool }

**Credential-like matches never leave with their value.** ``value`` is null for
those and only the redacted preview and the digest travel, the same contract the
gitleaks worker keeps. A URL is not a credential and is passed through in full,
because that is exactly what the endpoint stage needs to read.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import traceback

INPUT_DIR = "/input"

# Caps. A large app can match thousands of strings, and this process holds them
# before the engine ever sees them.
MAX_RULES = 200
MAX_PER_RULE = 500
MAX_STRING = 2048
MAX_PREVIEW = 200

KEEP_PREFIX = 4
KEEP_SUFFIX = 4

# The operator opt-in, forwarded as an environment variable by the adapter. OFF
# by default: a credential is redacted here and the full value never leaves the
# container. When set, the full value is allowed out, so the engine can show it
# behind its password gate. Read once at import; the container runs one scan.
CAPTURE_SECRETS = (os.environ.get("THEMOB_CAPTURE_SECRET_VALUES") or "") \
    .strip().lower() in ("1", "true", "yes", "on")

# Rule names whose matches are credentials. Redaction has to happen here, inside
# the container, because once a value is on stdout it has left. Everything else
# (links, IP addresses, package names) passes through whole: those are what the
# endpoint stage reads, and redacting a URL would make it useless.
CREDENTIAL_TOKENS = (
    "key", "token", "secret", "password", "passwd", "credential", "auth",
    "api_", "apikey", "aws", "gcp", "azure", "firebase", "private", "jwt",
    "bearer", "oauth", "hash", "salt", "signature", "certificate",
)
# Explicitly not credentials, even though the token test would catch them.
# "bucket" earns its place here: Amazon_AWS_S3_Bucket contains "aws" and would
# otherwise be redacted, but a bucket URL is an endpoint. Redacting it would
# hide the one thing the endpoint stage wants and claim a leaked credential
# that is not there.
NOT_CREDENTIAL = ("linkfinder", "ip_address", "ipv4", "ipv6", "url", "link",
                  "bucket", "endpoint", "domain", "host")


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


def tidy(match: str) -> str:
    """Strip the delimiters apkleaks captures along with the value.

    Its rules are not consistent about this: Amazon_AWS_Access_Key_ID returns
    the key with a leading double quote while AWS_API_Key returns it clean, so
    the same secret hashes two different ways and shows up as two nodes. It also
    breaks agreement with gitleaks, which captures the bare value.
    """
    return (match or "").strip().strip("\"'`,;").strip()


def is_credential(rule: str) -> bool:
    lowered = (rule or "").lower()
    if any(token in lowered for token in NOT_CREDENTIAL):
        return False
    return any(token in lowered for token in CREDENTIAL_TOKENS)


def tool_version() -> str:
    try:
        import apkleaks
        return clip(getattr(apkleaks, "__version__", "") or "2.6.3", 64)
    except Exception:                                   # noqa: BLE001
        return "unknown"


def find_sample() -> str | None:
    try:
        entries = sorted(os.listdir(INPUT_DIR))
    except OSError:
        return None
    for name in entries:
        path = os.path.join(INPUT_DIR, name)
        if os.path.isfile(path):
            return path
    return None


def run_apkleaks(sample: str, out_path: str) -> tuple[int, str]:
    # The console script, not `python -m apkleaks.cli`. apkleaks' cli.py defines
    # main() and has no `if __name__ == "__main__"` guard, so running it as a
    # module imports it, does nothing at all, and exits 0. That failure is
    # completely silent, which is the worst kind.
    command = [
        "apkleaks",
        "-f", sample,
        "-o", out_path,
        "--json",
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=1500, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 124, "apkleaks timed out"
    except OSError as exc:
        return 127, f"apkleaks could not be started: {exc}"
    stderr = clip((completed.stderr or "").strip(), 4000) or ""
    return completed.returncode, stderr


def read_report(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def normalise(document):
    """apkleaks' own record -> themob's bounded, redacted shape."""
    results = []
    truncated = False
    raw_results = (document or {}).get("results")
    if not isinstance(raw_results, list):
        return results, truncated

    for entry in raw_results:
        if not isinstance(entry, dict):
            continue
        if len(results) >= MAX_RULES:
            truncated = True
            break

        rule = clip(entry.get("name"), 128) or "unknown"
        credential = is_credential(rule)
        matches = entry.get("matches")
        if not isinstance(matches, list):
            continue

        seen = set()
        cleaned = []
        for match in matches:
            if not isinstance(match, str):
                match = str(match)
            match = tidy(match)
            if not match or match in seen:
                continue
            seen.add(match)
            if len(cleaned) >= MAX_PER_RULE:
                truncated = True
                break
            digest = hashlib.sha256(match.encode("utf-8", "replace")).hexdigest()
            cleaned.append({
                # Null for a credential unless the operator opted in. Once it is
                # on stdout it has left the container, so the decision is made
                # here: a non-credential (a URL, a bucket) always passes whole,
                # and a credential only when CAPTURE_SECRETS is set.
                "value": clip(match) if (CAPTURE_SECRETS or not credential)
                         else None,
                # The preview stays redacted for a credential regardless, so the
                # entity node and any un-gated view never show a live value.
                "preview": redact(clip(match, MAX_PREVIEW)) if credential
                           else clip(match, MAX_PREVIEW),
                "sha256": digest,
            })

        if cleaned:
            results.append({"rule": rule, "credential": credential,
                            "count": len(cleaned), "matches": cleaned})
    return results, truncated


def main() -> int:
    try:
        sample = find_sample()
        if sample is None:
            print(json.dumps({
                "ok": False,
                "tool": "apkleaks",
                "error": "no sample mounted at /input",
            }))
            return 0

        # apkleaks writes its report where it is told; /tmp is the tmpfs the
        # runner provides, and the root filesystem is read-only.
        handle, out_path = tempfile.mkstemp(prefix="apkleaks-", suffix=".json",
                                            dir="/tmp")
        os.close(handle)

        code, stderr = run_apkleaks(sample, out_path)
        document = read_report(out_path)

        # apkleaks DELETES its output file when it matched nothing, so a missing
        # report is not the same as a failed run. Only a non-zero exit means the
        # tool actually failed; exit 0 with no file is a clean scan, and
        # reporting that as an error would be crying wolf on every clean app.
        if document is None:
            if code != 0:
                print(json.dumps({
                    "ok": False,
                    "tool": "apkleaks",
                    "tool_version": tool_version(),
                    "error": clip(stderr, 2000)
                             or f"apkleaks failed with exit code {code}",
                }))
                return 0
            document = {"package": None, "results": []}

        results, truncated = normalise(document)
        print(json.dumps({
            "ok": True,
            "error": None,
            "tool": "apkleaks",
            "tool_version": tool_version(),
            "package": clip((document or {}).get("package"), 255),
            "results": results,
            "truncated": truncated,
        }))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print(json.dumps({
            "ok": False,
            "tool": "apkleaks",
            "error": clip(f"{type(exc).__name__}: {exc}", 2000),
            "trace": clip(traceback.format_exc(), 4000),
        }))
        return 0


if __name__ == "__main__":
    sys.exit(main())
