"""themob SBOM worker: what the app bundles, and which of it is vulnerable.

Runs inside a network-less container. ``/scan`` is a read-only mount of the
project's artifacts directory, which by this stage holds apktool's decoded tree
and jadx's decompiled Java.

Writes one JSON document to stdout and never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

**Why this worker catalogs Android dependencies itself.**

syft is in this image and is genuinely good at what it covers, but it has no
Android cataloger. Pointed at a real APK it reports zero artifacts, and pointed
at a directory holding ``META-INF/androidx.core_core.version`` and
``META-INF/maven/<group>/<artifact>/pom.properties`` it still reports zero: its
Java support reads *inside* JAR archives, and an Android package has none,
because every dependency has already been merged into ``classes.dex``.

So the build plan's "syft to grype" needs a step in between for Android. This
worker reads the evidence Android actually leaves behind, hands grype a
CycloneDX SBOM built from it, and still runs syft over the tree so that an
embedded JAR or a recognisable native binary is not missed.

Contract with ``themob/adapters/sbom_scan.py``:

    { "ok": bool, "error": str|null, "tool": "syft+grype",
      "tool_version": {"syft": str, "grype": str},
      "libraries": [ {"group": str, "name": str, "version": str, "purl": str,
                      "evidence": str, "cataloger": str} ],
      "vulnerabilities": [ {"id": str, "severity": str, "purl": str,
                            "package": str, "version": str,
                            "fixed_in": str|null, "description": str,
                            "cvss": float|null, "urls": [str]} ],
      "scanned": {"files": int, "libraries": int}, "truncated": bool }
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import traceback

SCAN_DIR = "/scan"
SBOM_PATH = "/tmp/themob-sbom.json"

# Caps. A hostile package can declare a great many of anything, and this process
# holds the lot in memory before the engine ever sees it.
MAX_LIBRARIES = 2000
MAX_VULNERABILITIES = 5000
MAX_STRING = 2048

# AndroidX and Google libraries drop "<groupId>_<artifactId>.version" into
# META-INF. Group ids are dotted and artifact ids are hyphenated, so the first
# underscore is the separator; neither half normally contains one.
_VERSION_MARKER = re.compile(r"^(?P<group>[A-Za-z0-9.\-]+)_(?P<artifact>[A-Za-z0-9.\-]+)\.version$")

# A version string worth believing. Anything wilder is a file that happens to
# end in .version rather than a dependency marker.
_VERSION_VALUE = re.compile(r"^[0-9][A-Za-z0-9.\-+_]{0,63}$")

_COORD = re.compile(r"^[A-Za-z0-9.\-_]{1,128}$")


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def purl_for(group: str, artifact: str, version: str) -> str:
    return f"pkg:maven/{group}/{artifact}@{version}"


def read_small(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


# --------------------------------------------------------------- cataloguing

def catalog_version_markers(root: str):
    """``META-INF/<group>_<artifact>.version``, the AndroidX convention."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != "META-INF":
            continue
        for name in filenames:
            match = _VERSION_MARKER.match(name)
            if not match:
                continue
            version = read_small(os.path.join(dirpath, name), 128).strip()
            if not _VERSION_VALUE.match(version):
                continue
            group = match.group("group")
            artifact = match.group("artifact")
            found.append({
                "group": group,
                "name": artifact,
                "version": version,
                "purl": purl_for(group, artifact, version),
                "evidence": clip(os.path.relpath(os.path.join(dirpath, name), root)
                                 .replace("\\", "/"), 512),
                "cataloger": "android-version-marker",
            })
    return found


def catalog_pom_properties(root: str):
    """``META-INF/maven/<group>/<artifact>/pom.properties``, shaded into an APK."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        if "pom.properties" not in filenames:
            continue
        path = os.path.join(dirpath, "pom.properties")
        fields = {}
        for line in read_small(path).splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()

        group = fields.get("groupId", "")
        artifact = fields.get("artifactId", "")
        version = fields.get("version", "")
        if not (_COORD.match(group) and _COORD.match(artifact)
                and _VERSION_VALUE.match(version)):
            continue
        found.append({
            "group": group,
            "name": artifact,
            "version": version,
            "purl": purl_for(group, artifact, version),
            "evidence": clip(os.path.relpath(path, root).replace("\\", "/"), 512),
            "cataloger": "maven-pom-properties",
        })
    return found


def run_syft(root: str):
    """Whatever syft *can* see: an embedded JAR, a recognisable binary.

    Kept because it costs one process and covers the cases the Android
    catalogers above do not, not because it finds Android dependencies.
    """
    try:
        completed = subprocess.run(
            ["syft", "scan", f"dir:{root}", "-o", "syft-json", "-q"],
            capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    try:
        document = json.loads(completed.stdout)
    except ValueError:
        return []

    found = []
    for artifact in (document.get("artifacts") or [])[:MAX_LIBRARIES]:
        if not isinstance(artifact, dict):
            continue
        purl = artifact.get("purl") or ""
        name = artifact.get("name") or ""
        version = artifact.get("version") or ""
        if not (name and version and purl):
            continue
        found.append({
            "group": "",
            "name": clip(name, 128),
            "version": clip(version, 64),
            "purl": clip(purl, 512),
            "evidence": clip((artifact.get("locations") or [{}])[0]
                             .get("path", ""), 512) or "syft",
            "cataloger": clip(artifact.get("foundBy"), 64) or "syft",
        })
    return found


def merge(*groups):
    """One entry per purl. Two catalogers agreeing is not two dependencies."""
    by_purl = {}
    for group in groups:
        for entry in group:
            existing = by_purl.get(entry["purl"])
            if existing is None:
                by_purl[entry["purl"]] = entry
            elif entry["cataloger"] not in existing["cataloger"]:
                # Record the agreement rather than dropping it on the floor.
                existing["cataloger"] = f"{existing['cataloger']},{entry['cataloger']}"
    return sorted(by_purl.values(), key=lambda e: e["purl"])[:MAX_LIBRARIES]


# ------------------------------------------------------------------- matching

def write_sbom(libraries) -> None:
    components = [{
        "type": "library",
        "group": entry["group"],
        "name": entry["name"],
        "version": entry["version"],
        "purl": entry["purl"],
    } for entry in libraries]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    with open(SBOM_PATH, "w", encoding="utf-8") as handle:
        json.dump(document, handle)


def run_grype():
    """Match the SBOM against grype's baked-in vulnerability database.

    The database ships in the image. grype would otherwise try to update it on
    first run, and this container has no network, so an image built without the
    database is an image that silently finds nothing.
    """
    try:
        completed = subprocess.run(
            ["grype", f"sbom:{SBOM_PATH}", "-o", "json", "-q"],
            capture_output=True, text=True, timeout=900,
            env={**os.environ, "GRYPE_DB_AUTO_UPDATE": "false"})
    except subprocess.TimeoutExpired:
        return None, "grype timed out"
    except OSError as exc:
        return None, f"grype could not be started: {exc}"
    if completed.returncode not in (0, 1):
        return None, clip((completed.stderr or "").strip(), 2000) or \
            f"grype exited with code {completed.returncode}"
    try:
        return json.loads(completed.stdout or "{}"), None
    except ValueError as exc:
        return None, f"grype output was not JSON: {exc}"


def normalise_matches(document):
    matches = []
    truncated = False
    for match in (document.get("matches") or []):
        if len(matches) >= MAX_VULNERABILITIES:
            truncated = True
            break
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}

        cvss = None
        for entry in (vulnerability.get("cvss") or []):
            metrics = (entry or {}).get("metrics") or {}
            score = metrics.get("baseScore")
            if isinstance(score, (int, float)):
                cvss = float(score)
                break

        fix = (vulnerability.get("fix") or {}).get("versions") or []
        matches.append({
            "id": clip(vulnerability.get("id"), 64) or "unknown",
            "severity": clip(vulnerability.get("severity"), 32) or "unknown",
            "purl": clip(artifact.get("purl"), 512) or "",
            "package": clip(artifact.get("name"), 128) or "",
            "version": clip(artifact.get("version"), 64) or "",
            "fixed_in": clip(fix[0], 64) if fix else None,
            "description": clip(vulnerability.get("description"), 1200) or "",
            "cvss": cvss,
            "urls": [clip(u, 512) for u in (vulnerability.get("urls") or [])
                     if isinstance(u, str)][:8],
        })
    return matches, truncated


def grype_db_info(document):
    """The vulnerability database's build date, from grype's own descriptor.

    A match against a stale database silently under-reports: a CVE published
    last week is invisible to a database built last month. grype records when
    its database was built, so the assessment can carry that forward and a
    reader can tell "no vulnerable dependencies" apart from "no recent data".

    grype moved the field between schema versions, so both shapes are read:
    the older ``descriptor.db.built`` and the newer ``descriptor.db.status.built``.
    """
    descriptor = document.get("descriptor") if isinstance(document, dict) else None
    db = (descriptor or {}).get("db") if isinstance(descriptor, dict) else None
    if not isinstance(db, dict):
        return None
    status = db.get("status") if isinstance(db.get("status"), dict) else {}
    built = status.get("built") or db.get("built")
    schema = status.get("schemaVersion") or db.get("schemaVersion")
    if not built:
        return None
    return {"built": clip(str(built), 64),
            "schema_version": clip(str(schema), 32) if schema else None}


def tool_version(binary: str) -> str:
    try:
        out = subprocess.run([binary, "version", "-o", "text"],
                             capture_output=True, text=True, timeout=60)
        first = (out.stdout or out.stderr or "").strip().splitlines()
        return clip(first[0], 64) if first else "unknown"
    except Exception:                                   # noqa: BLE001
        return "unknown"


def count_files(root: str) -> int:
    total = 0
    for _dirpath, _dirnames, filenames in os.walk(root):
        total += len(filenames)
        if total >= 200000:
            break
    return total


def main() -> int:
    try:
        if not os.path.isdir(SCAN_DIR):
            print(json.dumps({
                "ok": False,
                "error": "nothing to scan: /scan was not mounted",
                "tool": "syft+grype",
            }))
            return 0

        libraries = merge(catalog_version_markers(SCAN_DIR),
                          catalog_pom_properties(SCAN_DIR),
                          run_syft(SCAN_DIR))

        vulnerabilities = []
        truncated = False
        error = None
        vuln_db = None
        if libraries:
            write_sbom(libraries)
            document, error = run_grype()
            if document is not None:
                vulnerabilities, truncated = normalise_matches(document)
                vuln_db = grype_db_info(document)

        print(json.dumps({
            "ok": error is None,
            "error": error,
            "tool": "syft+grype",
            "tool_version": {"syft": tool_version("syft"),
                             "grype": tool_version("grype")},
            "libraries": libraries,
            "vulnerabilities": vulnerabilities,
            "scanned": {"files": count_files(SCAN_DIR),
                        "libraries": len(libraries)},
            "truncated": truncated,
            # When the vulnerability data was built. A clean dependency result
            # is only as current as this.
            "vuln_db": vuln_db,
        }))
        return 0
    except Exception as exc:                            # noqa: BLE001
        print(json.dumps({
            "ok": False,
            "tool": "syft+grype",
            "error": clip(f"{type(exc).__name__}: {exc}", 2000),
            "trace": clip(traceback.format_exc(), 4000),
        }))
        return 0


if __name__ == "__main__":
    sys.exit(main())
