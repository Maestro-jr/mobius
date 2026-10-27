"""themob apktool worker: decode resources and the manifest.

Runs inside a network-less container with the sample mounted read-only at
``/input`` and a writable ``/output``. Decodes the package with apktool, then
reports what came out as one JSON document on stdout. It never raises: a
failure is reported as ``{"ok": false, "error": ...}`` so the engine always has
a parseable answer.

Smali is deliberately **not** decoded (``--no-src``). This stage exists to
produce the decoded resources and the plain-text ``AndroidManifest.xml`` that
the config auditor, the secret scanners and the endpoint extractor all read;
decompiling code is jadx's job and doubling it here would double the slowest
part of the pipeline.

Contract with ``themob/adapters/apktool_decode.py``:

    { "ok": bool, "error": str|null, "tool": "apktool", "tool_version": str,
      "decoded_dir": "decoded", "manifest_path": str|null,
      "meta": {...},                # from apktool.yml
      "network_security_config": {...}|null,
      "inventory": {...}, "resources": {...}, "assets": [...],
      "stderr_tail": str }
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET

INPUT_DIR = "/input"
OUTPUT_DIR = "/output"
DECODED_NAME = "decoded"
APKTOOL_JAR = os.environ.get("APKTOOL_JAR", "/opt/apktool/apktool.jar")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Caps. A real app is far below these; anything above is malformed or hostile.
MAX_FILES = 60000
MAX_ASSETS = 4000
MAX_LOCALES = 400
MAX_DOMAINS = 2000
MAX_PINS = 2000
MAX_STRING = 4096
STDERR_TAIL = 4000

# apktool is given most of the container's budget; the runner caps the rest.
DECODE_TIMEOUT = 900


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def find_sample() -> str:
    if not os.path.isdir(INPUT_DIR):
        raise RuntimeError("no /input mount")
    names = sorted(n for n in os.listdir(INPUT_DIR)
                   if os.path.isfile(os.path.join(INPUT_DIR, n)))
    if not names:
        raise RuntimeError("no sample mounted at /input")
    return os.path.join(INPUT_DIR, names[0])


def apktool_version() -> str:
    try:
        proc = subprocess.run(
            ["java", "-jar", APKTOOL_JAR, "--version"],
            capture_output=True, text=True, timeout=120, check=False)
        return clip((proc.stdout or proc.stderr).strip().splitlines()[0], 64)
    except Exception:                                   # noqa: BLE001
        return "unknown"


def decode(sample: str, destination: str) -> tuple[bool, str]:
    """Run apktool. Returns ``(ok, stderr_tail)``."""
    command = [
        "java", "-jar", APKTOOL_JAR, "d",
        "--force",              # overwrite: the output mount may be reused
        "--no-src",             # resources only; jadx owns code
        "--output", destination,
        sample,
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=DECODE_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return False, f"apktool timed out after {DECODE_TIMEOUT}s"
    except OSError as exc:
        return False, f"could not start apktool: {exc}"

    tail = ((proc.stderr or "") + (proc.stdout or ""))[-STDERR_TAIL:]
    if proc.returncode != 0:
        return False, tail or f"apktool exited with code {proc.returncode}"
    # apktool can exit 0 having produced nothing useful.
    if not os.path.isdir(destination):
        return False, tail or "apktool produced no output directory"
    return True, tail


# --------------------------------------------------------------------- outputs

def _tolerant_yaml_loader():
    """A SafeLoader that tolerates unknown YAML tags.

    apktool writes ``apktool.yml`` with a Java class tag on the document,
    ``!!brut.androlib.meta.MetaInfo``, and ``safe_load`` refuses any tag it has
    no constructor for. Plain ``safe_load`` therefore fails on *every real*
    apktool.yml, which is exactly the kind of bug that only shows up against
    real output.

    Unknown tags are mapped to their underlying plain value. No object is ever
    constructed, so this stays as safe as SafeLoader against a hostile file;
    exact constructors still win, so ordinary scalars parse normally.
    """
    import yaml

    class TolerantLoader(yaml.SafeLoader):
        pass

    def _ignore_tag(loader, _tag_suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)

    TolerantLoader.add_multi_constructor("", _ignore_tag)
    return TolerantLoader


def read_meta(decoded: str) -> dict:
    """``apktool.yml``: version, SDK info, and the packaging flags."""
    path = os.path.join(decoded, "apktool.yml")
    if not os.path.isfile(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            # The file is generated from the sample, so it is untrusted input
            # like everything else here: hence a SafeLoader, tag-tolerant only.
            raw = yaml.load(handle.read(2 * 1024 * 1024),
                            Loader=_tolerant_yaml_loader())
    except Exception:                                   # noqa: BLE001
        return {}
    if not isinstance(raw, dict):
        return {}

    sdk = raw.get("sdkInfo") if isinstance(raw.get("sdkInfo"), dict) else {}
    version = raw.get("versionInfo") if isinstance(raw.get("versionInfo"), dict) else {}
    return {
        "apktool_version": clip(raw.get("version"), 64),
        "apk_file_name": clip(raw.get("apkFileName"), 255),
        "is_framework_apk": bool(raw.get("isFrameworkApk")),
        "shared_library": bool(raw.get("sharedLibrary")),
        "sparse_resources": bool(raw.get("sparseResources")),
        "min_sdk_version": clip(sdk.get("minSdkVersion"), 16),
        "target_sdk_version": clip(sdk.get("targetSdkVersion"), 16),
        "max_sdk_version": clip(sdk.get("maxSdkVersion"), 16),
        "version_code": clip(version.get("versionCode"), 32),
        "version_name": clip(version.get("versionName"), 128),
        "do_not_compress": [clip(x, 128) for x in (raw.get("doNotCompress") or [])
                            if isinstance(x, str)][:200],
    }


def manifest_root(decoded: str):
    """The decoded manifest as an element tree, or ``None``."""
    path = os.path.join(decoded, "AndroidManifest.xml")
    if not os.path.isfile(path):
        return None, None
    try:
        return ET.parse(path).getroot(), path
    except (ET.ParseError, OSError):
        return None, path


def resolve_resource(decoded: str, reference: str) -> str | None:
    """``@xml/network_security_config`` -> the decoded file that backs it."""
    match = re.match(r"^@(?:[\w.]+:)?(\w+)/(\w+)$", (reference or "").strip())
    if match is None:
        return None
    kind, name = match.group(1), match.group(2)
    res_root = os.path.join(decoded, "res")
    if not os.path.isdir(res_root):
        return None
    # The resource may live in a qualified directory (xml-v24, xml-en, ...).
    for entry in sorted(os.listdir(res_root)):
        if entry != kind and not entry.startswith(kind + "-"):
            continue
        candidate = os.path.join(res_root, entry, name + ".xml")
        if os.path.isfile(candidate):
            return candidate
    return None


def parse_network_security_config(path: str) -> dict:
    """The domains, cleartext policy and pins the app declares.

    Recorded, not judged: the config auditor decides what is a finding.
    """
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        return {"path": clip(path), "parse_error": clip(str(exc), 300)}

    def config(node, scope: str) -> dict:
        domains = [clip(d.text.strip(), 255) for d in node.findall("domain")
                   if (d.text or "").strip()][:MAX_DOMAINS]
        pins = []
        for pin_set in node.findall("pin-set"):
            for pin in pin_set.findall("pin"):
                if (pin.text or "").strip():
                    pins.append(clip(pin.text.strip(), 128))
        trust = []
        for anchors in node.findall("trust-anchors"):
            for certificates in anchors.findall("certificates"):
                src = certificates.get("src")
                if src:
                    trust.append(clip(src, 128))
        cleartext = node.get("cleartextTrafficPermitted")
        return {
            "scope": scope,
            "domains": domains,
            "include_subdomains": [d.get("includeSubdomains")
                                   for d in node.findall("domain")][:MAX_DOMAINS],
            "cleartext_permitted": (None if cleartext is None
                                    else cleartext.strip().lower() == "true"),
            "pins": pins[:MAX_PINS],
            "trust_anchors": trust[:64],
        }

    entries = [config(node, "base") for node in root.findall("base-config")]
    entries += [config(node, "domain") for node in root.findall("domain-config")]
    entries += [config(node, "debug") for node in root.findall("debug-overrides")]
    return {"path": clip(path), "configs": entries[:500]}


def inventory(decoded: str) -> tuple[dict, dict, list]:
    """File counts, resource breakdown, and the asset list."""
    counts: dict[str, int] = {}
    resource_dirs: dict[str, int] = {}
    assets: list[str] = []
    locales: set[str] = set()
    total = 0
    total_bytes = 0

    for dirpath, _dirnames, filenames in os.walk(decoded):
        relative_dir = os.path.relpath(dirpath, decoded).replace(os.sep, "/")
        for name in filenames:
            total += 1
            if total > MAX_FILES:
                break
            full = os.path.join(dirpath, name)
            try:
                total_bytes += os.path.getsize(full)
            except OSError:
                pass
            extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            counts[extension] = counts.get(extension, 0) + 1

            if relative_dir.startswith("res/"):
                bucket = relative_dir.split("/")[1]
                resource_dirs[bucket] = resource_dirs.get(bucket, 0) + 1
                if "-" in bucket:
                    qualifier = bucket.split("-", 1)[1]
                    if re.match(r"^[a-z]{2}(-r[A-Z]{2})?$", qualifier):
                        locales.add(qualifier)
            elif relative_dir == "assets" or relative_dir.startswith("assets/"):
                if len(assets) < MAX_ASSETS:
                    path = f"{relative_dir}/{name}" if relative_dir != "." else name
                    assets.append(clip(path, 512))
        if total > MAX_FILES:
            break

    top = sorted(counts.items(), key=lambda kv: -kv[1])[:30]
    return (
        {
            "file_count": total,
            "decoded_bytes": total_bytes,
            "extensions": dict(top),
            "truncated": total > MAX_FILES,
        },
        {
            "directories": dict(sorted(resource_dirs.items(),
                                       key=lambda kv: -kv[1])[:80]),
            "locales": sorted(locales)[:MAX_LOCALES],
            "locale_count": len(locales),
        },
        assets,
    )


# --------------------------------------------------------------------- main

def analyze(sample: str) -> dict:
    decoded = os.path.join(OUTPUT_DIR, DECODED_NAME)
    ok, tail = decode(sample, decoded)
    version = apktool_version()
    if not ok:
        return {"ok": False, "error": clip(tail, STDERR_TAIL), "tool": "apktool",
                "tool_version": version}

    root, manifest_path = manifest_root(decoded)
    nsc = None
    package = None
    if root is not None:
        # The package name is the App entity's key, so the engine can merge this
        # onto the node androguard created rather than making a second one.
        package = clip(root.get("package"), 255)
        application = root.find("application")
        if application is not None:
            reference = application.get(ANDROID_NS + "networkSecurityConfig")
            resolved = resolve_resource(decoded, reference) if reference else None
            if resolved is not None:
                nsc = parse_network_security_config(resolved)
                nsc["path"] = os.path.relpath(resolved, OUTPUT_DIR).replace(os.sep, "/")
            elif reference:
                nsc = {"reference": clip(reference, 255), "unresolved": True}

    files, resources, assets = inventory(decoded)
    return {
        "ok": True,
        "error": None,
        "tool": "apktool",
        "tool_version": version,
        "decoded_dir": DECODED_NAME,
        "package": package,
        "manifest_path": (os.path.relpath(manifest_path, OUTPUT_DIR).replace(os.sep, "/")
                          if manifest_path else None),
        "manifest_parsed": root is not None,
        "meta": read_meta(decoded),
        "network_security_config": nsc,
        "inventory": files,
        "resources": resources,
        "assets": assets,
        "stderr_tail": clip(tail, STDERR_TAIL),
    }


def main() -> int:
    try:
        path = sys.argv[1] if len(sys.argv) > 1 else find_sample()
        document = analyze(path)
    except Exception as exc:                            # noqa: BLE001
        document = {
            "ok": False,
            "error": clip(f"{type(exc).__name__}: {exc}"),
            "tool": "apktool",
            "traceback": clip(traceback.format_exc(), 8000),
        }
    json.dump(document, sys.stdout, separators=(",", ":"), default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
