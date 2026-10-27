"""themob iOS unpack worker: unpack and inventory an .ipa.

Runs inside a network-less container with the sample mounted read-only at
/input. Unzips Payload/*.app, reads Info.plist (binary or XML, via stdlib
plistlib), lists the embedded frameworks and dylibs, and reads the main Mach-O's
identity and exploit-mitigation flags with lief. Writes one JSON document to
stdout; a failure is reported as {"ok": false, "error": ...} so the engine
always gets a parseable answer, never a traceback.

Contract with themob/adapters/ios_unpack.py:

    { "ok": bool, "error": str|null, "tool": "ios-unpack", "tool_version": str,
      "app": {bundle_id, name, version, build, min_os, executable, platform,
              url_schemes, ats, file_sharing, supports_document_browser,
              entitlements, get_task_allow, provisions_devices, team_id,
              profile_name, aps_environment},
      "frameworks": [{path, name, kind}],
      "macho": {path, name, size, sha256, archs, pie, encrypted, signed,
                stack_canary, arc, nx},
      "endpoints": [url, ...],
      "inventory": {file_count, uncompressed_bytes, extracted_files} }

The bundle is also decoded to the writable /output mount so the secrets and
dependency scanners have a tree to walk; ``endpoints`` are the absolute http(s)
URLs found in the resources and the main binary, which the endpoint-extract
stage classifies into ENDPOINT and CLOUD_ASSET nodes just as it does on Android.

``ats`` carries arbitrary_loads / arbitrary_loads_web / arbitrary_loads_media,
the exception domain names, and ``insecure_domains`` (the subset that permit
cleartext). The entitlement facts come from embedded.mobileprovision, parsed
structurally; no certificate chain is verified, the profile is read, not
trusted. The iOS config auditor judges all of it.

Everything is bounded: a hostile .ipa can list a million files, and this process
is the one holding them in memory.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import sys
import tempfile
import traceback
import zipfile

INPUT_DIR = "/input"
OUTPUT_DIR = "/output"           # writable mount; the decoded bundle lands here

MAX_FILES = 100000
MAX_FRAMEWORKS = 2000
MAX_SCHEMES = 512
MAX_STRING = 4096
MAX_PROVISION = 4_000_000       # a mobileprovision is a few KB; cap the read hard
MAX_ENTITLEMENTS = 128

# Bounds for the decode-to-disk pass that gitleaks and syft then scan.
MAX_EXTRACT_FILES = 30000
MAX_EXTRACT_TOTAL = 500_000_000
MAX_EXTRACT_FILE = 60_000_000

# URL recon over the bundle, the iOS counterpart of apkleaks' LinkFinder pass.
MAX_URLS = 2000
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{3,512}")
_TEXT_SUFFIXES = (".plist", ".json", ".strings", ".stringsdict", ".txt", ".js",
                  ".html", ".htm", ".xml", ".cfg", ".config", ".mobileconfig",
                  ".plist", ".url", ".yaml", ".yml")


def clip(value, limit: int = MAX_STRING):
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:                                   # noqa: BLE001
        return default


def _all_true(values) -> bool:
    """A protection counts as present only if every slice confirms it."""
    return all(v is True for v in values)


def find_sample() -> str:
    if not os.path.isdir(INPUT_DIR):
        raise RuntimeError("no /input mount")
    names = sorted(n for n in os.listdir(INPUT_DIR)
                   if os.path.isfile(os.path.join(INPUT_DIR, n)))
    if not names:
        raise RuntimeError("no sample mounted at /input")
    return os.path.join(INPUT_DIR, names[0])


def _app_prefix(names) -> str | None:
    """The 'Payload/<name>.app/' prefix of the main bundle."""
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return f"Payload/{parts[1]}/"
    return None


def _plist_facts(info: dict) -> dict:
    """The Info.plist facts, structural only. The auditor judges them later."""
    schemes = []
    for entry in (info.get("CFBundleURLTypes") or [])[:MAX_SCHEMES]:
        if isinstance(entry, dict):
            for scheme in (entry.get("CFBundleURLSchemes") or []):
                if isinstance(scheme, str) and scheme:
                    schemes.append(clip(scheme, 128))

    ats_raw = info.get("NSAppTransportSecurity")
    ats = {}
    if isinstance(ats_raw, dict):
        exceptions = ats_raw.get("NSExceptionDomains")
        exc = exceptions if isinstance(exceptions, dict) else {}
        insecure = sorted(clip(domain, 255) for domain, cfg in exc.items()
                          if isinstance(cfg, dict)
                          and cfg.get("NSExceptionAllowsInsecureHTTPLoads"))
        ats = {
            "arbitrary_loads": bool(ats_raw.get("NSAllowsArbitraryLoads")),
            "arbitrary_loads_web": bool(ats_raw.get("NSAllowsArbitraryLoadsInWebContent")),
            "arbitrary_loads_media": bool(ats_raw.get("NSAllowsArbitraryLoadsForMedia")),
            "exception_domains": sorted(exc.keys())[:256],
            "insecure_domains": insecure[:256],
        }

    return {
        "bundle_id": clip(info.get("CFBundleIdentifier"), 255),
        "name": clip(info.get("CFBundleDisplayName") or info.get("CFBundleName"), 255),
        "version": clip(info.get("CFBundleShortVersionString"), 64),
        "build": clip(info.get("CFBundleVersion"), 64),
        "min_os": clip(info.get("MinimumOSVersion"), 32),
        "executable": clip(info.get("CFBundleExecutable"), 255),
        "platform": clip(info.get("DTPlatformName") or "ios", 32),
        "url_schemes": sorted(set(s for s in schemes if s))[:MAX_SCHEMES],
        "ats": ats,
        "file_sharing": bool(info.get("UIFileSharingEnabled")),
        "supports_document_browser": bool(info.get("UISupportsDocumentBrowser")),
    }


def _bound_value(value, depth: int = 0):
    """A JSON-safe, bounded copy of an entitlement value (hostile profile)."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return clip(value, 512)
    if isinstance(value, (list, tuple)) and depth < 2:
        return [_bound_value(v, depth + 1) for v in list(value)[:64]]
    if isinstance(value, dict) and depth < 2:
        return {clip(str(k), 128): _bound_value(v, depth + 1)
                for k, v in list(value.items())[:64]}
    return clip(str(value), 512)


def _extract_embedded_plist(blob: bytes):
    """Slice the plaintext plist out of a CMS-wrapped mobileprovision."""
    start = blob.find(b"<?xml")
    if start < 0:
        start = blob.find(b"<plist")
    end = blob.rfind(b"</plist>")
    if start < 0 or end < 0:
        return None
    try:
        parsed = plistlib.loads(blob[start:end + len(b"</plist>")])
    except Exception:                                   # noqa: BLE001
        return None
    return parsed if isinstance(parsed, dict) else None


def _entitlements(zf, app_prefix: str) -> dict:
    """The code-signing entitlements, read from embedded.mobileprovision.

    The provisioning profile is a CMS blob with a plaintext plist inside; we
    slice the plist out and read its Entitlements, which for get-task-allow and
    the common over-broad keys is the signal the auditor wants. No certificate
    chain is parsed: we read, we do not trust.
    """
    out = {"entitlements": {}, "get_task_allow": None, "provisions_devices": None,
           "team_id": None, "profile_name": None, "aps_environment": None}
    name = f"{app_prefix}embedded.mobileprovision"
    try:
        entry = zf.getinfo(name)
    except KeyError:
        return out
    if entry.file_size > MAX_PROVISION:
        return out
    try:
        blob = zf.read(name)
    except Exception:                                   # noqa: BLE001
        return out

    profile = _extract_embedded_plist(blob)
    if not isinstance(profile, dict):
        return out

    ents = profile.get("Entitlements")
    ents = ents if isinstance(ents, dict) else {}
    out["entitlements"] = {clip(str(k), 128): _bound_value(v)
                           for k, v in list(ents.items())[:MAX_ENTITLEMENTS]}
    if "get-task-allow" in ents:
        out["get_task_allow"] = bool(ents.get("get-task-allow"))
    out["provisions_devices"] = isinstance(profile.get("ProvisionedDevices"), list)
    team = profile.get("TeamIdentifier")
    if isinstance(team, list) and team:
        out["team_id"] = clip(str(team[0]), 64)
    else:
        out["team_id"] = clip(ents.get("com.apple.developer.team-identifier"), 64)
    out["profile_name"] = clip(profile.get("Name"), 255)
    aps = ents.get("aps-environment")
    out["aps_environment"] = clip(aps, 32) if isinstance(aps, str) else None
    return out


def _frameworks(zf, app_prefix: str) -> list:
    """The embedded frameworks and dylibs, deduplicated."""
    fw_prefix = f"{app_prefix}Frameworks/"
    seen: dict[str, dict] = {}
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(fw_prefix):
            continue
        rest = name[len(fw_prefix):]
        head = rest.split("/", 1)[0]
        if head.endswith(".framework"):
            key = f"{fw_prefix}{head}"
            seen.setdefault(key, {"path": clip(key, 1024),
                                  "name": clip(head, 255), "kind": "framework"})
        elif head.endswith(".dylib") and "/" not in rest:
            seen.setdefault(name, {"path": clip(name, 1024),
                                   "name": clip(head, 255), "kind": "dylib"})
        if len(seen) >= MAX_FRAMEWORKS:
            break
    return list(seen.values())


def _scan_urls(zf, app_prefix: str, executable: str | None) -> list:
    """Absolute http(s) URLs in the bundle: text resources and the main binary.

    The iOS counterpart of apkleaks running LinkFinder over an APK. These are
    candidates, not findings: the endpoint-extract stage classifies and filters
    them (namespace hosts dropped, cloud buckets split out) exactly as it does
    the Android list, so the same ENDPOINT and CLOUD_ASSET nodes come out.
    """
    urls: set[str] = set()
    targets = []
    if executable:
        targets.append(f"{app_prefix}{executable}")
    for info in zf.infolist():
        name = info.filename
        if name.startswith(app_prefix) and name.lower().endswith(_TEXT_SUFFIXES):
            targets.append(name)

    for name in targets:
        try:
            entry = zf.getinfo(name)
        except KeyError:
            continue
        if entry.file_size > MAX_EXTRACT_FILE:
            continue
        try:
            data = zf.read(name)
        except Exception:                               # noqa: BLE001
            continue
        for match in _URL_RE.findall(data):
            urls.add(clip(match.decode("utf-8", "replace"), 1024))
            if len(urls) >= MAX_URLS:
                return sorted(urls)
    return sorted(urls)


def _safe_extract(zf, dest: str) -> int:
    """Zip-slip-safe, bounded decode of the bundle to *dest* for the scanners.

    Returns the number of files written. Entries that escape dest, or that are
    too large, are skipped rather than trusted: the archive is hostile input.
    """
    if not os.path.isdir(dest):
        return 0
    base = os.path.realpath(dest)
    written = 0
    total = 0
    for info in zf.infolist():
        if written >= MAX_EXTRACT_FILES or total >= MAX_EXTRACT_TOTAL:
            break
        name = info.filename
        if not name or name.endswith("/"):
            continue
        if info.file_size > MAX_EXTRACT_FILE:
            continue
        resolved = os.path.realpath(os.path.join(base, name))
        if resolved != base and not resolved.startswith(base + os.sep):
            continue                                    # zip-slip attempt
        try:
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with zf.open(info) as src, open(resolved, "wb") as dst:
                chunk = src.read(MAX_EXTRACT_FILE + 1)[:MAX_EXTRACT_FILE]
                dst.write(chunk)
        except Exception:                               # noqa: BLE001
            continue
        total += len(chunk)
        written += 1
    return written


def _inventory(zf) -> dict:
    count = 0
    total = 0
    for info in zf.infolist():
        count += 1
        if count > MAX_FILES:
            break
        total += int(info.file_size)
    return {"file_count": count, "uncompressed_bytes": total}


def _allows_stack_exec(binary) -> bool:
    try:
        import lief
        return lief.MachO.HEADER_FLAGS.ALLOW_STACK_EXECUTION in binary.header.flags_list
    except Exception:                                   # noqa: BLE001
        return False


def _read_macho(zf, macho_name: str) -> dict:
    """The main Mach-O's identity and exploit-mitigation flags, read with lief.

    Conservative across fat slices: a protection is reported present only when
    every slice has it; FairPlay encryption is reported when any slice is
    encrypted. lief runs here, in the container, never in the engine.
    """
    out = {"path": clip(macho_name, 1024),
           "name": clip(macho_name.rsplit("/", 1)[-1], 255),
           "archs": [], "pie": None, "encrypted": None, "signed": None,
           "stack_canary": None, "arc": None, "nx": None}
    try:
        data = zf.read(macho_name)
    except Exception:                                   # noqa: BLE001
        return out
    out["size"] = len(data)
    out["sha256"] = hashlib.sha256(data).hexdigest()

    try:
        import lief                                     # noqa: F401
    except Exception:                                   # noqa: BLE001
        return out

    tmp = None
    binaries = []
    try:
        fd, tmp = tempfile.mkstemp(prefix="macho_")     # /tmp is the writable tmpfs
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        parsed = lief.MachO.parse(tmp)
        binaries = list(parsed) if parsed is not None else []
    except Exception:                                   # noqa: BLE001
        binaries = []
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass

    if not binaries:
        return out

    archs, pies, encs, signs, canaries, arcs, nxs = [], [], [], [], [], [], []
    for b in binaries:
        arch = _safe(lambda: clip(str(b.header.cpu_type), 32))
        if arch:
            archs.append(arch)
        pies.append(_safe(lambda: bool(b.is_pie)))
        encs.append(_safe(lambda: bool(b.has_encryption_info)
                          and getattr(b.encryption_info, "crypt_id", 0) != 0))
        signs.append(_safe(lambda: bool(b.has_code_signature)))
        syms = _safe(lambda: {s.name for s in b.imported_symbols}, set()) or set()
        canaries.append(any(n in syms for n in
                            ("___stack_chk_fail", "__stack_chk_fail")))
        arcs.append(any(n in syms for n in
                        ("_objc_release", "_objc_autoreleaseReturnValue",
                         "_objc_storeStrong")))
        nxs.append(_safe(lambda: not _allows_stack_exec(b)))

    out["archs"] = archs
    out["pie"] = _all_true(pies)
    out["encrypted"] = any(x is True for x in encs)
    out["signed"] = _all_true(signs)
    out["stack_canary"] = _all_true(canaries)
    out["arc"] = _all_true(arcs)
    out["nx"] = _all_true(nxs)
    return out


def _lief_version() -> str:
    try:
        import lief
        return clip(str(getattr(lief, "__version__", "unknown")), 64)
    except Exception:                                   # noqa: BLE001
        return "unknown"


def analyze(path: str) -> dict:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()[:MAX_FILES]
        app_prefix = _app_prefix(names)
        if app_prefix is None:
            raise RuntimeError("no Payload/*.app bundle in the archive")

        info = {}
        try:
            parsed = plistlib.loads(zf.read(f"{app_prefix}Info.plist"))
            if isinstance(parsed, dict):
                info = parsed
        except Exception:                               # noqa: BLE001
            info = {}

        app = _plist_facts(info)
        app.update(_entitlements(zf, app_prefix))
        frameworks = _frameworks(zf, app_prefix)
        macho = {}
        if app.get("executable"):
            macho = _read_macho(zf, f"{app_prefix}{app['executable']}")
        endpoints = _scan_urls(zf, app_prefix, app.get("executable"))
        # Decode the bundle to the writable mount so the secrets (gitleaks) and
        # dependency (syft) scanners, which read /scan or the artifacts tree,
        # have a tree to walk. Skipped cleanly when there is no /output mount.
        extracted = _safe_extract(zf, OUTPUT_DIR)
        inventory = _inventory(zf)
        inventory["extracted_files"] = extracted

    return {
        "ok": True,
        "error": None,
        "tool": "ios-unpack",
        "tool_version": _lief_version(),
        "app": app,
        "frameworks": frameworks,
        "macho": macho,
        "endpoints": endpoints,
        "inventory": inventory,
    }


def main() -> int:
    try:
        path = sys.argv[1] if len(sys.argv) > 1 else find_sample()
        document = analyze(path)
    except Exception as exc:                            # noqa: BLE001
        document = {
            "ok": False,
            "error": clip(f"{type(exc).__name__}: {exc}"),
            "tool": "ios-unpack",
            "tool_version": _lief_version(),
            "traceback": clip(traceback.format_exc(), 8000),
        }
    json.dump(document, sys.stdout, separators=(",", ":"), default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
