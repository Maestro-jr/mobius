"""themob androguard worker: unpack and inventory an APK.

Runs inside a network-less container with the sample mounted read-only at
``/input``. Parses the manifest, signing block and file inventory, and writes
one JSON document to stdout. It never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

Contract with ``themob/adapters/androguard_unpack.py``:

    { "ok": bool, "error": str|null, "tool": "androguard", "tool_version": str,
      "app": {...}, "permissions": [...], "declared_permissions": [...],
      "components": [...], "deep_links": [...], "certificates": [...],
      "native_libs": [...], "dex": [...], "inventory": {...} }

Everything is bounded: a hostile APK can declare a million components, and this
process is the one holding them in memory.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import traceback
import zipfile

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
INPUT_DIR = "/input"

# Caps. A real app is far below these; anything above is malformed or hostile.
MAX_COMPONENTS = 5000
MAX_PERMISSIONS = 2000
MAX_DEEP_LINKS = 2000
MAX_FILES = 50000
MAX_NATIVE_LIBS = 2000
MAX_STRING = 4096

COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def clip(value, limit: int = MAX_STRING):
    """Bound a value before it enters the JSON document."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def attr(element, name: str):
    return clip(element.get(ANDROID_NS + name))


def bool_attr(element, name: str):
    raw = element.get(ANDROID_NS + name)
    if raw is None:
        return None
    return str(raw).strip().lower() in ("true", "1")


def int_attr(element, name: str):
    raw = element.get(ANDROID_NS + name)
    if raw is None:
        return None
    try:
        text = str(raw).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def find_sample() -> str:
    if not os.path.isdir(INPUT_DIR):
        raise RuntimeError("no /input mount")
    names = sorted(n for n in os.listdir(INPUT_DIR)
                   if os.path.isfile(os.path.join(INPUT_DIR, n)))
    if not names:
        raise RuntimeError("no sample mounted at /input")
    return os.path.join(INPUT_DIR, names[0])


def silence_tool_logging() -> None:
    """androguard 4.x logs to stderr through loguru, loudly, on malformed input.

    That noise is not useful to the engine and can bury the real error, so drop
    it. stdout must stay a single clean JSON document either way.
    """
    try:
        from loguru import logger
        logger.remove()
    except Exception:                                   # noqa: BLE001
        pass


def load_apk(path: str):
    """Import androguard lazily so an import failure is reported as JSON."""
    silence_tool_logging()
    try:
        from androguard.core.apk import APK            # androguard >= 4
    except ImportError:                                 # pragma: no cover
        from androguard.core.bytecodes.apk import APK  # androguard 3.x
    return APK(path)


def androguard_version() -> str:
    try:
        import androguard
        return str(getattr(androguard, "__version__", "unknown"))
    except Exception:                                   # noqa: BLE001
        return "unknown"


# --------------------------------------------------------------------- manifest

def manifest_root(apk):
    """The parsed AndroidManifest tree, across androguard versions."""
    for getter in ("get_android_manifest_xml", "get_AndroidManifest"):
        fn = getattr(apk, getter, None)
        if fn is None:
            continue
        try:
            root = fn()
        except Exception:                               # noqa: BLE001
            continue
        if root is None:
            continue
        # get_AndroidManifest() may hand back an AXMLPrinter-ish wrapper.
        return getattr(root, "getroot", lambda: root)()
    raise RuntimeError("could not parse AndroidManifest.xml")


def collect_permissions(root):
    """Permissions the app requests, plus the ones it defines itself."""
    requested, declared = [], []
    for node in root.iter("uses-permission"):
        name = attr(node, "name")
        if name:
            requested.append({"name": name,
                              "max_sdk": int_attr(node, "maxSdkVersion")})
        if len(requested) >= MAX_PERMISSIONS:
            break
    for node in root.iter("permission"):
        name = attr(node, "name")
        if name:
            declared.append({
                "name": name,
                "protection_level": attr(node, "protectionLevel"),
                "permission_group": attr(node, "permissionGroup"),
            })
        if len(declared) >= MAX_PERMISSIONS:
            break
    return requested, declared


def intent_filters(node):
    """(filters, deep_links) declared under a component."""
    filters, links = [], []
    for filt in node.findall("intent-filter"):
        actions = [attr(a, "name") for a in filt.findall("action")]
        categories = [attr(c, "name") for c in filt.findall("category")]
        auto_verify = bool_attr(filt, "autoVerify")
        entry = {
            "actions": [a for a in actions if a][:64],
            "categories": [c for c in categories if c][:64],
            "auto_verify": auto_verify,
        }
        filters.append(entry)
        for data in filt.findall("data"):
            scheme = attr(data, "scheme")
            if not scheme:
                continue
            links.append({
                "scheme": scheme,
                "host": attr(data, "host"),
                "port": attr(data, "port"),
                "path": attr(data, "path"),
                "path_prefix": attr(data, "pathPrefix"),
                "path_pattern": attr(data, "pathPattern"),
                "mime_type": attr(data, "mimeType"),
                "auto_verify": auto_verify,
                "browsable": "android.intent.category.BROWSABLE" in entry["categories"],
            })
    return filters[:64], links


def implicitly_exported(node, filters) -> bool:
    """Android's default: a component with an intent-filter is exported.

    Only meaningful when ``android:exported`` is absent, which is itself a
    finding on modern target SDKs, where the attribute is mandatory.
    """
    return bool(filters)


def collect_components(root):
    components, deep_links = [], []
    application = root.find("application")
    if application is None:
        return components, deep_links, {}

    for tag, kind in COMPONENT_TAGS.items():
        for node in application.findall(tag):
            if len(components) >= MAX_COMPONENTS:
                break
            name = attr(node, "name")
            if not name:
                continue
            filters, links = intent_filters(node)
            declared_export = bool_attr(node, "exported")
            entry = {
                "kind": kind,
                "tag": tag,
                "name": name,
                "exported": (declared_export if declared_export is not None
                             else implicitly_exported(node, filters)),
                "exported_declared": declared_export,
                "enabled": bool_attr(node, "enabled"),
                "permission": attr(node, "permission"),
                "read_permission": attr(node, "readPermission"),
                "write_permission": attr(node, "writePermission"),
                "grant_uri_permissions": bool_attr(node, "grantUriPermissions"),
                "authorities": attr(node, "authorities"),
                "process": attr(node, "process"),
                "target_activity": attr(node, "targetActivity"),
                "intent_filters": filters,
            }
            components.append(entry)
            for link in links:
                if len(deep_links) < MAX_DEEP_LINKS:
                    link["component"] = name
                    deep_links.append(link)

    app_attrs = {
        "debuggable": bool_attr(application, "debuggable"),
        "allow_backup": bool_attr(application, "allowBackup"),
        "uses_cleartext_traffic": bool_attr(application, "usesCleartextTraffic"),
        "network_security_config": attr(application, "networkSecurityConfig"),
        "backup_agent": attr(application, "backupAgent"),
        "full_backup_content": attr(application, "fullBackupContent"),
        "data_extraction_rules": attr(application, "dataExtractionRules"),
        "app_class": attr(application, "name"),
        "has_code": bool_attr(application, "hasCode"),
        "test_only": bool_attr(application, "testOnly"),
    }
    return components, deep_links, app_attrs


# ------------------------------------------------------------------ signing

def certificate_info(apk):
    certs = []
    try:
        raw_certs = apk.get_certificates_der_v2() or []
    except Exception:                                   # noqa: BLE001
        raw_certs = []
    if not raw_certs:
        try:
            raw_certs = apk.get_certificates_der_v3() or []
        except Exception:                               # noqa: BLE001
            raw_certs = []
    if not raw_certs:
        try:
            raw_certs = [c.dump() for c in (apk.get_certificates() or [])]
        except Exception:                               # noqa: BLE001
            raw_certs = []

    for der in raw_certs[:16]:
        entry = {"sha256": hashlib.sha256(der).hexdigest()}
        try:
            from asn1crypto import x509
            cert = x509.Certificate.load(der)
            entry.update({
                "subject": clip(cert.subject.human_friendly),
                "issuer": clip(cert.issuer.human_friendly),
                "serial": clip(str(cert.serial_number)),
                "not_before": clip(str(cert["tbs_certificate"]["validity"]["not_before"].native)),
                "not_after": clip(str(cert["tbs_certificate"]["validity"]["not_after"].native)),
                "signature_algorithm": clip(cert["signature_algorithm"].signature_algo),
                "hash_algorithm": clip(cert["signature_algorithm"].hash_algo),
                "self_signed": cert.self_signed != "no",
            })
        except Exception:                               # noqa: BLE001
            entry["parse_error"] = True
        certs.append(entry)

    signing = {}
    for version, getter in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"),
                            ("v3", "is_signed_v3")):
        fn = getattr(apk, getter, None)
        try:
            signing[version] = bool(fn()) if fn else None
        except Exception:                               # noqa: BLE001
            signing[version] = None
    return certs, signing


# ---------------------------------------------------------------- inventory

def file_inventory(path: str):
    """Walk the zip directly: cheaper and more predictable than via androguard."""
    native, dex, counts = [], [], {}
    total_files = 0
    uncompressed = 0
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                total_files += 1
                if total_files > MAX_FILES:
                    break
                uncompressed += int(info.file_size)
                name = info.filename
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                counts[ext] = counts.get(ext, 0) + 1
                if name.endswith(".so") and len(native) < MAX_NATIVE_LIBS:
                    parts = name.split("/")
                    native.append({
                        "path": clip(name),
                        "name": clip(parts[-1]),
                        "arch": clip(parts[1]) if name.startswith("lib/") and len(parts) > 2 else None,
                        "size": int(info.file_size),
                    })
                elif name.endswith(".dex") and len(dex) < 64:
                    entry = {"path": clip(name), "size": int(info.file_size)}
                    try:
                        entry["sha256"] = hashlib.sha256(zf.read(name)).hexdigest()
                    except Exception:                   # noqa: BLE001
                        entry["sha256"] = None
                    dex.append(entry)
    except (zipfile.BadZipFile, OSError) as exc:
        return native, dex, {"error": clip(str(exc))}

    top_extensions = sorted(counts.items(), key=lambda kv: -kv[1])[:25]
    return native, dex, {
        "file_count": total_files,
        "uncompressed_bytes": uncompressed,
        "extensions": dict(top_extensions),
    }


# --------------------------------------------------------------------- main

def analyze(path: str) -> dict:
    apk = load_apk(path)
    root = manifest_root(apk)
    components, deep_links, app_attrs = collect_components(root)
    requested, declared = collect_permissions(root)
    certificates, signing = certificate_info(apk)
    native_libs, dex, inventory = file_inventory(path)

    def safe(fn, default=None):
        try:
            return fn()
        except Exception:                               # noqa: BLE001
            return default

    app = {
        "package": clip(safe(apk.get_package)),
        "version_name": clip(safe(apk.get_androidversion_name)),
        "version_code": clip(safe(apk.get_androidversion_code)),
        "min_sdk": safe(apk.get_min_sdk_version),
        "target_sdk": safe(apk.get_target_sdk_version),
        "max_sdk": safe(apk.get_max_sdk_version),
        "effective_target_sdk": safe(getattr(apk, "get_effective_target_sdk_version", lambda: None)),
        "main_activity": clip(safe(apk.get_main_activity)),
        "app_name": clip(safe(apk.get_app_name)),
        "is_valid": bool(safe(apk.is_valid_APK, False)),
        "signing": signing,
    }
    app.update(app_attrs)

    return {
        "ok": True,
        "error": None,
        "tool": "androguard",
        "tool_version": androguard_version(),
        "app": app,
        "permissions": requested,
        "declared_permissions": declared,
        "components": components,
        "deep_links": deep_links,
        "certificates": certificates,
        "native_libs": native_libs,
        "dex": dex,
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
            "tool": "androguard",
            "tool_version": androguard_version(),
            "traceback": clip(traceback.format_exc(), 8000),
        }
    json.dump(document, sys.stdout, separators=(",", ":"), default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
