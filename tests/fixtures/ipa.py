"""A tiny, valid .ipa built in code, so tests need no third-party iOS app.

Mirrors tests/fixtures/apk.py: a real zip with a Payload/<name>.app/ bundle, a
binary Info.plist, a minimal (placeholder) Mach-O, one embedded framework and a
dylib, and (optionally) an embedded.mobileprovision carrying entitlements. It is
enough for intake, the unpack adapter's run and normalize paths, the worker's
structural helpers (plist, frameworks, entitlements) and the iOS config auditor.
The real lief Mach-O parse is exercised under -m docker, not in the hermetic
suite.
"""
from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

# A 64-bit little-endian Mach-O magic, padded, so the bytes at least look like a
# Mach-O. lief in the container does the real parse; the hermetic tests only need
# the file to exist and be listed.
_MACHO_MAGIC = b"\xcf\xfa\xed\xfe" + b"\x00" * 60


def info_plist(*, bundle_id: str = "com.example.demo", name: str = "Demo",
               executable: str = "Demo", version: str = "1.0", build: str = "1",
               min_os: str = "14.0", url_schemes=("demo",),
               arbitrary_loads: bool = False, arbitrary_loads_web: bool = False,
               insecure_domains=(), file_sharing: bool = False,
               document_browser: bool = False) -> bytes:
    """A binary Info.plist, the common iOS form."""
    info = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": name,
        "CFBundleDisplayName": name,
        "CFBundleExecutable": executable,
        "CFBundleShortVersionString": version,
        "CFBundleVersion": build,
        "MinimumOSVersion": min_os,
        "DTPlatformName": "iphoneos",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": list(url_schemes)}],
        "UIFileSharingEnabled": file_sharing,
        "UISupportsDocumentBrowser": document_browser,
    }
    ats: dict = {}
    if arbitrary_loads:
        ats["NSAllowsArbitraryLoads"] = True
    if arbitrary_loads_web:
        ats["NSAllowsArbitraryLoadsInWebContent"] = True
    if insecure_domains:
        ats["NSExceptionDomains"] = {
            domain: {"NSExceptionAllowsInsecureHTTPLoads": True}
            for domain in insecure_domains}
    if ats:
        info["NSAppTransportSecurity"] = ats
    return plistlib.dumps(info, fmt=plistlib.FMT_BINARY)


def mobileprovision(*, entitlements=None, provisions_devices: bool = True,
                    name: str = "themob test profile",
                    team: str = "ABCDE12345") -> bytes:
    """A stand-in embedded.mobileprovision.

    The real file is a CMS (PKCS#7) container with a plaintext XML plist inside;
    the worker slices that plist out by its <plist> markers rather than verifying
    the signature. This mirrors the shape: an XML plist bracketed by filler
    bytes, so the slice-out path is what the test exercises.
    """
    profile = {
        "Name": name,
        "TeamIdentifier": [team],
        "Entitlements": dict(entitlements or {}),
    }
    if provisions_devices:
        profile["ProvisionedDevices"] = ["00000000-1111-2222-3333-444455556666"]
    plist = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
    return b"\x30\x82\x0a\x00CMS-outer-wrapper\x00" + plist + b"\x00signature"


def build_ipa(path, *, bundle_id: str = "com.example.demo", app_name: str = "Demo",
              executable: str = "Demo", url_schemes=("demo",),
              arbitrary_loads: bool = False, arbitrary_loads_web: bool = False,
              insecure_domains=(), file_sharing: bool = False,
              document_browser: bool = False, with_profile: bool = False,
              get_task_allow: bool = False, keychain_wildcard: bool = False,
              associated_domains_wildcard: bool = False) -> Path:
    """Write a minimal but structurally valid .ipa to *path*."""
    path = Path(path)
    app = f"Payload/{app_name}.app"
    plist = info_plist(bundle_id=bundle_id, name=app_name, executable=executable,
                       url_schemes=url_schemes, arbitrary_loads=arbitrary_loads,
                       arbitrary_loads_web=arbitrary_loads_web,
                       insecure_domains=insecure_domains, file_sharing=file_sharing,
                       document_browser=document_browser)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{app}/Info.plist", plist)
        zf.writestr(f"{app}/{executable}", _MACHO_MAGIC + b"main-macho")
        zf.writestr(f"{app}/Frameworks/Thing.framework/Thing",
                    _MACHO_MAGIC + b"thing-macho")
        zf.writestr(f"{app}/Frameworks/Thing.framework/Info.plist",
                    info_plist(bundle_id="com.example.thing", name="Thing",
                               executable="Thing"))
        zf.writestr(f"{app}/Frameworks/libextra.dylib", _MACHO_MAGIC + b"dylib")
        zf.writestr(f"{app}/Assets.car", b"assets")

        need_profile = (with_profile or get_task_allow or keychain_wildcard
                        or associated_domains_wildcard)
        if need_profile:
            entitlements = {"application-identifier": f"ABCDE12345.{bundle_id}"}
            if get_task_allow:
                entitlements["get-task-allow"] = True
            if keychain_wildcard:
                entitlements["keychain-access-groups"] = ["*"]
            if associated_domains_wildcard:
                entitlements["com.apple.developer.associated-domains"] = ["*"]
            zf.writestr(f"{app}/embedded.mobileprovision",
                        mobileprovision(entitlements=entitlements))
    return path
