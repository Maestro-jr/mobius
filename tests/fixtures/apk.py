"""Builds a real, parseable APK for tests.

A genuine Android package: a zip containing a binary ``AndroidManifest.xml``
(encoded by :mod:`tests.fixtures.axml`), a real ``classes.dex``, native
libraries, and a v1 signature block. androguard parses it the way it parses a
shipped app, so the vertical slice is exercised end to end without shipping a
third-party binary in the repository.

The manifest deliberately contains things the config auditor will care about in
Phase 1: debuggable, allowBackup, two Providers (one closed, one exported
and guarded only on reads), an unverified custom
scheme, so the same fixture keeps earning its place as adapters land.

The resource table is real. :mod:`tests.fixtures.arsc` builds a
``resources.arsc``, so apktool decodes "with resources" rather than falling back
to framework-only and emits an actual ``res/`` tree: ``values/strings.xml``,
the layout, and the network security config. The string resources carry an
HTTPS endpoint, a cleartext one, and a secret-shaped key, which is what the
secret scanners (1.4) and the endpoint extractor (1.7) are meant to find.

The manifest points ``android:networkSecurityConfig`` at that file by resource
id, so the config auditor's NSC checks run end to end: the config trusts the
user certificate store and opens one domain to cleartext, and both are findings.

The DEX is real. :mod:`tests.fixtures.dex` emits a decompilable
``classes.dex`` holding the four classes the manifest names, so jadx produces
Java from this fixture and the reverse-engineering stage can be asserted rather
than skipped. Its string constants are chosen for the stages that come next: an
HTTPS endpoint and a cleartext one for the endpoint extractor (1.7), and
secret-shaped strings for gitleaks and apkleaks (1.4).
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

from .axml import (ANDROID_NS, Attribute, Element, Reference,
                   encode_manifest)
from .arsc import network_security_config_id, shop_arsc
from .dex import shop_dex

PACKAGE = "com.example.shop"
VERSION_NAME = "3.2.1"
VERSION_CODE = 3021
MIN_SDK = 24
TARGET_SDK = 34


def _attr(name: str, value: object) -> Attribute:
    return Attribute(name=name, value=value, ns=ANDROID_NS)


def _plain(name: str, value: object) -> Attribute:
    return Attribute(name=name, value=value, ns=None)


def build_network_security_config() -> Element:
    """The NSC the manifest points at.

    Written so the config auditor has something real to judge end to end: the
    base config trusts the user certificate store, which is what makes casual
    interception possible on an unrooted device, and one domain opts back into
    cleartext. Both are findings, and both had unit coverage only.
    """
    root = Element("network-security-config")

    base = root.add(Element("base-config", [
        _plain("cleartextTrafficPermitted", False),
    ]))
    anchors = base.add(Element("trust-anchors"))
    anchors.add(Element("certificates", [_plain("src", "system")]))
    anchors.add(Element("certificates", [_plain("src", "user")]))

    domain = root.add(Element("domain-config", [
        _plain("cleartextTrafficPermitted", True),
    ]))
    domain.add(Element("domain", [_plain("includeSubdomains", True)],
                       text="legacy.shop.example.com"))
    return root


def build_layout() -> Element:
    """A tiny binary layout, so ``res/`` holds something apktool can decode.

    A four byte stub used to sit here. With a resource table present apktool
    actually tries to decode the file, and a stub makes it fail the whole
    package rather than the one resource.
    """
    return Element("LinearLayout", [
        Attribute("orientation", 1),
        Attribute("layout_width", -1),
        Attribute("layout_height", -1),
    ])


def build_manifest() -> Element:
    """The manifest tree for the fixture app."""
    manifest = Element("manifest", [
        _plain("package", PACKAGE),
        _attr("versionCode", VERSION_CODE),
        _attr("versionName", VERSION_NAME),
    ])

    manifest.add(Element("uses-sdk", [
        _attr("minSdkVersion", MIN_SDK),
        _attr("targetSdkVersion", TARGET_SDK),
    ]))

    for permission in ("android.permission.INTERNET",
                       "android.permission.READ_EXTERNAL_STORAGE",
                       "android.permission.ACCESS_FINE_LOCATION"):
        manifest.add(Element("uses-permission", [_attr("name", permission)]))

    # A permission the app defines itself, guarding its own provider.
    manifest.add(Element("permission", [
        _attr("name", f"{PACKAGE}.permission.SYNC"),
        _attr("protectionLevel", "signature"),
    ]))

    application = manifest.add(Element("application", [
        _attr("label", "Example Shop"),
        _attr("debuggable", True),          # a finding for the config auditor
        _attr("allowBackup", True),         # ditto
        _attr("usesCleartextTraffic", False),
        # A real resource reference, so apktool resolves the file and the
        # auditor judges what it actually declares rather than nothing.
        _attr("networkSecurityConfig", Reference(network_security_config_id())),
    ]))

    launcher = application.add(Element("activity", [
        _attr("name", ".MainActivity"),
        _attr("exported", True),
    ]))
    main_filter = launcher.add(Element("intent-filter"))
    main_filter.add(Element("action", [_attr("name", "android.intent.action.MAIN")]))
    main_filter.add(Element("category",
                            [_attr("name", "android.intent.category.LAUNCHER")]))

    # A verified https deep link...
    web = launcher.add(Element("intent-filter", [_attr("autoVerify", True)]))
    web.add(Element("action", [_attr("name", "android.intent.action.VIEW")]))
    web.add(Element("category",
                    [_attr("name", "android.intent.category.BROWSABLE")]))
    web.add(Element("data", [
        _attr("scheme", "https"),
        _attr("host", "shop.example.com"),
        _attr("path", "/order"),
    ]))

    # ...and an unverified custom scheme, which is the hijackable one.
    custom = launcher.add(Element("intent-filter"))
    custom.add(Element("action", [_attr("name", "android.intent.action.VIEW")]))
    custom.add(Element("category",
                       [_attr("name", "android.intent.category.BROWSABLE")]))
    custom.add(Element("data", [
        _attr("scheme", "exampleshop"),
        _attr("host", "pay"),
    ]))

    application.add(Element("service", [
        _attr("name", ".SyncService"),
        _attr("exported", False),
    ]))
    application.add(Element("receiver", [
        _attr("name", ".BootReceiver"),
        _attr("exported", True),
        _attr("permission", "android.permission.RECEIVE_BOOT_COMPLETED"),
    ]))
    # No android:exported at all: the SDK-31 case, where what matters is that
    # the *absence* survives into the graph. On a modern target SDK the
    # platform default leaves this one closed.
    application.add(Element("provider", [
        _attr("name", ".data.ShopProvider"),
        _attr("authorities", f"{PACKAGE}.provider"),
        _attr("readPermission", f"{PACKAGE}.permission.SYNC"),
    ]))
    # Genuinely exported, and guarded on reads only. Extremely common, and the
    # highest-value thing themob looks for: any app on the device can write to
    # it. It is also the fixture's one externally reachable finding, which is
    # what lets the scorer be tested end to end rather than in the abstract.
    application.add(Element("provider", [
        _attr("name", ".data.PublicProvider"),
        _attr("authorities", f"{PACKAGE}.public"),
        _attr("exported", True),
        _attr("readPermission", f"{PACKAGE}.permission.SYNC"),
    ]))
    return manifest


def _elf_shared_object(arch_marker: int) -> bytes:
    """A 64-bit ELF header: enough for inventory to see a native library."""
    header = bytearray(b"\x7fELF")
    header += bytes([2, 1, 1, 0])                      # 64-bit, LE, v1, SysV
    header += b"\x00" * 8
    header += struct.pack("<HH", 3, arch_marker)       # ET_DYN, e_machine
    header += struct.pack("<I", 1)                     # e_version
    header += b"\x00" * 40
    return bytes(header) + b"themob test .so".ljust(128, b"\x00")


# What the app bundles, as an APK actually records it.
#
# Android has no dependency manifest inside the package: Gradle merges every
# library into classes.dex, and what is left is these two conventions. AndroidX
# and Google libraries drop "<groupId>_<artifactId>.version" into META-INF, and
# a shaded Maven artifact keeps its pom.properties.
#
# This matters more than it looks: syft, the tool the build plan names for SBOM
# work, reports zero artifacts for both of these and for the APK as a whole,
# because its Java support reads inside JAR archives and an APK has none.
DEPENDENCY_MARKERS: dict[str, str] = {
    # Catalogued and clean, so "found a library" and "found a vulnerability"
    # can be told apart.
    "META-INF/androidx.core_core.version": "1.12.0",
    "META-INF/androidx.appcompat_appcompat.version": "1.6.1",
    # Catalogued and vulnerable: 2.8.5 predates the fix in 2.8.9.
    "META-INF/maven/com.google.code.gson/gson/pom.properties": "\n".join([
        "#Generated by Maven",
        "groupId=com.google.code.gson",
        "artifactId=gson",
        "version=2.8.5",
        "",
    ]),
}

VULNERABLE_LIBRARY = "pkg:maven/com.google.code.gson/gson@2.8.5"
CLEAN_LIBRARY = "pkg:maven/androidx.core/core@1.12.0"


def build_apk(path: str | Path, *, with_native: bool = True,
              with_dex: bool = True) -> Path:
    """Write a parseable APK to *path* and return it."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        # AndroidManifest.xml must be stored first, as aapt writes it.
        archive.writestr("AndroidManifest.xml", encode_manifest(build_manifest()))
        if with_dex:
            archive.writestr("classes.dex", shop_dex())
        archive.writestr("resources.arsc", shop_arsc())
        archive.writestr("res/xml/network_security_config.xml",
                         encode_manifest(build_network_security_config()))
        archive.writestr("res/layout/activity_main.xml",
                         encode_manifest(build_layout()))
        archive.writestr("assets/config.json",
                         b'{"api_base":"https://api.example.com/v2"}')
        if with_native:
            archive.writestr("lib/arm64-v8a/libshop.so", _elf_shared_object(0xB7))
            archive.writestr("lib/armeabi-v7a/libshop.so", _elf_shared_object(0x28))
        # Dependency evidence, the way a real APK carries it. Every library has
        # been merged into classes.dex by this point, so these markers are all
        # that survives to say what was bundled.
        #
        # gson 2.8.5 is deliberately a version with a published advisory, so the
        # CVE path has something true to match. androidx.core is the control:
        # present, catalogued, and not vulnerable.
        for marker, body in DEPENDENCY_MARKERS.items():
            archive.writestr(marker, body)

        archive.writestr("META-INF/MANIFEST.MF",
                         "Manifest-Version: 1.0\r\nCreated-By: themob-tests\r\n\r\n")
        archive.writestr("META-INF/CERT.SF",
                         "Signature-Version: 1.0\r\nCreated-By: themob-tests\r\n\r\n")
        archive.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x00" + b"\x00" * 128)
    return target
