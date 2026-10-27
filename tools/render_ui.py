"""Render themob's console to PNGs: the Overview, the Code page and the graph.

Seeds a throwaway project with a realistic graph, five findings and a small
decompiled-source tree, then grabs each page. Nothing is written outside the
output directory and a temp workspace, and no container is started.

Usage::

    python tools/render_ui.py [output-dir]
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# The offscreen plugin exposes zero font families on Windows, so every glyph
# renders as tofu and text metrics come out ~2x too wide, which wrecks the
# layout. Use the real platform plugin and keep the window off the screen
# with WA_DontShowOnScreen instead.
os.environ["QT_QPA_PLATFORM"] = os.environ.get("THEMOB_RENDER_QPA", "windows")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication

from themob.app import theme
from themob.app.main_window import MainWindow
from themob.audit.attestation import Attestation, AuditTrail
from themob.model.entities import Edge, Entity
from themob.model.enums import EdgeType, EntityType, Platform
from themob.orchestrator.intake import intake
from themob.storage.db import open_database
from themob.storage.repositories import Repositories
from tests.fixtures.apk import build_apk

OUT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "docs" / "screens"

PKG = "com.example.shop"

MAIN_ACTIVITY = "\n".join([
    "package com.example.shop;",
    "",
    "import android.app.Activity;",
    "import android.os.Bundle;",
    "import android.util.Log;",
    "",
    "/* Decompiled by jadx. */",
    "public class MainActivity extends Activity {",
    '    private static final String TAG = "MainActivity";',
    '    private static final String API_BASE = "https://shop.example.com/api/v1";',
    "",
    "    @Override",
    "    protected void onCreate(Bundle savedInstanceState) {",
    "        super.onCreate(savedInstanceState);",
    "        setContentView(R.layout.activity_main);",
    '        Log.d(TAG, "starting against " + API_BASE);',
    "        new SyncClient(API_BASE).schedule();",
    "    }",
    "",
    "    public boolean isDebugBuild() {",
    "        return (getApplicationInfo().flags & 2) != 0;",
    "    }",
    "}",
])

SYNC_CLIENT = "\n".join([
    "package com.example.shop;",
    "",
    "import java.net.URL;",
    "import javax.crypto.Cipher;",
    "import javax.crypto.spec.SecretKeySpec;",
    "",
    "public final class SyncClient {",
    "    private final String base;",
    "",
    "    public SyncClient(String base) {",
    "        this.base = base;",
    "    }",
    "",
    "    // A hardcoded key is the sort of thing 1.4 will flag.",
    '    private static final byte[] KEY = "s3cr3t-key-0001!".getBytes();',
    "",
    "    public Cipher cipher() throws Exception {",
    '        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");',
    '        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));',
    "        return c;",
    "    }",
    "",
    "    public URL endpoint(String path) throws Exception {",
    "        return new URL(this.base + path);",
    "    }",
    "",
    "    public void schedule() { /* ... */ }",
    "}",
])

SHOP_PROVIDER = "\n".join([
    "package com.example.shop.data;",
    "",
    "import android.content.ContentProvider;",
    "import android.content.ContentValues;",
    "import android.database.Cursor;",
    "import android.net.Uri;",
    "",
    "public class ShopProvider extends ContentProvider {",
    "    @Override",
    "    public boolean onCreate() {",
    "        return true;",
    "    }",
    "",
    "    @Override",
    "    public Cursor query(Uri uri, String[] projection, String selection,",
    "                        String[] selectionArgs, String sortOrder) {",
    "        // Concatenating into a query is what semgrep will look for.",
    '        return getDb().rawQuery("SELECT * FROM orders WHERE id = "',
    "                + uri.getLastPathSegment(), null);",
    "    }",
    "",
    "    @Override",
    "    public Uri insert(Uri uri, ContentValues values) { return null; }",
    "}",
])

SOURCES = {
    "com.example.shop.MainActivity": MAIN_ACTIVITY,
    "com.example.shop.SyncClient": SYNC_CLIENT,
    "com.example.shop.data.ShopProvider": SHOP_PROVIDER,
}


def main() -> int:
    # The console pops a modal when Docker is missing, correct behaviour
    # (themob will not fall back to parsing untrusted packages in-process),
    # but it would block an offscreen render. Screenshot the normal state.
    from themob.sandbox.runner import SandboxRunner
    SandboxRunner.is_available = lambda self: True
    SandboxRunner.has_image = lambda self, image: True

    app = QApplication.instance() or QApplication([])
    # Same bootstrap as themob/app/main.py, without it the window
    # renders unstyled with fallback fonts, which is not what ships.
    app.setApplicationName("themob")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(theme.stylesheet())
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="themob-render-"))

    database = open_database(tmp / "themob.db")
    repos = Repositories(database)
    audit = AuditTrail(repos.audit)

    apk = build_apk(tmp / "shop.apk")
    result = intake(apk, repos, audit, name="Example Shop", root=tmp / "home")
    audit.record_attestation(result.project, Attestation(
        target_name="shop.apk", target_sha256=result.sha256,
        operator="tester@lab", engagement_ref="ENG-DEMO", attested=True),
        repos.projects)

    project = repos.projects.get(result.project.id)

    def add(etype, key, **attrs):
        return repos.entities.upsert(project.id, Entity(
            type=etype, platform=Platform.ANDROID, key=key,
            label=key.rsplit(".", 1)[-1], attributes=attrs))

    # --- a decompiled tree for the Code page ---------------------------------
    sources_dir = "artifacts/jadx/sources"
    index = []
    for fqcn, body in SOURCES.items():
        package, _, name = fqcn.rpartition(".")
        rel = sources_dir + "/" + fqcn.replace(".", "/") + ".java"
        target = (result.workspace.artifacts_root / "jadx" / "sources"
                  / (fqcn.replace(".", "/") + ".java"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        index.append({"fqcn": fqcn, "package": package, "name": name,
                      "path": rel})

    # --- a graph with enough variety that the legend earns its space ---------
    app_node = add(EntityType.APP, PKG, package=PKG, version_name="3.2.1",
                   version_code="3021", min_sdk=24, target_sdk=34,
                   debuggable=True, allow_backup=True,
                   uses_cleartext_traffic=False,
                   signing={"v1": True, "v2": False, "v3": None},
                   network_security_config={
                       "path": "res/xml/network_security_config.xml",
                       "configs": [
                           {"scope": "base", "domains": [],
                            "trust_anchors": ["system", "user"]},
                           {"scope": "domain",
                            "domains": ["legacy.shop.example.com"],
                            "cleartext_permitted": True}]},
                   sources_dir=sources_dir, class_count=len(index))
    # Exported, but it is the launcher: the auditor must *not* flag it, and
    # the screenshot is a better demo for showing that it does not.
    activity = add(EntityType.COMPONENT, PKG + ".MainActivity",
                   kind="activity", exported=True,
                   intent_filters=[{
                       "actions": ["android.intent.action.MAIN"],
                       "categories": ["android.intent.category.LAUNCHER"],
                       "auto_verify": None}])
    service = add(EntityType.COMPONENT, PKG + ".SyncService",
                  kind="service", exported=False)
    provider = add(EntityType.COMPONENT, PKG + ".data.ShopProvider",
                   kind="provider", exported=True,
                   authorities=PKG + ".provider")
    perm_net = add(EntityType.PERMISSION, "android.permission.INTERNET",
                   requested=True, custom=False)
    perm_loc = add(EntityType.PERMISSION,
                   "android.permission.ACCESS_FINE_LOCATION",
                   requested=True, custom=False, protection_level="dangerous")
    perm_sync = add(EntityType.PERMISSION, PKG + ".permission.SYNC",
                    custom=True, declared_by_app=True, protection_level="normal")
    lib = add(EntityType.NATIVE_LIB, "lib/arm64-v8a/libshop.so",
              arch="arm64-v8a")
    link = add(EntityType.DEEP_LINK, "https://shop.example.com/order",
               scheme="https", host="shop.example.com")
    endpoint = add(EntityType.ENDPOINT, "https://shop.example.com/api/v1",
                   host="shop.example.com", scheme="https")
    secret = add(EntityType.SECRET, "aes-key:s3cr3t-key-0001",
                 kind="symmetric_key")

    for src, dst, etype in ((app_node, activity, EdgeType.EXPORTS),
                            (app_node, service, EdgeType.DECLARES),
                            (app_node, provider, EdgeType.EXPORTS),
                            (app_node, perm_net, EdgeType.REQUESTS_PERMISSION),
                            (app_node, perm_loc, EdgeType.REQUESTS_PERMISSION),
                            (provider, perm_sync, EdgeType.REQUESTS_PERMISSION),
                            (app_node, lib, EdgeType.EMBEDS),
                            (activity, link, EdgeType.DECLARES),
                            (activity, endpoint, EdgeType.TALKS_TO),
                            (provider, secret, EdgeType.USES)):
        repos.edges.upsert(project.id, Edge(src_id=src.id, dst_id=dst.id,
                                            type=etype))

    # --- real findings, from the real auditor --------------------------------
    # The config auditor needs no container: it judges the graph. So the screens
    # show what themob actually reports, not a hand-written impression of it.
    from themob.adapters.base import AnalysisContext
    from themob.adapters.config_audit import ConfigAuditAnalyzer
    from themob.correlate.graph import build_snapshot

    auditor = ConfigAuditAnalyzer()
    context = AnalysisContext(snapshot=build_snapshot(repos, project.id))
    raw = auditor.run(result.target, result.workspace, None, context)
    if not raw.ok:
        raise SystemExit(f"the auditor produced nothing to render: {raw.error}")
    for finding in auditor.normalize(raw, result.target).findings:
        repos.findings.upsert(project.id, finding)

    # --- render --------------------------------------------------------------
    window = MainWindow(database, tmp / "home")
    window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    window.resize(1560, 980)
    window.load_project(result)
    window.show()
    for _ in range(4):
        app.processEvents()

    window._sidebar.select("overview")
    for _ in range(4):
        app.processEvents()
    window.grab().save(str(OUT / "themob-overview.png"))

    window._code.load(result.workspace, index)
    window._code.open_class("com.example.shop.SyncClient")
    window._sidebar.select("code")
    for _ in range(4):
        app.processEvents()
    window.grab().save(str(OUT / "themob-code.png"))

    window._sidebar.select("graph")
    for _ in range(4):
        app.processEvents()
    window.grab().save(str(OUT / "themob-graph.png"))

    # A section panel: the projection of the graph a tester actually works in.
    window._sidebar.select("section:platform")
    for _ in range(4):
        app.processEvents()
    window.grab().save(str(OUT / "themob-section.png"))

    # One finding in full, with the verdict controls. Reached by clicking a
    # finding, so it has no nav entry to select.
    worst = sorted(repos.findings.list(project.id),
                   key=lambda f: -(f.risk or 0))[0]
    window._open_finding(worst.fingerprint)
    for _ in range(4):
        app.processEvents()
    window.grab().save(str(OUT / "themob-finding.png"))

    window._sidebar.select("queries")
    window._queries._select("reachable-secrets")
    app.processEvents()
    window.grab().save(str(OUT / "themob-queries.png"))

    window._sidebar.select("dynamic")
    app.processEvents()
    window.grab().save(str(OUT / "themob-dynamic.png"))

    # The collapsed rail, with the hover toggle forced visible. It normally
    # appears only while the pointer is near the sidebar, so a screenshot of
    # the resting state would never show it.
    window._sidebar.select("overview")
    window._sidebar.toggle()
    # Drive the collapse animation to its end value. Grabbing mid-flight caught
    # the rail at 186px with the buttons still stretched across it.
    for animation in window._sidebar._anims:
        animation.setCurrentTime(animation.duration())
    window._sidebar._toggle.show()
    window._sidebar._toggle.raise_()
    for _ in range(6):
        app.processEvents()
    window.grab().save(str(OUT / "themob-collapsed.png"))


    print("rendered:")
    for name in ("themob-overview.png", "themob-code.png",
                 "themob-graph.png", "themob-collapsed.png",
                 "themob-section.png", "themob-finding.png"):
        p = OUT / name
        print("  ", p, p.stat().st_size, "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
