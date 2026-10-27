"""themob MobSF client: upload, scan, and bring back the JSON.

This runs in its own container on the service's internal network, which is the
whole point of the design (see themob/sandbox/service.py). MobSF is a server, so
something has to speak HTTP to it; making that a container rather than the
engine means the engine never opens a socket to a hostile service, and the
network the pair share has no route off the host.

Writes one JSON document to stdout and never raises: a failure is reported as
``{"ok": false, "error": ...}`` so the engine always gets a parseable answer.

Standard library only, on purpose. A client whose job is to move a file and read
some JSON does not need a dependency tree, and every dependency here would be
one more thing running beside a hostile sample.

MobSF is GPL and is reached over its published REST API only. Nothing of it is
imported, vendored or re-implemented here (locked decision 11); this file knows
three endpoint paths and the shape of the JSON that comes back, which is what
using an API means.

Contract with ``themob/adapters/mobsf_scan.py``:

    { "ok": bool, "error": str|null, "tool": "mobsf", "tool_version": str,
      "app": {"package": str, "version_name": str, "version_code": str,
              "sha256": str},
      "sections": { "<section>": [ {"rule": str, "title": str,
                                    "severity": str, "description": str,
                                    "targets": [str]} ] },
      "truncated": bool }
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
import urllib.error
import urllib.request
import uuid

INPUT_DIR = "/input"
# Bounded so a server that decides to return a gigabyte cannot become the
# engine's memory problem. The runner caps stdout too; this fails earlier and
# says why.
MAX_RESPONSE_BYTES = 96 * 1024 * 1024
MAX_ITEMS_PER_SECTION = 500
UPLOAD_TIMEOUT_S = 300
SCAN_TIMEOUT_S = 1800


def _fail(message: str, detail: str = "") -> dict:
    return {"ok": False, "error": message, "detail": detail, "tool": "mobsf",
            "tool_version": "", "app": {}, "sections": {}, "truncated": False}


def _sample() -> str:
    entries = [e for e in sorted(os.listdir(INPUT_DIR))
               if os.path.isfile(os.path.join(INPUT_DIR, e))]
    if not entries:
        raise FileNotFoundError(f"no sample mounted at {INPUT_DIR}")
    return os.path.join(INPUT_DIR, entries[0])


def _multipart(path: str) -> tuple[bytes, str]:
    """Encode one file as multipart/form-data.

    By hand rather than with requests: this is the only reason the client would
    need a dependency, and the encoding is twenty lines.
    """
    boundary = "----themob" + uuid.uuid4().hex
    name = os.path.basename(path)
    with open(path, "rb") as handle:
        payload = handle.read()

    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        payload,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    return body, f"multipart/form-data; boundary={boundary}"


def _post(url: str, api_key: str, body: bytes, content_type: str,
          timeout: float) -> dict:
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Authorization", api_key)
    request.add_header("Content-Type", content_type)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"the response exceeded {MAX_RESPONSE_BYTES} bytes")
    return json.loads(raw.decode("utf-8", "replace"))


def _form(fields: dict[str, str]) -> tuple[bytes, str]:
    from urllib.parse import urlencode
    return (urlencode(fields).encode(),
            "application/x-www-form-urlencoded")


def _wait_for(base: str, api_key: str, deadline: float) -> None:
    """MobSF answers before it is ready to scan; poll until it is."""
    last = ""
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(f"{base}/api/v1/scans", method="GET")
            request.add_header("Authorization", api_key)
            with urllib.request.urlopen(request, timeout=10):
                return
        except urllib.error.HTTPError as exc:
            # 401 means it is up and disagrees about the key, which polling
            # will never fix, so it is reported now rather than at the timeout.
            if exc.code == 401:
                raise PermissionError("MobSF rejected the API key") from None
            return
        except OSError as exc:
            last = str(exc)
            time.sleep(2)
    raise TimeoutError(f"MobSF never answered: {last}")


# --------------------------------------------------------------------- mapping

# Where in MobSF's report each section lives, and the key its items use for
# the rule id. MobSF has reshaped this JSON between releases, so each is looked
# up defensively and a section that is missing is reported empty rather than
# taken as "nothing found".
_SECTIONS = {
    "manifest": (("manifest_analysis", "manifest_findings"), "rule"),
    "code": (("code_analysis", "findings"), None),
    "network": (("network_security", "network_findings"), None),
    "certificate": (("certificate_analysis", "certificate_findings"), None),
}


def _dig(document: dict, path: tuple[str, ...]):
    node = document
    for step in path:
        if not isinstance(node, dict):
            return None
        node = node.get(step)
    return node


def _targets(item: dict) -> list[str]:
    """Whatever names a place, with the empties dropped.

    MobSF is inconsistent here: a manifest finding carries a list like
    ``["Activity", "com.example.shop.MainActivity"]``, the component type
    followed by its name, and the name is empty when it could not resolve one.
    Passing the empties through would let the adapter mistake the type for the
    name and file a finding against a place that does not exist.
    """
    for key in ("files", "path", "component", "name"):
        value = item.get(key)
        if isinstance(value, dict):
            found = sorted(str(k) for k in value if str(k).strip())
        elif isinstance(value, list):
            found = [str(v) for v in value if str(v).strip()]
        elif isinstance(value, str) and value.strip():
            found = [value]
        else:
            continue
        if found:
            return found[:20]
    return []


def _items(node, rule_key: str | None) -> list[dict]:
    """MobSF returns a list here in some releases and a dict in others."""
    out = []
    if isinstance(node, dict):
        pairs = node.items()
    elif isinstance(node, list):
        pairs = ((None, item) for item in node)
    else:
        return out

    for key, item in pairs:
        if not isinstance(item, dict):
            continue
        rule = str(item.get(rule_key) or key or item.get("rule") or
                   item.get("title") or "")
        if not rule:
            continue
        out.append({
            "rule": rule,
            "title": str(item.get("title") or rule),
            "severity": str(item.get("severity") or item.get("stat") or "info"),
            "description": str(item.get("description") or ""),
            "targets": _targets(item),
        })
    return out


def _shape(report: dict) -> tuple[dict, dict, bool]:
    app = {
        "package": str(report.get("package_name") or ""),
        "version_name": str(report.get("version_name") or ""),
        "version_code": str(report.get("version_code") or ""),
        "sha256": str(report.get("sha256") or ""),
    }
    sections: dict[str, list] = {}
    truncated = False
    for name, (path, rule_key) in _SECTIONS.items():
        items = _items(_dig(report, path), rule_key)
        if len(items) > MAX_ITEMS_PER_SECTION:
            items = items[:MAX_ITEMS_PER_SECTION]
            truncated = True
        sections[name] = items
    return app, sections, truncated


# ------------------------------------------------------------------------ main

def main() -> int:
    base = os.environ.get("THEMOB_MOBSF_URL", "").rstrip("/")
    api_key = os.environ.get("THEMOB_MOBSF_KEY", "")
    if not base or not api_key:
        print(json.dumps(_fail("THEMOB_MOBSF_URL and THEMOB_MOBSF_KEY are required")))
        return 1

    try:
        path = _sample()
        _wait_for(base, api_key, time.monotonic() + 120)

        body, content_type = _multipart(path)
        uploaded = _post(f"{base}/api/v1/upload", api_key, body, content_type,
                         UPLOAD_TIMEOUT_S)
        digest = uploaded.get("hash")
        if not digest:
            return _emit(_fail("MobSF accepted no upload",
                               json.dumps(uploaded)[:400]))

        scan_body, scan_type = _form({
            "hash": str(digest),
            "scan_type": str(uploaded.get("scan_type") or "apk"),
            "file_name": str(uploaded.get("file_name") or os.path.basename(path)),
        })
        report = _post(f"{base}/api/v1/scan", api_key, scan_body, scan_type,
                       SCAN_TIMEOUT_S)
        if not isinstance(report, dict) or not report:
            return _emit(_fail("MobSF returned no report"))

        app, sections, truncated = _shape(report)
        # Delete the scan so the service holds no copy of the sample after the
        # container is gone. Best effort: the container is destroyed either way.
        try:
            delete_body, delete_type = _form({"hash": str(digest)})
            _post(f"{base}/api/v1/delete_scan", api_key, delete_body,
                  delete_type, 60)
        except Exception:                                  # noqa: BLE001
            pass

        return _emit({
            "ok": True, "error": None, "tool": "mobsf",
            "tool_version": str(report.get("version") or ""),
            "app": app, "sections": sections, "truncated": truncated,
        })
    except PermissionError as exc:
        return _emit(_fail(str(exc)))
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace") if exc.fp else ""
        return _emit(_fail(f"MobSF returned HTTP {exc.code}", detail))
    except Exception as exc:                               # noqa: BLE001
        return _emit(_fail(f"{type(exc).__name__}: {exc}", traceback.format_exc()))


def _emit(document: dict) -> int:
    json.dump(document, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if document.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
