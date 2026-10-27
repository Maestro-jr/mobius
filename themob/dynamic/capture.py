"""Traffic capture: watch the app talk, and decrypt only what was authorised.

Executing the app generates real requests to real servers. Capturing them is
how "the app sends the session token in a query string" stops being a guess.
The hazard is the decryption: terminating TLS for a host means reading traffic
that may belong to somebody the engagement never named, so the interception
scope from the execution gate is law here.

**Two ways to capture, and themob is honest about which is running.**

* **mitmproxy**, which themob drives. It loads :mod:`scope_filter`, which
  decrypts hosts in scope and relays everything else untouched. themob reads
  the addon's own JSON log, so it never has to parse mitmproxy's binary format
  and the "which hosts were decrypted" record is one themob owns.
* **attach-your-own-Burp**, for the operator who already has a proxy. themob
  runs no proxy and decrypts nothing; it records that capture was delegated and
  to where. This exists because the build plan promised it and because a
  pentester's Burp setup is theirs, not something to duplicate.

**Interception needs a CA the device trusts, and themob cannot install it
silently.** So a plan carries the instruction rather than pretending the step
does not exist, and it says plainly that a pinned app defeats the CA regardless,
which is the seam back to the SSL-unpin job in 3.3.

The live proxy is isolated behind :meth:`CapturePlan.command`, the argv an
operator or an integration test runs. Everything decidable without a device,
the gate, the scope, the argv, the log parsing, is here and tested.
"""
from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gate import require_execution

logger = logging.getLogger(__name__)

ADDON_PATH = Path(__file__).resolve().parent / "addons" / "scope_filter.py"

_MITMDUMP = "mitmdump"
_DEFAULT_PORT = 8080


class CaptureError(RuntimeError):
    """Capture could not be prepared."""


@dataclass
class CapturePlan:
    """A prepared capture, before any proxy is started.

    ``kind`` is ``"mitmproxy"`` or ``"delegated"``. A delegated plan has no
    command: themob is not the one capturing, and the record says so.
    """

    kind: str
    scope: list[str] = field(default_factory=list)
    listen_host: str = "0.0.0.0"
    listen_port: int = _DEFAULT_PORT
    scope_file: Path | None = None
    log_file: Path | None = None
    command: list[str] = field(default_factory=list)
    external_proxy: str = ""
    instructions: list[str] = field(default_factory=list)

    @property
    def intercepts_anything(self) -> bool:
        return bool(self.scope)

    def to_detail(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            # Recorded in full: the whole point is that a disputed capture can
            # be answered with "these hosts and no others".
            "interception_scope": sorted(self.scope),
            "listen": f"{self.listen_host}:{self.listen_port}",
            "external_proxy": self.external_proxy,
        }


def _scope_for(repos, project_id: str) -> list[str]:
    """The interception scope the gate recorded. The gate is re-checked here."""
    detail = require_execution(repos, project_id)
    scope = detail.get("interception_scope") or []
    return sorted({str(h).strip().lower() for h in scope if str(h).strip()})


def mitmproxy_capture(repos, project_id: str, workdir: str | Path, *,
                      listen_host: str = "0.0.0.0",
                      listen_port: int = _DEFAULT_PORT) -> CapturePlan:
    """Prepare a themob-driven mitmproxy capture, scoped to the attestation.

    Writes the scope to a file the addon reads, so the list of hosts whose TLS
    may be terminated travels as data rather than as a command line a shell
    could mangle.
    """
    scope = _scope_for(repos, project_id)
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    scope_file = work / "intercept-scope.json"
    log_file = work / "capture.jsonl"

    scope_file.write_text(json.dumps(scope), encoding="utf-8")
    log_file.write_text("", encoding="utf-8")

    # The addon reads its scope and log paths from the environment (see
    # environment()), not from the command line: a path on argv is a path a
    # shell could touch, and these decide what gets decrypted.
    command = [
        _MITMDUMP,
        "--listen-host", listen_host,
        "--listen-port", str(int(listen_port)),
        "-s", str(ADDON_PATH),
        "-q",
    ]

    instructions = _ca_instructions(scope)
    return CapturePlan(
        kind="mitmproxy", scope=scope, listen_host=listen_host,
        listen_port=int(listen_port), scope_file=scope_file, log_file=log_file,
        command=command, instructions=instructions)


def delegated_capture(repos, project_id: str, external_proxy: str) -> CapturePlan:
    """Record that capture is delegated to the operator's own proxy.

    themob runs nothing and decrypts nothing. The record exists so the report
    can say the traffic went through Burp at this address rather than implying
    themob saw it.
    """
    scope = _scope_for(repos, project_id)
    proxy = (external_proxy or "").strip()
    if not proxy:
        raise CaptureError("a delegated capture needs the proxy address the "
                           "device is pointed at, e.g. 127.0.0.1:8080")
    return CapturePlan(
        kind="delegated", scope=scope, external_proxy=proxy,
        instructions=[
            f"Point the device's proxy at {proxy}.",
            "themob is not capturing: your proxy is. Only the hosts you are "
            "authorised to intercept should be decrypted there.",
        ])


def environment(plan: CapturePlan) -> dict[str, str]:
    """The env the addon reads. Passed to the proxy process, not the shell."""
    env: dict[str, str] = {}
    if plan.scope_file:
        env["THEMOB_SCOPE_FILE"] = str(plan.scope_file)
    if plan.log_file:
        env["THEMOB_CAPTURE_LOG"] = str(plan.log_file)
    return env


def is_available(mitmdump_bin: str = _MITMDUMP) -> bool:
    return shutil.which(mitmdump_bin) is not None


# ------------------------------------------------------------------- reading

@dataclass
class Flow:
    """One request/response themob was authorised to see."""

    host: str
    method: str = ""
    scheme: str = ""
    path: str = ""
    status: int | None = None


@dataclass
class CaptureResult:
    """What a capture saw: what it decrypted, and what it deliberately did not."""

    intercepted_hosts: list[str] = field(default_factory=list)
    passed_through_hosts: list[str] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (f"{len(self.flows)} request(s) across "
                f"{len(self.intercepted_hosts)} intercepted host(s); "
                f"{len(self.passed_through_hosts)} host(s) passed through "
                "untouched")


def read_capture(log_path: str | Path) -> CaptureResult:
    """Parse the addon's JSON-lines log. Treated as untrusted, like any capture.

    A capture log records traffic from a hostile app, so a malformed line is
    skipped rather than trusted, and the parse never raises on content.
    """
    result = CaptureResult()
    path = Path(log_path)
    if not path.is_file():
        return result

    flows: dict[tuple, Flow] = {}
    intercepted: set[str] = set()
    passed: set[str] = set()

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            line = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(line, dict):
            continue
        host = str(line.get("host") or "")
        event = line.get("event")

        if event == "intercept":
            intercepted.add(host)
        elif event == "passthrough":
            passed.add(host)
        elif event == "request":
            key = (host, str(line.get("method") or ""), str(line.get("path") or ""))
            flows[key] = Flow(host=host, method=str(line.get("method") or ""),
                              scheme=str(line.get("scheme") or ""),
                              path=str(line.get("path") or ""))
        elif event == "response":
            status = line.get("status")
            for flow in flows.values():
                if flow.host == host and flow.status is None:
                    flow.status = int(status) if isinstance(status, int) else None
                    break

    # A host that produced a request was necessarily intercepted, even if the
    # clienthello line was lost: the flows are the stronger evidence.
    intercepted |= {flow.host for flow in flows.values()}
    result.intercepted_hosts = sorted(intercepted)
    result.passed_through_hosts = sorted(passed - intercepted)
    result.flows = sorted(flows.values(),
                          key=lambda f: (f.host, f.path, f.method))
    return result


def _ca_instructions(scope: list[str]) -> list[str]:
    if not scope:
        return [
            "No hosts are in the interception scope, so nothing will be "
            "decrypted: this capture records which hosts the app contacts, "
            "not what it sends them.",
        ]
    return [
        "Install mitmproxy's CA certificate on the device and trust it as a "
        "user CA (mitm.it once the proxy is running).",
        "Android 7+ ignores user CAs for app traffic unless the app opts in, "
        "so a release build usually needs the SSL-unpin job as well.",
        "Only these hosts will be decrypted: " + ", ".join(sorted(scope))
        + ". Every other host is relayed untouched.",
    ]
