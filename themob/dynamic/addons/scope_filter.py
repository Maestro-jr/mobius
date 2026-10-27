"""A mitmproxy addon that decrypts only what the engagement authorised.

This runs inside mitmproxy's own process, not themob's, so it stands alone: no
themob imports, no dependencies beyond mitmproxy itself. themob writes the
interception scope to a file and points ``THEMOB_SCOPE_FILE`` at it; this reads
that file and, for every connection, decides whether to terminate TLS or let it
pass through untouched.

**Out of scope means passthrough, not block.** A host nobody authorised is not
dropped, it is relayed without being decrypted, so the app behaves normally and
the operator has not silently MITMed a third party. The one thing that must
never happen is decrypting a host that is not in scope, and that is the single
decision this file exists to get right.

**The matching is a copy of ``themob.dynamic.gate.host_in_scope`` on purpose.**
It cannot import it, because mitmproxy's interpreter is not themob's. So
``tests/test_dynamic_capture.py`` loads both and asserts they agree across a
battery of hosts: the copy is allowed, drifting from the original is not.

Every decision is appended to ``THEMOB_CAPTURE_LOG`` as one JSON line, which is
what themob reads back. "Which hosts did you decrypt" is the question a disputed
capture turns on, and this is the record that answers it.
"""
from __future__ import annotations

import json
import os
import time


def host_in_scope(host: str, scope) -> bool:
    """Kept identical to themob.dynamic.gate.host_in_scope. See the module doc."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    for entry in scope or ():
        entry = (entry or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def load_scope(path: str) -> list:
    """Read the scope themob wrote. A missing or unreadable file means nothing.

    Failing closed here matters more than anywhere: if the scope cannot be read,
    the safe reading is "intercept nothing", never "intercept everything".
    """
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict) and isinstance(data.get("scope"), list):
        return [str(x) for x in data["scope"]]
    return []


class ScopeFilter:
    """mitmproxy addon: passthrough for everything outside the attested scope."""

    def __init__(self) -> None:
        self.scope = load_scope(os.environ.get("THEMOB_SCOPE_FILE", ""))
        self.log_path = os.environ.get("THEMOB_CAPTURE_LOG", "")
        self.intercepted: set = set()
        self.passed_through: set = set()

    # ------------------------------------------------------------------ hooks

    def tls_clienthello(self, data) -> None:
        """The decision point: decrypt this connection, or relay it untouched.

        mitmproxy calls this before the TLS handshake. Setting
        ``ignore_connection`` makes it a blind relay: the bytes pass through and
        nothing is decrypted. That is what an out-of-scope host gets.
        """
        host = _sni(data)
        if host_in_scope(host, self.scope):
            self.intercepted.add(host)
            self._record("intercept", host)
        else:
            data.ignore_connection = True
            self.passed_through.add(host)
            self._record("passthrough", host)

    def request(self, flow) -> None:
        """Log the requests themob is allowed to see: the intercepted ones.

        A passed-through flow was never decrypted, so there is no request to
        log, which is the correct and only outcome for a host out of scope.
        """
        try:
            host = flow.request.pretty_host
        except Exception:                                  # noqa: BLE001
            return
        if not host_in_scope(host, self.scope):
            return
        self._record("request", host, method=flow.request.method,
                     scheme=flow.request.scheme, path=flow.request.path)

    def response(self, flow) -> None:
        try:
            host = flow.request.pretty_host
            status = flow.response.status_code
        except Exception:                                  # noqa: BLE001
            return
        if not host_in_scope(host, self.scope):
            return
        self._record("response", host, status=status)

    # --------------------------------------------------------------- internal

    def _record(self, event: str, host: str, **extra) -> None:
        line = {"ts": round(time.time(), 3), "event": event, "host": host}
        line.update(extra)
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(line) + "\n")
        except OSError:
            pass


def _sni(data) -> str:
    """The host from the TLS ClientHello, across mitmproxy versions."""
    for attr in ("sni",):
        value = getattr(data, attr, None)
        if value:
            return str(value)
    context = getattr(data, "context", None)
    address = getattr(getattr(context, "server", None), "address", None)
    if address and isinstance(address, (list, tuple)) and address:
        return str(address[0])
    return ""


# mitmproxy discovers addons through a module-level ``addons`` list.
addons = [ScopeFilter()]
