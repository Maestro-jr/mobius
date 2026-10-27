"""Meterless Runtime (Nightshift): mobius's primary AI provider.

Implements the Meterless Runtime provider contract published with the Power
Prompt at meterless.ai/engines.html:

* every call sends ``Authorization: Bearer <runtime token>`` and a stable
  ``meterless-app`` id; chat also sends ``meterless-scope: user``;
* ``GET /v1/models`` decides the connection state (401/403 is "unauthorized",
  200 carrying ``meterless/*`` ids is "online", anything else "offline"); a
  working ``/healthz`` proves only that the process is up, so it is not used as
  evidence of a model;
* ``POST /v1/chat/completions`` is the OpenAI-compatible chat route;
* errors arrive as ``{error: {message, type, code}}``, sometimes with a
  ``meterless`` block whose ``fix[]`` takes priority; a carrier refusal means
  "use another route", not "this hardware cannot";
* the timeout is 180 s, because a lane may be loading a model;
* the token is never logged, and the placeholder ``rt-local`` is refused.

Every completion produces a :class:`Receipt` naming the route that was asked
for and the concrete model that answered, as reported by the runtime. That
receipt is the evidence for "which model handled each request": the agent run
collects them into its ledger, so a reader can see that Nemotron did the work
rather than take it on trust.

Stdlib only (``urllib``), so the provider adds no dependency and tests inject a
fake transport instead of a network.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Callable
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlsplit

DEFAULT_BASE_URL = "http://127.0.0.1:8088/v1"
DEFAULT_APP = "mobius"
DEFAULT_ROUTE = "meterless/auto"
TIMEOUT_SECONDS = 180.0
_PLACEHOLDER_TOKENS = {"", "rt-local", "your-nightshift-runtime-token"}
# The contract's Auto Detect: these ports on these hosts, first online or
# unauthorized answer wins.
_DETECT_PORTS = (8088, 8090, 8787, 11434)
_DETECT_HOSTS = ("127.0.0.1", "localhost", "[::1]")

# (method, url, headers, body, timeout) -> (status, headers, body bytes)
Transport = Callable[[str, str, dict, bytes | None, float],
                     tuple[int, dict, bytes]]


@dataclass
class Receipt:
    """One request through the runtime: what was asked for, what answered."""

    request_id: str
    role: str                     # planner / executor / critic / assistant
    route: str                    # the model id sent, e.g. meterless/auto
    model: str                    # the model the runtime says answered
    latency_ms: int
    ok: bool
    prompt_tokens: int = 0
    completion_tokens: int = 0
    error: str = ""
    # Anything the runtime volunteered about routing (its ``meterless`` block
    # and ``meterless-*`` response headers), kept verbatim as evidence.
    runtime: dict = field(default_factory=dict)

    @property
    def nemotron(self) -> bool:
        return "nemotron" in self.model.lower()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["nemotron"] = self.nemotron
        return data


class MeterlessError(RuntimeError):
    """A runtime error, with the server's message first and its fixes."""

    def __init__(self, message: str, *, status: int = 0, type_: str = "",
                 code: str = "", fixes: list[str] | None = None,
                 carrier_refusal: bool = False) -> None:
        self.status = status
        self.type = type_
        self.code = code
        self.fixes = list(fixes or [])
        self.carrier_refusal = carrier_refusal
        text = message
        if carrier_refusal:
            text += " (this route cannot carry chat; use another route)"
        if self.fixes:
            text += ". Fix: " + "; ".join(self.fixes)
        super().__init__(text)


def normalize_base_url(url: str) -> str:
    """``<scheme>://<host>[:port]/v1`` from whatever was pasted."""
    url = (url or "").strip()
    if not url:
        return DEFAULT_BASE_URL
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/v1"


def _urllib_transport(method: str, url: str, headers: dict,
                      body: bytes | None, timeout: float) -> tuple[int, dict, bytes]:
    req = urlrequest.Request(url, data=body, method=method, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as response:   # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urlerror.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read() or b""


def _decode(body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _error_from(status: int, body: bytes) -> MeterlessError:
    data = _decode(body)
    err = data.get("error") if isinstance(data.get("error"), dict) else {}
    block = data.get("meterless") if isinstance(data.get("meterless"), dict) else {}
    fixes = [str(f) for f in (block.get("fix") or []) if f]
    code = str(err.get("code") or "")
    carrier = (code == "class_carrier_unsupported"
               or block.get("chat_carrier") is False)
    message = str(err.get("message") or "").strip()
    if not message:
        if status in (401, 403):
            message = "the Nightshift runtime token was refused"
        else:
            message = f"Nightshift returned HTTP {status}"
    return MeterlessError(message, status=status, type_=str(err.get("type") or ""),
                          code=code, fixes=fixes, carrier_refusal=carrier)


def _runtime_evidence(headers: dict, data: dict) -> dict:
    evidence: dict = {}
    if isinstance(data.get("meterless"), dict):
        evidence["meterless"] = data["meterless"]
    for name, value in (headers or {}).items():
        low = name.lower()
        if (low.startswith("meterless-") or low.startswith("x-meterless")) \
                and "token" not in low and "auth" not in low:
            evidence[low] = value
    return evidence


class MeterlessClient:
    """A client for one Nightshift runtime, bound to a default route.

    Satisfies the assistant's :class:`~themob.assist.llm.LlmClient` protocol
    (``complete``), and adds ``chat`` for a full message list, ``models`` for
    discovery and ``state`` for the connection check.
    """

    def __init__(self, base_url: str, token: str, model: str = DEFAULT_ROUTE,
                 *, app: str = DEFAULT_APP, role: str = "assistant",
                 max_output_tokens: int = 4096, temperature: float = 0.2,
                 transport: Transport | None = None,
                 sink: Callable[[Receipt], None] | None = None) -> None:
        if (token or "").strip() in _PLACEHOLDER_TOKENS:
            raise MeterlessError(
                "no real Nightshift runtime token: copy the API key from "
                "Nightshift > Console into METERLESS_RUNTIME_TOKEN")
        self.base_url = normalize_base_url(base_url)
        self._token = token.strip()
        self.model = model or DEFAULT_ROUTE
        self.app = (app or DEFAULT_APP).strip().lower()
        self.role = role
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self._transport = transport or _urllib_transport
        self._sink = sink
        self.receipts: list[Receipt] = []

    def __repr__(self) -> str:                       # never shows the token
        return f"MeterlessClient({self.base_url!r}, model={self.model!r})"

    @classmethod
    def from_env(cls, *, model: str | None = None, role: str = "assistant",
                 **kwargs) -> "MeterlessClient":
        return cls(os.environ.get("METERLESS_BASE_URL", DEFAULT_BASE_URL),
                   os.environ.get("METERLESS_RUNTIME_TOKEN", ""),
                   model or os.environ.get("METERLESS_MODEL") or DEFAULT_ROUTE,
                   app=os.environ.get("METERLESS_APP", DEFAULT_APP),
                   role=role, **kwargs)

    def with_route(self, model: str, role: str,
                   sink: Callable[[Receipt], None] | None = None) -> "MeterlessClient":
        """The same runtime and receipt ledger, pinned to another route."""
        twin = MeterlessClient(self.base_url, self._token, model, app=self.app,
                               role=role, max_output_tokens=self.max_output_tokens,
                               temperature=self.temperature,
                               transport=self._transport, sink=sink or self._sink)
        twin.receipts = self.receipts
        return twin

    # -- the wire ----------------------------------------------------------

    def _headers(self, *, chat: bool) -> dict:
        headers = {"Authorization": f"Bearer {self._token}",
                   "meterless-app": self.app,
                   "Accept": "application/json"}
        if chat:
            headers["meterless-scope"] = "user"
            headers["Content-Type"] = "application/json"
        return headers

    def _call(self, method: str, path: str, payload: dict | None = None,
              *, chat: bool = False) -> tuple[int, dict, dict]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        try:
            status, headers, raw = self._transport(
                method, self.base_url + path, self._headers(chat=chat), body,
                TIMEOUT_SECONDS)
        except (urlerror.URLError, OSError, TimeoutError) as exc:
            raise MeterlessError(
                f"Nightshift is not reachable at {self.base_url} ({exc}); "
                "is Nightshift running?") from exc
        if status >= 400:
            raise _error_from(status, raw)
        return status, headers, _decode(raw)

    # -- discovery ---------------------------------------------------------

    def state(self) -> str:
        """``online`` / ``unauthorized`` / ``offline``, per the contract."""
        try:
            _status, _headers, data = self._call("GET", "/models")
        except MeterlessError as exc:
            return "unauthorized" if exc.status in (401, 403) else "offline"
        ids = [str(m.get("id", "")) for m in data.get("data") or []
               if isinstance(m, dict)]
        return "online" if any(i.startswith("meterless/") for i in ids) else "offline"

    def models(self) -> list[dict]:
        """Every model the runtime exposes, unknown ``meterless/*`` ids kept."""
        _status, _headers, data = self._call("GET", "/models")
        return [m for m in data.get("data") or [] if isinstance(m, dict)]

    # -- chat --------------------------------------------------------------

    def chat(self, messages: list[dict], *, max_tokens: int | None = None,
             model: str | None = None) -> tuple[str, Receipt]:
        route = model or self.model
        request_id = str(uuid.uuid4())
        started = time.monotonic()
        payload = {"model": route, "messages": messages,
                   "max_tokens": max_tokens or self.max_output_tokens,
                   "temperature": self.temperature}
        try:
            _status, headers, data = self._call("POST", "/chat/completions",
                                                payload, chat=True)
        except MeterlessError as exc:
            self._record(Receipt(request_id, self.role, route, "", _ms(started),
                                 False, error=str(exc)))
            raise
        choices = data.get("choices") or []
        text = ""
        if choices and isinstance(choices[0], dict):
            text = ((choices[0].get("message") or {}).get("content") or "").strip()
        usage = data.get("usage") or {}
        receipt = Receipt(
            request_id, self.role, route,
            str(data.get("model") or "(runtime did not say)"), _ms(started),
            bool(choices),
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            runtime=_runtime_evidence(headers, data))
        if not choices:
            receipt.error = "the runtime returned no choices"
        self._record(receipt)
        if not choices:
            raise MeterlessError("Nightshift returned no completion choices")
        return text, receipt

    def complete(self, system: str, prompt: str,
                 *, max_tokens: int | None = None) -> str:
        text, _receipt = self.chat([{"role": "system", "content": system},
                                    {"role": "user", "content": prompt}],
                                   max_tokens=max_tokens)
        return text

    def _record(self, receipt: Receipt) -> None:
        self.receipts.append(receipt)
        if self._sink is not None:
            self._sink(receipt)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def autodetect(token: str = "", *, transport: Transport | None = None) -> str:
    """The first runtime URL that answers online or unauthorized, else ""."""
    send = transport or _urllib_transport
    for port in _DETECT_PORTS:
        for host in _DETECT_HOSTS:
            base = f"http://{host}:{port}/v1"
            headers = {"meterless-app": DEFAULT_APP, "Accept": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                status, _h, raw = send("GET", base + "/models", headers, None, 3.0)
            except (urlerror.URLError, OSError, TimeoutError):
                continue
            if status in (401, 403):
                return base
            ids = [str(m.get("id", "")) for m in _decode(raw).get("data") or []
                   if isinstance(m, dict)]
            if status == 200 and any(i.startswith("meterless/") for i in ids):
                return base
    return ""
