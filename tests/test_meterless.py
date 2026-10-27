"""Meterless Runtime (Nightshift) provider: the Power contract, hermetically.

A fake transport stands in for Nightshift, so these prove the wire contract
(headers, routes, state, errors, receipts) with no network and no token.
"""
from __future__ import annotations

import json

import pytest

from themob.assist import llm
from themob.assist.meterless import (MeterlessClient, MeterlessError, autodetect,
                                     normalize_base_url)

_TOKEN = "ns-test-token-123"


class _FakeRuntime:
    def __init__(self, *, status=200, body=None, headers=None, models=None):
        self.calls: list[dict] = []
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.models = models if models is not None else [
            {"id": "meterless/auto"}, {"id": "meterless/fast"}]

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": json.loads(body) if body else None,
                           "timeout": timeout})
        if url.endswith("/models"):
            return self.status, {}, json.dumps({"data": self.models}).encode()
        payload = self.body if self.body is not None else {
            "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
            "choices": [{"message": {"content": "ready"}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 1}}
        return self.status, self.headers, json.dumps(payload).encode()


def _client(fake, **kwargs):
    return MeterlessClient("http://127.0.0.1:8088", _TOKEN, transport=fake, **kwargs)


def test_base_url_is_normalised_to_host_v1():
    assert normalize_base_url("127.0.0.1:8088") == "http://127.0.0.1:8088/v1"
    assert normalize_base_url("http://h:9/v1/chat/completions") == "http://h:9/v1"
    assert normalize_base_url("") == "http://127.0.0.1:8088/v1"


@pytest.mark.parametrize("token", ["", "rt-local", "your-nightshift-runtime-token"])
def test_placeholder_tokens_are_refused(token):
    with pytest.raises(MeterlessError, match="Console"):
        MeterlessClient("http://127.0.0.1:8088", token)


def test_chat_sends_the_contract_headers_and_route():
    fake = _FakeRuntime()
    text = _client(fake, role="planner").complete("sys", "hello")
    call = fake.calls[-1]
    assert text == "ready"
    assert call["method"] == "POST"
    assert call["url"] == "http://127.0.0.1:8088/v1/chat/completions"
    assert call["headers"]["Authorization"] == f"Bearer {_TOKEN}"
    assert call["headers"]["meterless-app"] == "mobius"
    assert call["headers"]["meterless-scope"] == "user"
    assert call["timeout"] == 180.0
    assert call["body"]["model"] == "meterless/auto"
    assert call["body"]["messages"][0] == {"role": "system", "content": "sys"}


def test_discovery_does_not_send_the_chat_scope():
    fake = _FakeRuntime()
    _client(fake).models()
    assert "meterless-scope" not in fake.calls[-1]["headers"]
    assert fake.calls[-1]["url"].endswith("/v1/models")


def test_receipt_names_the_model_that_answered():
    seen = []
    fake = _FakeRuntime(headers={"meterless-lane": "1", "meterless-provider": "nvidia",
                                 "Authorization": "never-kept"})
    client = _client(fake, role="executor", sink=seen.append)
    client.complete("s", "p")
    receipt = seen[0]
    assert receipt.role == "executor"
    assert receipt.route == "meterless/auto"
    assert receipt.model == "nvidia/nemotron-3.5-lightning-30b-a3b"
    assert receipt.nemotron is True
    assert receipt.prompt_tokens == 12 and receipt.completion_tokens == 1
    assert receipt.runtime == {"meterless-lane": "1", "meterless-provider": "nvidia"}
    assert client.receipts == [receipt]


def test_pinned_route_shares_the_receipt_ledger():
    fake = _FakeRuntime()
    base = _client(fake)
    critic = base.with_route("meterless/judge", "critic")
    critic.complete("s", "p")
    assert fake.calls[-1]["body"]["model"] == "meterless/judge"
    assert base.receipts[0].role == "critic"


@pytest.mark.parametrize("status,models,expected", [
    (200, [{"id": "meterless/auto"}], "online"),
    (200, [{"id": "llama3"}], "offline"),
    (401, [], "unauthorized"),
    (403, [], "unauthorized"),
    (500, [], "offline"),
])
def test_state_follows_the_models_route(status, models, expected):
    assert _client(_FakeRuntime(status=status, models=models)).state() == expected


def test_server_message_and_fixes_come_first():
    fake = _FakeRuntime(status=400, body={
        "error": {"message": "lane 2 has no model", "type": "invalid_request",
                  "code": "lane_empty"},
        "meterless": {"fix": ["assign a model to lane 2"]}})
    with pytest.raises(MeterlessError) as info:
        _client(fake).complete("s", "p")
    assert str(info.value).startswith("lane 2 has no model")
    assert info.value.fixes == ["assign a model to lane 2"]
    assert info.value.code == "lane_empty"


def test_carrier_refusal_means_use_another_route():
    fake = _FakeRuntime(status=400, body={
        "error": {"message": "image class", "code": "class_carrier_unsupported"}})
    with pytest.raises(MeterlessError) as info:
        _client(fake).complete("s", "p")
    assert info.value.carrier_refusal
    assert "use another route" in str(info.value)


def test_failed_request_still_leaves_a_receipt():
    fake = _FakeRuntime(status=401, body={})
    client = _client(fake)
    with pytest.raises(MeterlessError):
        client.complete("s", "p")
    assert client.receipts[0].ok is False
    assert "refused" in client.receipts[0].error


def test_unreachable_runtime_says_so():
    def down(*_args):
        raise OSError("connection refused")
    with pytest.raises(MeterlessError, match="is Nightshift running"):
        MeterlessClient("http://127.0.0.1:8088", _TOKEN, transport=down).complete("s", "p")


def test_the_token_never_appears_in_repr():
    assert _TOKEN not in repr(_client(_FakeRuntime()))


def test_autodetect_returns_the_first_runtime_that_answers():
    def transport(method, url, headers, body, timeout):
        if ":8090/" in url and "127.0.0.1" in url:
            return 401, {}, b"{}"
        raise OSError("closed")
    assert autodetect(transport=transport) == "http://127.0.0.1:8090/v1"


def test_meterless_is_the_primary_provider(monkeypatch):
    for name in ("THEMOB_LLM_PROVIDER", "THEMOB_LLM_MODEL", "METERLESS_MODEL",
                 "GEMINI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("METERLESS_RUNTIME_TOKEN", _TOKEN)
    monkeypatch.setenv("GEMINI_API_KEY", "also-set")
    assert llm.current_provider() == "meterless"
    assert llm.preflight() == (True, "")
    client, error = llm.make_client()
    assert error == "" and isinstance(client, MeterlessClient)
    assert client.model == "meterless/auto"


def test_make_client_explains_a_placeholder_token(monkeypatch):
    monkeypatch.setenv("METERLESS_RUNTIME_TOKEN", "rt-local")
    client, error = llm.make_client("meterless")
    assert client is None and "Console" in error
