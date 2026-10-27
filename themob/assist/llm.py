"""The LLM binding for the assistant: Claude, or any free, OpenAI-compatible
provider, behind an optional dependency.

The model that explains and coaches is chosen by whichever key is set. Claude
(the ``anthropic`` SDK) is one option. Several providers with a genuinely free
tier speak the OpenAI chat API, so one small client reaches all of them by base
URL: Groq, Google Gemini (its OpenAI-compatible endpoint), OpenRouter, Mistral,
Cerebras, and a local Ollama. The SDKs are the optional ``themob[assist]`` extra;
without a key or the SDK the assistant degrades to a clear message, not a crash.

Pick a provider with ``THEMOB_LLM_PROVIDER``, or just set one provider's key and
it is auto-detected. Override the model with ``THEMOB_LLM_MODEL``.

The :class:`LlmClient` protocol is tiny on purpose, so the core logic and its
tests depend on no SDK: a stub client satisfies it in tests.
"""
from __future__ import annotations

import os
from typing import Protocol

_DEFAULT_CLAUDE_MODEL = "claude-sonnet-5-5"

# The answer budget, per provider. Groq counts prompt + this reservation against
# a free-tier tokens-per-minute cap (8000 on gpt-oss-120b), so a huge value is
# refused with a 413; 4096 stays under it. A capable provider (Gemini, Claude)
# has far more room, and a 70-finding report needs it, so those default higher,
# below in _PROVIDERS. Override any of them with THEMOB_LLM_MAX_TOKENS.
_DEFAULT_MAX_TOKENS = 4096
_LARGE_MAX_TOKENS = 8192


def _max_tokens(default: int = _DEFAULT_MAX_TOKENS) -> int:
    try:
        value = int(os.environ.get("THEMOB_LLM_MAX_TOKENS", "").strip())
    except ValueError:
        value = 0
    return value if value > 0 else default


# Low by default so the same question over the same findings gives a steady
# answer rather than wandering each time it is asked. Override with
# THEMOB_LLM_TEMPERATURE (0 is fully deterministic, 1 is the model default).
_DEFAULT_TEMPERATURE = 0.2


def _temperature() -> float:
    try:
        value = float(os.environ.get("THEMOB_LLM_TEMPERATURE", "").strip())
    except ValueError:
        return _DEFAULT_TEMPERATURE
    return value if 0.0 <= value <= 2.0 else _DEFAULT_TEMPERATURE

# provider -> how to reach it. The OpenAI-compatible ones differ only by base
# URL, the key variable, and a default model; Claude uses its own SDK.
_PROVIDERS: dict[str, dict] = {
    # Meterless Nightshift, the primary provider: the local AI hotspot that
    # routes to NVIDIA Nemotron lanes. Its own client implements the Runtime
    # contract (headers, discovery, errors, per-request model receipts).
    "meterless": {"keys": ("METERLESS_RUNTIME_TOKEN",), "model": "meterless/auto",
                  "meterless": True, "free": True, "max_tokens": _LARGE_MAX_TOKENS},
    "anthropic": {"keys": ("ANTHROPIC_API_KEY",), "model": _DEFAULT_CLAUDE_MODEL,
                  "native": True, "free": False, "max_tokens": _LARGE_MAX_TOKENS},
    "groq": {"keys": ("GROQ_API_KEY",),
             "base_url": "https://api.groq.com/openai/v1",
             "model": "openai/gpt-oss-120b", "free": True},
    "gemini": {"keys": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
               # Google retires flash model versions; override with
               # THEMOB_LLM_MODEL if this one is gone (the 404 says the current name).
               "model": "gemini-3.8-flash", "free": True,
               "max_tokens": _LARGE_MAX_TOKENS},
    "openrouter": {"keys": ("OPENROUTER_API_KEY",),
                   "base_url": "https://openrouter.ai/api/v1",
                   "model": "meta-llama/llama-3.3-70b-instruct:free", "free": True},
    "mistral": {"keys": ("MISTRAL_API_KEY",),
                "base_url": "https://api.mistral.ai/v1",
                "model": "mistral-small-latest", "free": True},
    "cerebras": {"keys": ("CEREBRAS_API_KEY",),
                 "base_url": "https://api.cerebras.ai/v1",
                 "model": "llama-3.3-70b", "free": True},
    "ollama": {"keys": (), "base_url": "http://localhost:11434/v1",
               "model": "llama3.1", "free": True, "no_key": True},
}
# Auto-detect order: Nightshift first, it is the primary provider. Ollama is not auto-chosen (it is a local server that may not
# be running); name it explicitly with THEMOB_LLM_PROVIDER=ollama.
_ORDER = ("meterless", "anthropic", "gemini", "groq", "openrouter", "mistral", "cerebras")


class LlmClient(Protocol):
    def complete(self, system: str, prompt: str,
                 *, max_tokens: int | None = None) -> str: ...


class AnthropicClient:
    def __init__(self, api_key: str, model: str,
                 max_output_tokens: int = _DEFAULT_MAX_TOKENS) -> None:
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        # The provider's answer budget, so a caller that wants "as much as this
        # provider allows" (the agent's final answer) can read it.
        self.max_output_tokens = max_output_tokens

    def complete(self, system: str, prompt: str,
                 *, max_tokens: int | None = None) -> str:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens or _max_tokens(self.max_output_tokens),
            temperature=_temperature(),
            system=system, messages=[{"role": "user", "content": prompt}])
        return "\n".join(block.text for block in message.content
                         if getattr(block, "type", "") == "text").strip()


class OpenAICompatibleClient:
    """Any provider that speaks the OpenAI chat API (Groq, Gemini, OpenRouter,
    Mistral, Cerebras, a local Ollama), chosen by base URL."""

    def __init__(self, base_url: str, api_key: str, model: str,
                 max_output_tokens: int = _DEFAULT_MAX_TOKENS) -> None:
        import openai
        self._client = openai.OpenAI(base_url=base_url, api_key=api_key or "none")
        self._model = model
        self.max_output_tokens = max_output_tokens
        # Open reasoning models (gpt-oss, qwen3) spend tokens thinking before
        # they write; with a small budget that leaves nothing for the answer.
        self._reasoning = any(tag in model.lower()
                              for tag in ("gpt-oss", "qwen3"))

    def complete(self, system: str, prompt: str,
                 *, max_tokens: int | None = None) -> str:
        budget = max_tokens or _max_tokens(self.max_output_tokens)
        kwargs: dict = {
            "model": self._model, "max_tokens": budget,
            "temperature": _temperature(),
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}]}
        # Explaining given findings is grounded Q&A, not a reasoning puzzle, so
        # keep the thinking short on a reasoning model regardless of budget. At
        # full effort it spent most of the budget before writing, leaving a short
        # and run-to-run variable answer; "low" gives the answer the tokens.
        if self._reasoning:
            kwargs["reasoning_effort"] = "low"
        response = self._client.chat.completions.create(**kwargs)
        return (response.choices[0].message.content or "").strip()


def _first_key(names) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _autodetect() -> str:
    for provider in _ORDER:
        if _first_key(_PROVIDERS[provider]["keys"]):
            return provider
    return ""


def _sdk_available(module: str) -> bool:
    # find_spec checks the SDK is importable WITHOUT importing it: the anthropic
    # and openai packages cost seconds to import, and a readiness check runs at
    # window construction, so importing them there stalls startup for no reason.
    import importlib.util
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def current_provider() -> str:
    """The provider that would be used, for display. Empty if none is configured."""
    return (os.environ.get("THEMOB_LLM_PROVIDER") or _autodetect() or "").lower()


def preflight(provider: str | None = None) -> tuple[bool, str]:
    """``(ready, reason)``: whether a client could be built, without building it.

    Checks the provider, the key and the SDK's presence, but imports no SDK and
    creates no client, so a readiness check (the Assistant status line) pays none
    of the SDK import cost. The real client, and the import, come from
    :func:`make_client` when the model is actually used.
    """
    provider = (provider or os.environ.get("THEMOB_LLM_PROVIDER")
                or _autodetect()).lower()
    if not provider:
        free = ", ".join(f"{p.upper()}_API_KEY" for p in
                         ("gemini", "groq", "openrouter"))
        return False, ("no LLM key set. Set ANTHROPIC_API_KEY, or a free "
                       f"provider's key ({free}), or THEMOB_LLM_PROVIDER=ollama")
    spec = _PROVIDERS.get(provider)
    if spec is None:
        return False, f"unknown LLM provider {provider!r}"
    if not _first_key(spec["keys"]) and not spec.get("no_key"):
        return False, (f"no API key set for {provider} (expected "
                       + " or ".join(spec["keys"]) + ")")
    if spec.get("meterless"):
        return True, ""                  # stdlib client, no SDK to check
    module = "anthropic" if spec.get("native") else "openai"
    if not _sdk_available(module):
        return False, (f'the {module} SDK is not installed '
                       '(pip install "themob[assist]")')
    return True, ""


def make_client(provider: str | None = None, model: str | None = None):
    """``(client, error)``: an LLM client, or None with a readable reason.

    The provider is ``THEMOB_LLM_PROVIDER``, else the one whose key is set. The
    free options (Groq, Gemini, OpenRouter, Mistral, Cerebras, a local Ollama)
    work exactly as Claude does; only the key and the model differ.
    """
    provider = (provider or os.environ.get("THEMOB_LLM_PROVIDER")
                or _autodetect()).lower()
    if not provider:
        free = ", ".join(f"{p.upper()}_API_KEY" for p in
                         ("gemini", "groq", "openrouter"))
        return None, ("no LLM key set. Set ANTHROPIC_API_KEY, or a free "
                      f"provider's key ({free}), or THEMOB_LLM_PROVIDER=ollama "
                      "for a local model")
    spec = _PROVIDERS.get(provider)
    if spec is None:
        return None, (f"unknown LLM provider {provider!r}; choose one of "
                      + ", ".join(sorted(_PROVIDERS)))
    model = model or os.environ.get("THEMOB_LLM_MODEL") or spec["model"]
    budget = spec.get("max_tokens", _DEFAULT_MAX_TOKENS)
    key = _first_key(spec["keys"])
    if not key and not spec.get("no_key"):
        return None, (f"no API key set for {provider} (expected "
                      + " or ".join(spec["keys"]) + ")")
    if spec.get("meterless"):
        from .meterless import MeterlessClient, MeterlessError
        try:
            return MeterlessClient.from_env(
                model=model if model != spec["model"] else None,
                max_output_tokens=budget), ""
        except MeterlessError as exc:
            return None, str(exc)
    if spec.get("native"):
        if not _sdk_available("anthropic"):
            return None, ('the anthropic SDK is not installed '
                          '(pip install "themob[assist]")')
        try:
            return AnthropicClient(key, model, budget), ""
        except Exception as exc:                 # noqa: BLE001
            return None, f"could not create the {provider} client: {exc}"
    if not _sdk_available("openai"):
        return None, ('the openai SDK is not installed '
                      '(pip install "themob[assist]")')
    try:
        return OpenAICompatibleClient(spec["base_url"], key, model, budget), ""
    except Exception as exc:                     # noqa: BLE001
        return None, f"could not create the {provider} client: {exc}"
