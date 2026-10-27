"""themob's AI assistant: explain a project's real findings and coach the fix.

The product that sits on top of the deterministic engine. It reads the findings
themob actually produced, never invents one, and asks a model to put them in
plain language with a step-by-step fix. The one-shot explainer is
:mod:`themob.assist.core`; :mod:`themob.assist.agent` is the multi-step
investigation agent that drives themob's read-only tools to answer a free-form
goal. Both are Qt-free and model-agnostic: the desktop panel wires a real model
client in, the tests wire a stub. The model binding (Claude, or a free provider)
is :mod:`themob.assist.llm`, and the dormant license gate is
:mod:`themob.assist.license`.
"""
from __future__ import annotations

__all__ = ["agent", "core", "license", "llm"]
