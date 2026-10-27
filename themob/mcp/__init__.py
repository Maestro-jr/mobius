"""themob's Model Context Protocol server.

An agent (REA, Claude, or themob's own assistant) drives themob's contained,
reproducible tools through this, the same way the CLI and the window drive the
engine. The capabilities live in :mod:`themob.mcp.tools` as plain functions that
import neither the MCP SDK nor PyQt6; :mod:`themob.mcp.server` wraps them as MCP
tools, and the unit tests call the plain functions directly.

Run it over stdio::

    python -m themob.mcp
    themob mcp

Needs the optional MCP SDK: ``pip install "themob[mcp]"``. The tools themselves
run without it, which is why the logic and the SDK binding are separate files.
"""
from __future__ import annotations

__all__ = ["tools"]
