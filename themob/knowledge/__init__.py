"""Standards knowledge: the loader for the rule packs at the repo root.

The packs themselves live in ``knowledge/`` beside ``workers/`` and
``shared/``, where the build plan's §13 puts them. This package reads and
validates them.

Kept separate from the adapters on purpose. An adapter knows how to run a tool;
it must not also be the place where "what this weakness *is*" lives, or every
tool integration grows its own private opinion of severity and every cross-tool
merge becomes a negotiation between them.
"""
from .weaknesses import (KNOWLEDGE_DIR, Weakness, WeaknessPackError,
                         catalogue, get, keys, load, warnings)

__all__ = ["KNOWLEDGE_DIR", "Weakness", "WeaknessPackError", "catalogue",
           "get", "keys", "load", "warnings"]
