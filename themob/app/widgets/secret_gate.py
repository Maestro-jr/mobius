"""Reveal state for secret values in the UI.

Secret findings (hardcoded keys, tokens, basic-auth strings) are shown masked by
default: a screen-share, a shoulder-surf, or a screenshot pasted into a chat
should not leak a credential at a glance. One toggle reveals every value on the
finding, and another hides them again.

There is no password. themob runs on the operator's own machine against an app
they are authorized to assess, and the real access control is the app's own
login, not this view; a password here only stood between the operator and their
own data. (Whether the full value exists to reveal at all is a separate matter:
the secret scanners redact inside the sandbox unless THEMOB_CAPTURE_SECRET_VALUES
is set. See adapters/base.py.)
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import QWidget

# Weakness keys whose evidence is a secret to mask. Startswith for the namespaced
# ones; substring for the tokens a detector may place anywhere in the key.
_SECRET_PREFIXES = ("android.secrets.", "ios.secrets.")
_SECRET_TOKENS = ("secret", "credential", "api-key", "api_key", "apikey",
                  "token", "high-entropy", "hardcoded", "private-key",
                  "password")


def is_secret_finding(finding) -> bool:
    """Whether this finding's evidence is a credential that should be masked."""
    key = (getattr(finding, "weakness_key", "") or "").lower()
    if key.startswith(_SECRET_PREFIXES):
        return True
    return any(token in key for token in _SECRET_TOKENS)


def mask_secret(text: str, keep: int = 4, max_stars: int = 12) -> str:
    """A value with its middle starred out, keeping a few edge characters.

    Short values are starred whole (keeping edges of a 6-character value would
    reveal most of it). The star run is bounded so a long token does not render
    as a line of hundreds of asterisks.
    """
    s = text or ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    middle = min(len(s) - keep * 2, max_stars)
    return f"{s[:keep]}{'*' * middle}{s[-keep:]}"


class SecretGate:
    """Session reveal state for secret values: masked by default, one toggle
    reveals them. No password (see the module docstring)."""

    def __init__(self, home: str | Path | None = None) -> None:
        # home is accepted for call-site compatibility; nothing is persisted.
        self._unlocked = False

    @property
    def unlocked(self) -> bool:
        return self._unlocked

    def lock(self) -> None:
        self._unlocked = False

    def toggle(self, parent: Optional[QWidget] = None) -> bool:
        """Flip the reveal state and return it. No prompt: see the docstring."""
        self._unlocked = not self._unlocked
        return self._unlocked
