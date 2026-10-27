"""Masking and the reveal toggle that guard showing secret values."""
from __future__ import annotations

from types import SimpleNamespace

from themob.app.widgets.secret_gate import (SecretGate, is_secret_finding,
                                            mask_secret)


def test_mask_keeps_edges_and_bounds_the_star_run() -> None:
    secret = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
    masked = mask_secret(secret)
    assert masked.startswith(secret[:4])
    assert masked.endswith(secret[-4:])
    assert "*" in masked
    # The star run is bounded, so a long token is not a line of asterisks.
    assert masked.count("*") <= 12
    assert secret[4:-4] not in masked          # the middle is not recoverable


def test_mask_stars_short_values_whole() -> None:
    # Keeping four edge characters of a six-character value would reveal most
    # of it, so a short value is starred entirely.
    assert mask_secret("short!") == "*" * 6
    assert mask_secret("") == ""


def test_is_secret_finding_matches_credentials_not_crypto() -> None:
    assert is_secret_finding(SimpleNamespace(
        weakness_key="android.secrets.high-entropy-string"))
    assert is_secret_finding(SimpleNamespace(weakness_key="x.hardcoded-token"))
    assert is_secret_finding(SimpleNamespace(weakness_key="aws.api_key.exposed"))
    assert not is_secret_finding(SimpleNamespace(
        weakness_key="android.crypto.weak-cipher-mode"))
    assert not is_secret_finding(SimpleNamespace(weakness_key=None))


def test_the_gate_starts_masked_and_toggles_without_a_password(tmp_path) -> None:
    gate = SecretGate(tmp_path)
    assert not gate.unlocked               # masked by default

    assert gate.toggle() is True           # one toggle reveals, no prompt
    assert gate.unlocked
    assert gate.toggle() is False          # and hides again
    assert not gate.unlocked


def test_the_gate_persists_nothing(tmp_path) -> None:
    """No password means no hash file on disk."""
    gate = SecretGate(tmp_path)
    gate.toggle()
    gate.lock()
    assert list(tmp_path.iterdir()) == []
