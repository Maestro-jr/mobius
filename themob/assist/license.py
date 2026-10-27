"""The license gate for the assistant: a signed, self-hosted license key.

The assistant is the licensed product. The engine, the CLI and the MCP server are
not gated by it; only the assistant is. A license is a small payload (licensee,
tier, expiry) signed with Ed25519, so it cannot be forged or edited, and it is
verified against a trusted public key the operator configures
(``THEMOB_LICENSE_PUBKEY``, or ``<home>/license.pub``). The private key is the
vendor's and never ships in this repository.

This reuses themob's existing Ed25519 primitives (:mod:`themob._signing`), so it
needs no new dependency. Without cryptography a check returns "not verified"
rather than silently passing, the same rule the report signing follows.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import _signing

_ENV_LICENSE = "THEMOB_LICENSE"
_ENV_PUBKEY = "THEMOB_LICENSE_PUBKEY"


@dataclass
class LicenseStatus:
    """Whether the assistant may run, and why not when it may not."""
    valid: bool
    reason: str = ""
    licensee: str = ""
    tier: str = ""
    expires: str = ""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def issue(private_key_pem: bytes, licensee: str, tier: str = "standard",
          days: int = 365) -> str:
    """Mint a license token. The vendor runs this with their private key."""
    now = datetime.now(timezone.utc)
    payload = {
        "licensee": licensee,
        "tier": tier,
        "issued": now.isoformat(timespec="seconds"),
        "expires": (now + timedelta(days=days)).isoformat(timespec="seconds"),
    }
    payload_bytes = _canonical(payload)
    signature, _public = _signing.sign(payload_bytes, private_key_pem)
    return f"{_b64(payload_bytes)}.{_b64(signature)}"


def verify(token: str, public_key_pem: bytes) -> LicenseStatus:
    """Verify a token's signature and expiry against *public_key_pem*."""
    if not _signing.available():
        return LicenseStatus(False, "cannot verify the license: cryptography is "
                             "not installed (pip install cryptography)")
    token = (token or "").strip()
    if token.count(".") != 1:
        return LicenseStatus(False, "the license key is malformed")
    payload_part, sig_part = token.split(".")
    try:
        payload_bytes = _unb64(payload_part)
        signature = _unb64(sig_part)
    except Exception:                        # noqa: BLE001
        return LicenseStatus(False, "the license key is malformed")
    if not _signing.verify(payload_bytes, signature, public_key_pem):
        return LicenseStatus(False, "the license signature does not verify")
    try:
        payload = json.loads(payload_bytes)
    except ValueError:
        return LicenseStatus(False, "the license payload is not readable")

    licensee = str(payload.get("licensee") or "")
    tier = str(payload.get("tier") or "")
    expires = str(payload.get("expires") or "")
    if expires:
        try:
            if datetime.fromisoformat(expires) < datetime.now(timezone.utc):
                return LicenseStatus(False, f"the license expired on {expires}",
                                     licensee=licensee, tier=tier, expires=expires)
        except ValueError:
            return LicenseStatus(False, "the license expiry is not a valid date")
    return LicenseStatus(True, "licensed", licensee=licensee, tier=tier,
                         expires=expires)


def _trusted_pubkey(home) -> bytes | None:
    env = os.environ.get(_ENV_PUBKEY)
    if env:
        path = Path(env).expanduser()
        if path.is_file():
            try:
                return path.read_bytes()
            except OSError:
                return None
        return env.encode("utf-8")           # the PEM itself, given inline
    if home:
        default = Path(home).expanduser() / "license.pub"
        if default.is_file():
            try:
                return default.read_bytes()
            except OSError:
                return None
    return None


def _load_token(home) -> str | None:
    env = os.environ.get(_ENV_LICENSE)
    if env:
        path = Path(env).expanduser()
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8").strip()
            except OSError:
                return None
        return env.strip()
    if home:
        default = Path(home).expanduser() / "license.key"
        if default.is_file():
            try:
                return default.read_text(encoding="utf-8").strip()
            except OSError:
                return None
    return None


def check(home=None) -> LicenseStatus:
    """The gate: load the trusted key and the license, and verify both."""
    pubkey = _trusted_pubkey(home)
    if pubkey is None:
        return LicenseStatus(False, "no trusted license key configured. Set "
                             "THEMOB_LICENSE_PUBKEY, or place license.pub in the "
                             "themob home directory.")
    token = _load_token(home)
    if not token:
        return LicenseStatus(False, "no license. Set THEMOB_LICENSE, or place "
                             "license.key in the themob home directory.")
    return verify(token, pubkey)
