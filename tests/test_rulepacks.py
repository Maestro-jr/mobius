"""Extensible rule packs, and the policy that keeps them from being trusted blindly.

An operator can drop an extra weakness pack next to themob without rebuilding it,
by pointing ``THEMOB_KNOWLEDGE_EXTRA`` at a directory. That is a real convenience
and a real risk: a pack decides a finding's severity and its canonical key, so a
pack an attacker slipped onto disk could quietly downgrade a critical finding or
split a merge. The loader answers that with signatures. In strict mode an extra
pack loads only if it carries a signature from a key the operator listed in
``THEMOB_KNOWLEDGE_PUBKEYS``; outside strict mode an unsigned pack still loads,
but the load records that it was unverified so the provenance is never hidden.

These tests exercise that policy across the matrix that matters (signed, unsigned,
tampered, wrong key) x (strict, lax), the refusal to let an extra pack override a
built-in key, and the ``themob sign-pack`` command an operator uses to sign one.
The built-in-only path is covered in test_knowledge.py; here every pack is extra.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from themob import _signing
from themob.cli import sign_pack_main
from themob.knowledge import warnings as pack_warnings
from themob.knowledge import weaknesses

_HAS_CRYPTO = _signing.available()
_needs_crypto = pytest.mark.skipif(not _HAS_CRYPTO,
                                   reason="cryptography is not installed")

_EXTRA_KEY = "vendor.extra.thing"


def _valid(key: str = _EXTRA_KEY, **overrides) -> dict:
    doc = {
        "key": key,
        "title": "An extra weakness",
        "severity": "medium",
        "masvs_category": "MASVS-PLATFORM",
        "masvs_control": "MASVS-PLATFORM-1",
        "description": "Something an extra pack flags.",
        "remediation": "Stop doing it.",
    }
    doc.update(overrides)
    return doc


def _write_pack(directory: Path, name: str = "vendor-weaknesses.json",
                entries: list[dict] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps({"weaknesses": entries or [_valid()]}),
                    encoding="utf-8")
    return path


def _keypair(directory: Path) -> tuple[Path, Path]:
    """A private/public PEM pair on disk, named like sign-pack would name them."""
    directory.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = _signing.generate_keypair()
    priv = directory / "signing.pem"
    pub = directory / "signing.pub"
    priv.write_bytes(private_pem)
    pub.write_bytes(public_pem)
    return priv, pub


def _sign_pack(pack: Path, private_key: Path) -> Path:
    signature, _public = _signing.sign(pack.read_bytes(),
                                        private_key.read_bytes())
    sig = pack.with_name(pack.name + ".sig")
    sig.write_bytes(signature)
    return sig


def _configure(monkeypatch, *, extra: Path | None = None,
               pubkeys: list[Path] | None = None, strict: bool = False) -> None:
    for name in ("THEMOB_KNOWLEDGE_EXTRA", "THEMOB_KNOWLEDGE_PUBKEYS",
                 "THEMOB_KNOWLEDGE_STRICT"):
        monkeypatch.delenv(name, raising=False)
    if extra is not None:
        monkeypatch.setenv("THEMOB_KNOWLEDGE_EXTRA", str(extra))
    if pubkeys:
        monkeypatch.setenv("THEMOB_KNOWLEDGE_PUBKEYS",
                           os.pathsep.join(str(p) for p in pubkeys))
    if strict:
        monkeypatch.setenv("THEMOB_KNOWLEDGE_STRICT", "1")


# --------------------------------------------------- an extra pack is loaded

def test_an_unsigned_extra_pack_loads_but_is_flagged(tmp_path, monkeypatch):
    """The lax default: it runs, and the load says it could not vouch for it."""
    _write_pack(tmp_path / "extra")
    _configure(monkeypatch, extra=tmp_path / "extra")

    loaded = weaknesses.load()

    assert _EXTRA_KEY in loaded
    issues = pack_warnings()
    assert any("unverified" in w for w in issues), issues
    assert any("vendor-weaknesses.json" in w for w in issues)


@_needs_crypto
def test_a_signed_and_trusted_extra_pack_loads_without_warning(tmp_path,
                                                               monkeypatch):
    pack = _write_pack(tmp_path / "extra")
    priv, pub = _keypair(tmp_path / "keys")
    _sign_pack(pack, priv)
    _configure(monkeypatch, extra=tmp_path / "extra", pubkeys=[pub])

    loaded = weaknesses.load()

    assert _EXTRA_KEY in loaded
    assert pack_warnings() == []


@_needs_crypto
def test_strict_mode_skips_an_unsigned_pack(tmp_path, monkeypatch):
    _write_pack(tmp_path / "extra")
    _configure(monkeypatch, extra=tmp_path / "extra", strict=True)

    loaded = weaknesses.load()

    assert _EXTRA_KEY not in loaded
    assert any("skipped unverified" in w for w in pack_warnings())


@_needs_crypto
def test_strict_mode_skips_a_tampered_pack(tmp_path, monkeypatch):
    """Signed, the key is trusted, but the bytes changed after signing."""
    pack = _write_pack(tmp_path / "extra")
    priv, pub = _keypair(tmp_path / "keys")
    _sign_pack(pack, priv)
    # Edit the pack after signing: the signature no longer covers these bytes.
    pack.write_text(json.dumps({"weaknesses": [
        _valid(severity="info")]}), encoding="utf-8")
    _configure(monkeypatch, extra=tmp_path / "extra", pubkeys=[pub], strict=True)

    loaded = weaknesses.load()

    assert _EXTRA_KEY not in loaded
    assert any("skipped unverified" in w for w in pack_warnings())


@_needs_crypto
def test_strict_mode_skips_a_pack_signed_by_an_untrusted_key(tmp_path,
                                                             monkeypatch):
    """A valid signature is not enough; it must be a key the operator listed."""
    pack = _write_pack(tmp_path / "extra")
    signer, _signer_pub = _keypair(tmp_path / "signer")
    _sign_pack(pack, signer)
    _stranger_priv, stranger_pub = _keypair(tmp_path / "stranger")
    _configure(monkeypatch, extra=tmp_path / "extra",
               pubkeys=[stranger_pub], strict=True)

    loaded = weaknesses.load()

    assert _EXTRA_KEY not in loaded
    assert any("skipped unverified" in w for w in pack_warnings())


@_needs_crypto
def test_a_signed_pack_loads_only_the_matching_key_trusts_it(tmp_path,
                                                             monkeypatch):
    """The positive of the test above: the right key in the trust list loads it."""
    pack = _write_pack(tmp_path / "extra")
    signer, signer_pub = _keypair(tmp_path / "signer")
    _sign_pack(pack, signer)
    _stranger_priv, stranger_pub = _keypair(tmp_path / "stranger")
    # Both keys are trusted; only one of them signed the pack, which is enough.
    _configure(monkeypatch, extra=tmp_path / "extra",
               pubkeys=[stranger_pub, signer_pub], strict=True)

    loaded = weaknesses.load()

    assert _EXTRA_KEY in loaded
    assert pack_warnings() == []


# ---------------------------------------------- an extra pack cannot override

def test_an_extra_pack_cannot_redefine_a_builtin_key(tmp_path, monkeypatch):
    """The whole point of canonical keys: an extra pack must not shadow one.

    Overriding a built-in key would let a dropped-in pack change the severity or
    standards mapping of a weakness the engine already knows. The clash is
    refused; in the lax mode used here the built-in survives and the load warns.
    """
    builtin_key = next(iter(weaknesses.keys()))
    _write_pack(tmp_path / "extra",
                entries=[_valid(key=builtin_key, severity="info",
                                title="Impostor")])
    _configure(monkeypatch, extra=tmp_path / "extra")

    loaded = weaknesses.load()

    # The built-in definition is the one that survived, unchanged.
    assert loaded[builtin_key].title != "Impostor"
    assert any("already defined" in w for w in pack_warnings())


def test_an_explicit_directory_ignores_the_extra_pack_env(tmp_path, monkeypatch):
    """load(directory=...) is the trusted form: it reads only that directory.

    A caller that passes a directory is naming exactly the packs it wants, so
    the extra-pack environment must not smuggle more in behind it.
    """
    _write_pack(tmp_path / "extra", entries=[_valid(key="vendor.smuggled.in")])
    _configure(monkeypatch, extra=tmp_path / "extra")

    named = tmp_path / "named"
    _write_pack(named, entries=[_valid(key="vendor.named.only")])
    loaded = weaknesses.load(named)

    assert set(loaded) == {"vendor.named.only"}


# ------------------------------------------------------ preflight surfaces it

def test_the_preflight_surfaces_an_unverified_pack(tmp_path, monkeypatch):
    from themob import preflight

    _write_pack(tmp_path / "extra")
    _configure(monkeypatch, extra=tmp_path / "extra")
    weaknesses.load()  # populate the warnings the preflight reads

    check = preflight.knowledge_packs()

    assert check.state == preflight.WARN
    assert "unverified" in check.detail
    assert check.fix


# ------------------------------------------------------- the sign-pack command

@_needs_crypto
def test_sign_pack_generates_a_keypair(tmp_path, capsys):
    out = tmp_path / "operator.pem"
    rc = sign_pack_main(["--generate-key", str(out)])

    assert rc == 0
    assert out.is_file()
    assert out.with_suffix(".pub").is_file()
    # The private key is a real Ed25519 key: it can sign, and its public half
    # verifies the result.
    signature, public_pem = _signing.sign(b"probe", out.read_bytes())
    assert _signing.verify(b"probe", signature, public_pem)


@_needs_crypto
def test_sign_pack_signs_a_pack_that_then_loads_as_trusted(tmp_path, monkeypatch,
                                                           capsys):
    """The end-to-end path an operator actually walks."""
    pack = _write_pack(tmp_path / "extra")
    priv, pub = _keypair(tmp_path / "keys")

    rc = sign_pack_main([str(pack), "--key", str(priv)])
    assert rc == 0
    assert pack.with_name(pack.name + ".sig").is_file()

    # With the signature in place and the key trusted, strict mode loads it.
    _configure(monkeypatch, extra=tmp_path / "extra", pubkeys=[pub], strict=True)
    loaded = weaknesses.load()
    assert _EXTRA_KEY in loaded
    assert pack_warnings() == []


@_needs_crypto
def test_sign_pack_rejects_a_missing_pack(tmp_path, capsys):
    priv, _pub = _keypair(tmp_path / "keys")
    rc = sign_pack_main([str(tmp_path / "nope-weaknesses.json"),
                         "--key", str(priv)])
    assert rc == 2
    assert "no such pack" in capsys.readouterr().err


@_needs_crypto
def test_sign_pack_without_a_key_explains_itself(tmp_path, capsys):
    pack = _write_pack(tmp_path / "extra")
    rc = sign_pack_main([str(pack)])
    assert rc == 2
    assert "--key" in capsys.readouterr().err
