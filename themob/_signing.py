"""Ed25519 signing primitives, shared and dependency-light.

Two places need to make and check signatures: the tamper-evident report
manifest (:mod:`themob.report.signing`) and the rule-pack loader
(:mod:`themob.knowledge`). Both need the same three operations and neither
should have to import the other's package to get them, so the primitives live
here, at the top of the tree, importing nothing from themob and only lazily from
``cryptography``.

Ed25519, because the keys and signatures are small, there are no parameters to
get wrong, and verification is fast. ``cryptography`` is an optional dependency,
so the import is deferred and its absence is a clear message rather than a crash
at startup. Everything that only *verifies* still works to say "not verified"
when the package is missing, so a check never silently passes for want of a
library.
"""
from __future__ import annotations


class SigningUnavailable(RuntimeError):
    """A signing operation needs cryptography, which is not installed."""


class SignatureError(RuntimeError):
    """A signature could not be produced, or a key could not be read."""


def available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:                          # pragma: no cover
        raise SigningUnavailable(
            "this needs the cryptography package. Install it with "
            "`pip install cryptography`.") from exc
    return ed25519, serialization


def generate_keypair() -> tuple[bytes, bytes]:
    """A fresh Ed25519 keypair as (private_pem, public_pem)."""
    ed25519, serialization = _ed25519()
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def sign(data: bytes, private_key_pem: bytes) -> tuple[bytes, bytes]:
    """Sign *data*, returning (signature, public_key_pem)."""
    ed25519, serialization = _ed25519()
    try:
        private = serialization.load_pem_private_key(private_key_pem,
                                                     password=None)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"the signing key could not be read: {exc}") from None
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SignatureError("the signing key is not an Ed25519 key")
    signature = private.sign(data)
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return signature, public_pem


def verify(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Whether *signature* is a valid Ed25519 signature of *data* by the key.

    Returns False rather than raising when cryptography is missing or the key or
    signature is malformed: a verification that cannot run has not passed.
    """
    if not available():
        return False
    ed25519, serialization = _ed25519()
    try:
        public = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError):
        return False
    if not isinstance(public, ed25519.Ed25519PublicKey):
        return False
    try:
        public.verify(signature, data)
        return True
    except Exception:                                   # noqa: BLE001
        return False
