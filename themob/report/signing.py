"""Optional Ed25519 signatures over a manifest.

The manifest (:mod:`themob.report.manifest`) is tamper-evident on its own: a
recipient recomputes the file hashes and catches an edit. A signature adds the
other half, authorship: proof the manifest was produced by whoever holds the
private key, so an attacker cannot recompute the hashes for altered files and
present a clean-looking manifest.

The Ed25519 primitives live in :mod:`themob._signing`, shared with the rule-pack
loader so neither package imports the other. This module keeps only the piece
that is about a manifest specifically: writing the signature and public key
beside it.
"""
from __future__ import annotations

from pathlib import Path

from .._signing import (SignatureError, SigningUnavailable, available,
                        generate_keypair, sign, verify)

__all__ = ["SignatureError", "SigningUnavailable", "available",
           "generate_keypair", "sign", "verify", "sign_manifest"]


def sign_manifest(manifest, out_dir: str | Path,
                  private_key_pem: bytes) -> dict[str, Path]:
    """Sign a manifest and write the signature and public key beside it."""
    directory = Path(out_dir)
    signature, public_pem = sign(manifest.signable_bytes(), private_key_pem)
    sig_path = directory / "manifest.sig"
    pub_path = directory / "manifest.pub"
    sig_path.write_bytes(signature)
    pub_path.write_bytes(public_pem)
    return {"signature": sig_path, "public_key": pub_path}
