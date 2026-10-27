"""The canonical weakness catalogue: the identities findings are keyed by.

The data lives in ``knowledge/*-weaknesses.json`` at the repository root, which
is where the build plan's §13 puts "MASVS/MASWE/MobileTop10 maps, semgrep rule
packs": alongside ``workers/`` and ``shared/``, not inside the engine. This
module is the loader and the validator for those packs.

Why the catalogue exists at all: a finding's fingerprint is built from the
canonical weakness identity, never from a tool's own rule name::

    Finding.compute_fingerprint(weakness_key, location, evidence)

If the config auditor keyed on ``"debuggable"`` and MobSF later keyed on
``"android_debuggable"``, the two would never collide, cross-tool voting would
never fire, and the same issue would be reported twice with half the confidence
it deserves.

What the packs deliberately leave null: **MASWE ids**, rather than guessed ones.
MASVS controls, Mobile Top 10 categories and CWE ids all map. The MAS Weakness
Enumeration ids could not be verified against the OWASP source, and a wrong
standards reference in a pentest report is worse than a missing one. The field
travels through the loader, the report renders it as "not mapped", and the
preflight warns about it, so filling it here needs no code change.

Severity in a pack is the *default*, the starting point before context.
``scoring/`` adjusts it for reachability and exploitability. Nothing downstream
should assume the default survived.

Loading fails loudly. A security tool that silently runs with half its checks
because a rule pack was malformed is worse than one that refuses to start.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..model.enums import MASVSCategory, Severity


def _locate_packs() -> Path:
    """Where the weakness packs live, checkout or installed.

    Same convention as sandbox/build.py's WORKERS_DIR: the packs sit at the
    repository root beside workers/ and shared/, which is where the build plan's
    section 13 puts them. That path does not exist in an installed copy, so a
    wheel carries them under the environment's ``share/themob/`` instead and
    they are found there when the checkout is not present.

    ``THEMOB_KNOWLEDGE_DIR`` overrides both, for running against an edited pack
    without touching the installation.
    """
    override = os.environ.get("THEMOB_KNOWLEDGE_DIR")
    if override:
        return Path(override).expanduser()

    checkout = Path(__file__).resolve().parent.parent.parent / "knowledge"
    if checkout.is_dir():
        return checkout
    return Path(sys.prefix) / "share" / "themob" / "knowledge"


KNOWLEDGE_DIR = _locate_packs()

_PACK_GLOB = "*-weaknesses.json"
_REQUIRED = ("key", "title", "severity", "masvs_category", "masvs_control",
             "description", "remediation")


class WeaknessPackError(RuntimeError):
    """A rule pack is missing or malformed."""


@dataclass(frozen=True)
class Weakness:
    """One canonical weakness: what it is, and how to talk about it."""

    key: str                                    # themob's stable identity
    title: str
    severity: Severity                          # default, pre-context
    masvs_category: MASVSCategory
    masvs_control: str
    description: str
    remediation: str
    cwe: str | None = None
    maswe_id: str | None = None                 # null until verified upstream
    mobile_top10: str | None = None             # OWASP Mobile Top 10 (2024)
    references: tuple[str, ...] = field(default_factory=tuple)


def _text(value: object, field_name: str, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WeaknessPackError(
            f"weakness {key!r}: {field_name} must be a non-empty string")
    return value


def _optional(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _weakness(doc: object, source: Path) -> Weakness:
    if not isinstance(doc, dict):
        raise WeaknessPackError(f"{source.name}: every weakness must be an object")

    key = doc.get("key")
    if not isinstance(key, str) or not key.strip():
        raise WeaknessPackError(f"{source.name}: a weakness is missing its key")

    missing = [f for f in _REQUIRED if not doc.get(f)]
    if missing:
        raise WeaknessPackError(
            f"weakness {key!r} in {source.name} is missing: {', '.join(missing)}")

    try:
        severity = Severity(doc["severity"])
    except ValueError:
        raise WeaknessPackError(
            f"weakness {key!r}: {doc['severity']!r} is not a severity") from None
    try:
        category = MASVSCategory(doc["masvs_category"])
    except ValueError:
        raise WeaknessPackError(
            f"weakness {key!r}: {doc['masvs_category']!r} is not a MASVS "
            "category") from None

    references = doc.get("references") or []
    if not isinstance(references, list):
        raise WeaknessPackError(f"weakness {key!r}: references must be a list")

    return Weakness(
        key=key,
        title=_text(doc["title"], "title", key),
        severity=severity,
        masvs_category=category,
        masvs_control=_text(doc["masvs_control"], "masvs_control", key),
        description=_text(doc["description"], "description", key),
        remediation=_text(doc["remediation"], "remediation", key),
        cwe=_optional(doc.get("cwe")),
        maswe_id=_optional(doc.get("maswe_id")),
        mobile_top10=_optional(doc.get("mobile_top10")),
        references=tuple(r for r in references if isinstance(r, str)),
    )


def _read_pack(pack: Path, found: dict[str, Weakness]) -> dict[str, Weakness]:
    """Parse and validate one pack, refusing duplicates against *found*."""
    try:
        document = json.loads(pack.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WeaknessPackError(f"{pack.name} could not be read: {exc}") from None
    if not isinstance(document, dict):
        raise WeaknessPackError(f"{pack.name}: expected a JSON object")

    entries = document.get("weaknesses")
    if not isinstance(entries, list):
        raise WeaknessPackError(f"{pack.name}: 'weaknesses' must be a list")

    weaknesses = [_weakness(entry, pack) for entry in entries]

    # A duplicate key is a silent voting failure, two adapters that meant the
    # same weakness quietly stop merging, so it is refused rather than letting
    # the later entry win. This is also what stops an extra pack from
    # overriding a built-in weakness by re-declaring its key.
    duplicates = sorted(k for k, n in Counter(w.key for w in weaknesses).items()
                        if n > 1)
    if duplicates:
        raise WeaknessPackError(
            f"{pack.name}: duplicate weakness keys: {', '.join(duplicates)}")
    clashes = sorted(set(found) & {w.key for w in weaknesses})
    if clashes:
        raise WeaknessPackError(
            f"{pack.name}: keys already defined by another pack: "
            f"{', '.join(clashes)}")
    return {w.key: w for w in weaknesses}


def load(directory: Path | None = None) -> dict[str, Weakness]:
    """Read every built-in weakness pack, plus any signed extra packs.

    When *directory* is given, only that directory is read and its packs are
    treated as trusted: that is the form the tests and a caller pointing at a
    specific pack set use. With no argument, the built-in packs load from
    :data:`KNOWLEDGE_DIR` (trusted, they ship with the code) and each configured
    extra directory is loaded under the signing policy in :func:`_load_extra`.
    """
    _WARNINGS.clear()
    base = directory or KNOWLEDGE_DIR
    packs = sorted(base.glob(_PACK_GLOB)) if base.is_dir() else []
    if not packs:
        raise WeaknessPackError(
            f"no weakness packs found in {base}. Themob cannot key findings "
            "without them; expected at least one file matching " + _PACK_GLOB)

    found: dict[str, Weakness] = {}
    for pack in packs:
        found.update(_read_pack(pack, found))

    if directory is None:
        _load_extra(found)
    return found


def _load_extra(found: dict[str, Weakness]) -> None:
    """Load extra packs from the configured directories, under the sign policy.

    An extra pack is third-party rules dropped in without rebuilding themob, so
    it is not trusted the way the shipped packs are. In strict mode an extra
    pack must carry a signature that verifies against a configured trusted key,
    or it is skipped with a warning: a security tool must not silently load
    rules that could change a severity or a canonical key. Outside strict mode
    an unsigned pack loads, but the warning still says it was unverified, so the
    provenance is never hidden.
    """
    trusted = _trusted_keys()
    strict = _strict()
    for pack in _extra_packs():
        verified = _verify_pack(pack, trusted)
        if strict and not verified:
            _WARNINGS.append(f"skipped unverified extra pack {pack.name} "
                             "(strict mode requires a trusted signature)")
            continue
        if not verified:
            _WARNINGS.append(f"loaded {pack.name} unverified: it carries no "
                             "signature from a trusted key")
        try:
            found.update(_read_pack(pack, found))
        except WeaknessPackError as exc:
            _WARNINGS.append(f"skipped {pack.name}: {exc}")


def _extra_dirs() -> list[Path]:
    raw = os.environ.get("THEMOB_KNOWLEDGE_EXTRA", "")
    dirs = [Path(part).expanduser() for part in raw.split(os.pathsep) if part.strip()]
    return [d for d in dirs if d.is_dir()]


def _extra_packs() -> list[Path]:
    packs: list[Path] = []
    for directory in _extra_dirs():
        packs.extend(sorted(directory.glob(_PACK_GLOB)))
    return packs


def _trusted_keys() -> list[bytes]:
    raw = os.environ.get("THEMOB_KNOWLEDGE_PUBKEYS", "")
    keys: list[bytes] = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        try:
            keys.append(Path(part).expanduser().read_bytes())
        except OSError:
            continue
    return keys


def _strict() -> bool:
    return os.environ.get("THEMOB_KNOWLEDGE_STRICT", "").strip().lower() in (
        "1", "true", "yes", "on")


def _verify_pack(pack: Path, trusted: list[bytes]) -> bool:
    """Whether *pack* carries a ``.sig`` that verifies against a trusted key."""
    signature = pack.with_name(pack.name + ".sig")
    if not signature.is_file() or not trusted:
        return False
    from .._signing import verify

    try:
        data = pack.read_bytes()
        sig = signature.read_bytes()
    except OSError:
        return False
    return any(verify(data, sig, key) for key in trusted)


# Provenance notes from the last load: extra packs that were unsigned or
# skipped. Surfaced by the preflight so an operator knows what rules ran.
_WARNINGS: list[str] = []


def warnings() -> list[str]:
    """What the last load could not fully vouch for. Empty in the common case."""
    return list(_WARNINGS)


_CATALOGUE: dict[str, Weakness] = load()


def catalogue() -> dict[str, Weakness]:
    """Every known weakness, keyed by its canonical id."""
    return dict(_CATALOGUE)


def keys() -> frozenset[str]:
    return frozenset(_CATALOGUE)


def get(key: str) -> Weakness:
    """Look up a weakness, failing loudly on an unknown key.

    Deliberately not forgiving. An adapter emitting a key that is not in a pack
    is a bug that would otherwise surface as an unmapped finding with no
    severity and no standards reference, weeks later, in a report.
    """
    try:
        return _CATALOGUE[key]
    except KeyError:
        raise KeyError(
            f"unknown weakness key {key!r}: add it to a pack in "
            f"{KNOWLEDGE_DIR.name}/ before emitting findings for it") from None
