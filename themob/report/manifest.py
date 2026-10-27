"""A tamper-evident manifest for the deliverable.

A report is a document somebody may have to defend in a dispute, and "here is
the PDF" is a weak answer when the other side asks whether it was edited after
the fact. themob already hash-chains its own audit trail; this extends that
property to the files that leave the tool.

The manifest is a plain JSON file listing every file in the deliverable with its
SHA-256, plus a digest of the raw evidence and the tip of the audit chain. It
gives three checks, in increasing strength:

* **checksums**: recompute the hash of each report file and compare. Any edit to
  the HTML, JSON or SARIF changes a hash, so a silent change is caught.
* **the evidence digest**: a single hash over every raw tool output, so tampering
  with the evidence a finding cites is detectable even when the evidence is not
  shipped alongside the report.
* **the audit head**: the hash at the tip of the immutable trail at export time,
  which ties the deliverable to the chain without shipping the chain.

Signing (:mod:`themob.report.signing`) is the optional cryptographic layer on
top: a detached signature over this manifest's bytes lets a third party verify
authorship with a public key. Without a key the manifest still stands on its
checksums, which is tamper-evidence, not tamper-proofing, and the difference is
stated rather than blurred.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

FORMAT = "themob.manifest/1"

# A hostile package can decompile to an enormous tree. The manifest hashes files,
# so it needs the same ceilings the rest of the pipeline uses.
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_FILES = 20_000


@dataclass
class FileEntry:
    path: str                             # relative to the manifest's directory
    sha256: str
    bytes: int


@dataclass
class Manifest:
    """What the deliverable contains, and what it was tied to."""

    format: str = FORMAT
    package: str = ""
    sample_sha256: str = ""
    generated_at: str = ""
    themob_version: str = ""
    audit_head: str = ""
    audit_chain_ok: bool = True
    files: list[FileEntry] = field(default_factory=list)
    evidence_digest: str = ""
    evidence_count: int = 0

    def signable_bytes(self) -> bytes:
        """The exact bytes a signature covers. Canonical, so it is reproducible."""
        return canonical_bytes(to_dict(self))


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                digest.update(chunk)
                break
            digest.update(chunk)
    return digest.hexdigest(), total


def _evidence_digest(raw_root: Path) -> tuple[str, int]:
    """One hash over every raw tool output, plus the count.

    A hash of "relative path : file hash" lines, sorted, so the digest is stable
    across runs and any change to any evidence file changes it. The files
    themselves are not copied into the manifest: this proves what the evidence
    was without bloating the deliverable with it.
    """
    if not raw_root.is_dir():
        return "", 0
    lines: list[str] = []
    for path in sorted(raw_root.rglob("*")):
        if not path.is_file():
            continue
        if len(lines) >= _MAX_FILES:
            break
        try:
            file_hash, _size = sha256_file(path)
        except OSError:
            continue
        rel = path.relative_to(raw_root).as_posix()
        lines.append(f"{rel}:{file_hash}")
    if not lines:
        return "", 0
    combined = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    return combined, len(lines)


def build(report, report_dir: str | Path, *, raw_root: Path | None = None,
          audit=None, files: list[str] | None = None) -> Manifest:
    """Assemble the manifest for a deliverable already written to *report_dir*.

    *files* names the report files to cover (relative to *report_dir*); when
    omitted, every file already in the directory is covered, which is what an
    export wants.
    """
    directory = Path(report_dir)
    provenance = report.provenance

    covered: list[Path]
    if files is not None:
        covered = [directory / name for name in files]
    else:
        covered = sorted(p for p in directory.rglob("*")
                         if p.is_file() and p.name != "manifest.json"
                         and not p.name.startswith("manifest."))

    entries: list[FileEntry] = []
    for path in covered:
        if not path.is_file():
            continue
        file_hash, size = sha256_file(path)
        entries.append(FileEntry(
            path=path.relative_to(directory).as_posix(),
            sha256=file_hash, bytes=size))

    evidence_digest, evidence_count = ("", 0)
    if raw_root is not None:
        evidence_digest, evidence_count = _evidence_digest(raw_root)

    chain_ok = True
    head = ""
    if audit is not None:
        head = audit.head()
        chain_ok, _message = audit.verify_chain()

    return Manifest(
        package=provenance.package,
        sample_sha256=provenance.sha256,
        generated_at=provenance.generated_at,
        themob_version=provenance.themob_version,
        audit_head=head,
        audit_chain_ok=chain_ok,
        files=sorted(entries, key=lambda e: e.path),
        evidence_digest=evidence_digest,
        evidence_count=evidence_count,
    )


def to_dict(manifest: Manifest) -> dict[str, Any]:
    return asdict(manifest)


def canonical_bytes(document: dict[str, Any]) -> bytes:
    """Sorted, compact JSON: the same manifest always serialises the same way."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def write(manifest: Manifest, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(to_dict(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return target


# ------------------------------------------------------------------- verifying

@dataclass
class VerifyResult:
    """The outcome of checking a deliverable against its manifest."""

    ok: bool = False
    checked: int = 0
    problems: list[str] = field(default_factory=list)
    signed: bool = False
    signature_ok: bool | None = None      # None when there was no signature
    audit_head: str = ""

    @property
    def summary(self) -> str:
        if not self.ok:
            return "TAMPERED: " + "; ".join(self.problems[:5])
        signature = ("signature verified" if self.signature_ok
                     else "checksums verified, no signature")
        return f"intact ({self.checked} file(s) checked, {signature})"


def load(manifest_path: str | Path) -> Manifest:
    document = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise ValueError("not a themob manifest")
    files = [FileEntry(path=str(f.get("path")), sha256=str(f.get("sha256")),
                       bytes=int(f.get("bytes") or 0))
             for f in document.get("files") or [] if isinstance(f, dict)]
    document["files"] = files
    known = {k: document.get(k) for k in Manifest.__dataclass_fields__
             if k in document}
    known["files"] = files
    return Manifest(**known)


def verify(manifest_path: str | Path) -> VerifyResult:
    """Recompute every file's hash and compare it to the manifest.

    The audit chain is not re-verified here: it lives in the database, not the
    deliverable, so the manifest records its head as a reference rather than
    something a recipient can re-walk. What a recipient can check, the files,
    is checked in full.
    """
    path = Path(manifest_path)
    directory = path.parent
    try:
        manifest = load(path)
    except (OSError, ValueError) as exc:
        return VerifyResult(ok=False, problems=[f"the manifest is unreadable: {exc}"])

    result = VerifyResult(audit_head=manifest.audit_head)
    for entry in manifest.files:
        target = directory / entry.path
        if not target.is_file():
            result.problems.append(f"missing: {entry.path}")
            continue
        actual, size = sha256_file(target)
        result.checked += 1
        if actual != entry.sha256:
            result.problems.append(f"changed: {entry.path}")
        elif size != entry.bytes:
            result.problems.append(f"size mismatch: {entry.path}")

    result.ok = not result.problems
    return result
