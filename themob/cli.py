"""``themob``: the whole console, without the window.

The desktop app is one way into themob; this is the other. Every capability the
GUI exposes has a subcommand here, driving the same engine, storage, gate and
audit trail with no PyQt6 imported at all, so themob runs the same on a build
server, over SSH, or on a machine that has never had a display.

The design rules, so the surface stays coherent as it grows:

* **argparse only, one entry point.** No third-party CLI framework; the standard
  library is enough and adds nothing to install. Every subcommand has its own
  ``--help`` and short, memorable flags.
* **the engine is reused, never reimplemented.** A subcommand assembles the same
  ``Pipeline``, ``Repositories`` and ``AuditTrail`` the window does and calls the
  same functions. Where a piece was trapped behind a Qt import (the authorization
  gate), it was lifted into :mod:`themob.orchestrator.authorize`, which both the
  window and this share.
* **the gate is not softened for being headless.** Assessing a binary still
  needs an attestation, executing one still needs the second gate, and testing a
  credential still needs the third. In a terminal that is a confirmation prompt,
  or ``--yes`` for automation; it is never skipped.
* **degrade, do not crash.** A missing tool, no Docker, an unbuilt image: each is
  reported with what to do about it and a clean exit code, never a traceback.
  ``themob doctor`` is the one command whose whole job is to say what is missing.

Output is plain ASCII so it renders in any console, colour is added only when the
stream is a terminal and ``--no-color`` was not given, and every exit code is
chosen so a pipeline step can branch on it.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

from .model.enums import Severity

logger = logging.getLogger(__name__)

# The threshold vocabulary, weakest to strongest, plus "none" (never gate).
_RANK = {
    "none": 99,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


# ===========================================================================
# Terminal: pure-ASCII banner, and colour that turns itself off when it should
# ===========================================================================

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# Semantic, and it stays semantic: critical red, low green, the same ramp the
# GUI uses. A console that recolours risk to match a palette misreports.
_SEVERITY_ANSI = {
    Severity.CRITICAL: "91",     # bright red
    Severity.HIGH: "33",         # amber
    Severity.MEDIUM: "93",       # yellow
    Severity.LOW: "32",          # green
    Severity.INFO: "35",         # violet, the one level with no urgency
}

# Drawn with underscores, pipes and slashes only, so it survives a codepage that
# has no box-drawing characters, which is the Windows console's default.
_BANNER = r"""
   _   _                     _
  | |_| |__   ___ _ __ ___   ___ | |__
  | __| '_ \ / _ \ '_ ` _ \ / _ \| '_ \
  | |_| | | |  __/ | | | | | (_) | |_) |
   \__|_| |_|\___|_| |_| |_|\___/|_.__/
"""


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape handling in the Windows console. False if it will not.

    Modern Windows 10+ consoles support the escapes but do not enable them for a
    process by default. Older ones cannot, and there is no colour to be had, so
    this reports whether it worked and the caller falls back to plain text.
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32           # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)         # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:                                # noqa: BLE001
        return False


class Ink:
    """Wraps text in ANSI colour, or does nothing when colour is off.

    One object per invocation, so nothing decides globally whether the whole
    program is coloured: a command writing machine-readable JSON to a pipe gets
    an :class:`Ink` that is off, the same command in a terminal gets one that is
    on, and neither reaches for a global.
    """

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self.paint("1", text)

    def dim(self, text: str) -> str:
        return self.paint("2", text)

    def accent(self, text: str) -> str:
        return self.paint("35", text)

    def ok(self, text: str) -> str:
        return self.paint("32", text)

    def warn(self, text: str) -> str:
        return self.paint("33", text)

    def error(self, text: str) -> str:
        return self.paint("91", text)

    def severity(self, sev: Severity, text: str | None = None) -> str:
        return self.paint(_SEVERITY_ANSI.get(sev, "0"),
                          text if text is not None else sev.value.title())


def _ink(args: argparse.Namespace, stream=None) -> Ink:
    """The colour policy: off unless a real terminal asked for it.

    ``--no-color`` forces it off; so does the conventional ``NO_COLOR`` variable
    and a stream that is not a TTY (a pipe, a file, a CI log). On Windows the
    escapes are also switched on at the console, and if that fails colour stays
    off rather than printing raw escape codes.
    """
    stream = stream or sys.stdout
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return Ink(False)
    if not hasattr(stream, "isatty") or not stream.isatty():
        return Ink(False)
    if sys.platform == "win32" and not _enable_windows_vt():
        return Ink(False)
    return Ink(True)


def _visible_len(text: str) -> int:
    """Length as printed, not counting the zero-width colour escapes."""
    return len(_ANSI_RE.sub("", text))


def _print_table(headers, rows, ink: Ink, *, stream=None) -> None:
    """A flush, hairline-free ASCII table. Cells may already carry colour.

    Widths are measured on the visible text so a coloured cell still lines up,
    the same reason the GUI computes layout on values rather than on styled
    widgets.
    """
    stream = stream or sys.stdout
    columns = list(zip(*([headers] + rows))) if rows else [(h,) for h in headers]
    widths = [max(_visible_len(str(c)) for c in col) for col in columns]

    def line(cells) -> str:
        out = []
        for cell, width in zip(cells, widths):
            cell = str(cell)
            out.append(cell + " " * (width - _visible_len(cell)))
        return "  ".join(out).rstrip()

    print(ink.dim(line(headers)), file=stream)
    for row in rows:
        print(line(row), file=stream)


def _banner_text(ink: Ink) -> str:
    return (ink.accent(_BANNER.rstrip("\n"))
            + "\n  " + ink.dim("authorization-gated mobile attack-surface "
                               "intelligence") + "\n")


# ===========================================================================
# scan: the whole static assessment, headless, for a pipeline
# ===========================================================================

def _add_scan_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("sample", help="path to the .apk to assess")
    parser.add_argument("--engagement", required=True,
                        help="engagement or ticket reference; this is the "
                             "authorization the assessment is recorded under")
    parser.add_argument("--operator", default="",
                        help="who is running this (defaults to the OS user)")
    parser.add_argument("--out", default="themob-out",
                        help="directory for the report files (default: themob-out)")
    parser.add_argument("--name", default="",
                        help="project name (default: the file stem)")
    parser.add_argument("--fail-on", default="none", choices=sorted(_RANK),
                        help="exit non-zero if a finding reaches this severity "
                             "(default: none)")
    parser.add_argument("--scope-note", default="",
                        help="optional note recorded with the attestation")
    parser.add_argument("--baseline", default="",
                        help="a previous themob JSON report; with it, --fail-on "
                             "counts only findings not present in that baseline, "
                             "so the build gates on newly introduced issues "
                             "rather than inherited debt")
    parser.add_argument("--sign", default="",
                        help="an Ed25519 private key (PEM) to sign the "
                             "deliverable's manifest with, so a recipient can "
                             "verify it was not altered after export")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="themob scan",
        description="Run the static assessment on an APK without the console.")
    return _add_scan_args(parser)


def gate_exit(report, fail_on: str, baseline=None) -> int:
    """0 or 1 by whether a gating finding meets the threshold. Pure.

    With *baseline* (a set of fingerprints from a prior report), only findings
    absent from it count, so the build gates on what this change introduced.
    """
    threshold = _RANK.get(fail_on, 99)
    if threshold >= 99:
        return 0
    for reported in report.reported:
        if baseline is not None and reported.finding.fingerprint in baseline:
            continue
        if _SEVERITY_RANK[reported.finding.severity] >= threshold:
            return 1
    return 0


def scan(args: argparse.Namespace) -> int:
    """Run one headless assessment. Returns the process exit code."""
    from .audit.attestation import (Attestation, AuditTrail, AuthorizationError,
                                     current_operator)
    from .orchestrator import (IntakeError, Pipeline, intake, target_for)
    from .adapters import build_registry
    from .report import export
    from .sandbox.runner import SandboxRunner
    from .storage.db import open_database
    from .storage.repositories import Repositories
    from .storage.workspace import default_root

    operator = args.operator.strip() or current_operator()
    sample = Path(args.sample)
    if not sample.is_file():
        print(f"no such file: {sample}", file=sys.stderr)
        return 2

    print("themob scan")
    print(f"  Running this records an authorization attestation for "
          f"{operator} under {args.engagement}. Only assess software you are "
          "authorised to assess.\n")

    root = default_root()
    database = open_database(root / "themob.db")
    repos = Repositories(database)
    audit = AuditTrail(repos.audit)

    try:
        result = intake(sample, repos, audit, name=args.name, root=root)
    except IntakeError as exc:
        print(f"intake refused the sample: {exc}", file=sys.stderr)
        database.close_all()
        return 2

    try:
        audit.record_attestation(result.project, Attestation(
            target_name=sample.name, target_sha256=result.sha256,
            operator=operator, engagement_ref=args.engagement,
            scope_note=args.scope_note, attested=True), repos.projects)
    except AuthorizationError as exc:
        print(f"authorization failed: {exc}", file=sys.stderr)
        database.close_all()
        return 2

    project = repos.projects.get(result.project.id)
    sandbox = SandboxRunner()
    if not sandbox.is_available():
        print("Docker is not available: the static analyzers run in containers, "
              "so a scan needs a running daemon. Start Docker and retry.",
              file=sys.stderr)
        database.close_all()
        return 2

    pipeline = Pipeline(build_registry(), repos, sandbox, audit)
    try:
        summary = pipeline.run(project, target_for(project, result.workspace),
                               result.workspace)
    except Exception as exc:                            # noqa: BLE001
        logger.exception("scan failed")
        print(f"the scan failed: {exc}", file=sys.stderr)
        database.close_all()
        return 2

    sign_key = None
    if args.sign:
        try:
            sign_key = Path(args.sign).read_bytes()
        except OSError as exc:
            print(f"the signing key could not be read: {exc}", file=sys.stderr)
            database.close_all()
            return 2

    try:
        written = export(repos, audit, project.id, args.out, operator=operator,
                         workspace=result.workspace, sign_key=sign_key)
    except Exception as exc:                            # noqa: BLE001
        # A signing failure (no cryptography, a bad key) should not lose the
        # scan; say what went wrong and stop, rather than half-writing.
        print(f"the report could not be exported: {exc}", file=sys.stderr)
        database.close_all()
        return 2
    report = written.report

    counts = report.counts if report else {}
    ordered = ("critical", "high", "medium", "low", "info")
    tally = ", ".join(f"{counts.get(s, 0)} {s}" for s in ordered)
    print(f"\n{summary.entities} entities, {report.total if report else 0} "
          f"findings ({tally}).")
    for kind, path in sorted(written.files.items()):
        print(f"  {kind}: {path}")

    baseline = None
    if args.baseline:
        from .report import diff

        try:
            baseline = diff.read_baseline_fingerprints(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"the baseline could not be read: {exc}", file=sys.stderr)
            database.close_all()
            return 2
        if report is not None:
            new_findings = diff.new_against_baseline(report, baseline)
            print(f"\n{len(new_findings)} finding(s) not in the baseline "
                  f"{args.baseline}.")

    code = gate_exit(report, args.fail_on, baseline) if report else 0
    if code:
        scope = "new findings" if baseline is not None else "findings"
        print(f"\n{scope.capitalize()} reached the '{args.fail_on}' threshold.",
              file=sys.stderr)
    database.close_all()
    return code


# ===========================================================================
# diff: what changed between two reports
# ===========================================================================

def _add_diff_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("baseline", help="the earlier themob JSON report")
    parser.add_argument("current", help="the later themob JSON report")
    parser.add_argument("--out", default="",
                        help="write the delta as JSON to this path")
    parser.add_argument("--fail-on-new", default="none", choices=sorted(_RANK),
                        help="exit non-zero if a NEW finding reaches this "
                             "severity (default: none)")
    return parser


def build_diff_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="themob diff",
        description="Compare two themob JSON reports and show what changed.")
    return _add_diff_args(parser)


def diff_command(args: argparse.Namespace) -> int:
    from .report import diff

    try:
        delta = diff.compare_files(args.baseline, args.current)
    except (OSError, ValueError) as exc:
        print(f"could not compare: {exc}", file=sys.stderr)
        return 2

    print(diff.render_text(delta))
    if args.out:
        path = diff.write(delta, args.out)
        print(f"\ndelta: {path}")

    threshold = _RANK.get(args.fail_on_new, 99)
    if threshold < 99:
        offending = delta.new_at_or_above(Severity(args.fail_on_new))
        if offending:
            print(f"\n{len(offending)} new finding(s) reached "
                  f"'{args.fail_on_new}'.", file=sys.stderr)
            return 1
    return 0


# ===========================================================================
# verify: a deliverable against its manifest and signature
# ===========================================================================

def _add_verify_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("directory",
                        help="the folder holding the report and manifest.json")
    parser.add_argument("--pubkey", default="",
                        help="a trusted Ed25519 public key (PEM) to check the "
                             "signature against, instead of the one bundled")
    return parser


def build_verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="themob verify",
        description="Check a deliverable against its manifest, and its "
                    "signature if one is present.")
    return _add_verify_args(parser)


def verify_command(args: argparse.Namespace) -> int:
    from .report import manifest, signing

    directory = Path(args.directory)
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        print(f"no manifest.json in {directory}", file=sys.stderr)
        return 2

    result = manifest.verify(manifest_path)

    # If the deliverable carries a signature, check it too. A bundled public key
    # proves internal consistency; a key the recipient supplies proves it came
    # from who they think. Both are reported.
    sig_path = directory / "manifest.sig"
    pub_path = Path(args.pubkey) if args.pubkey else directory / "manifest.pub"
    if sig_path.is_file() and pub_path.is_file():
        result.signed = True
        try:
            doc = manifest.load(manifest_path)
            result.signature_ok = signing.verify(
                doc.signable_bytes(), sig_path.read_bytes(),
                pub_path.read_bytes())
        except Exception as exc:                        # noqa: BLE001
            result.signature_ok = False
            result.problems.append(f"signature could not be checked: {exc}")
        if not result.signature_ok:
            result.ok = False
            if "signature does not verify" not in result.problems:
                result.problems.append("signature does not verify")

    print(result.summary)
    if result.audit_head:
        print(f"audit head at export: {result.audit_head}")
    return 0 if result.ok else 1


# ===========================================================================
# sign-pack: sign a weakness pack so themob will load it as trusted
# ===========================================================================

def _add_sign_pack_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("pack", nargs="?",
                        help="the *-weaknesses.json pack to sign")
    parser.add_argument("--key",
                        help="an Ed25519 private key (PEM) to sign with; "
                             "make one first with --generate-key")
    parser.add_argument("--generate-key", default="", metavar="PATH",
                        help="write a fresh Ed25519 keypair to PATH (private) "
                             "and PATH.pub (public), then exit, instead of "
                             "signing anything")
    return parser


def build_sign_pack_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="themob sign-pack",
        description="Sign a weakness pack so themob can load it as trusted.")
    return _add_sign_pack_args(parser)


def sign_pack_command(args: argparse.Namespace) -> int:
    from . import _signing

    if not _signing.available():
        print("signing needs the cryptography package: pip install cryptography",
              file=sys.stderr)
        return 2

    if args.generate_key:
        try:
            private_pem, public_pem = _signing.generate_keypair()
            priv = Path(args.generate_key)
            priv.write_bytes(private_pem)
            pub = priv.with_suffix(".pub")
            pub.write_bytes(public_pem)
        except OSError as exc:
            print(f"could not write the key: {exc}", file=sys.stderr)
            return 2
        print(f"private key: {priv}")
        print(f"public key:  {pub}")
        print("keep the private key secret; distribute the public key as a "
              "trusted key via THEMOB_KNOWLEDGE_PUBKEYS.")
        return 0

    if not args.pack or not args.key:
        print("sign-pack needs a pack and --key (or --generate-key to make a "
              "key first)", file=sys.stderr)
        return 2

    pack = Path(args.pack)
    if not pack.is_file():
        print(f"no such pack: {pack}", file=sys.stderr)
        return 2
    try:
        private_pem = Path(args.key).read_bytes()
        signature, _public = _signing.sign(pack.read_bytes(), private_pem)
    except (OSError, _signing.SignatureError) as exc:
        print(f"could not sign: {exc}", file=sys.stderr)
        return 2

    sig_path = pack.with_name(pack.name + ".sig")
    sig_path.write_bytes(signature)
    print(f"signature: {sig_path}")
    print("themob will load this pack as trusted when THEMOB_KNOWLEDGE_PUBKEYS "
          "names the matching public key.")
    return 0


# ===========================================================================
# Shared plumbing for the project-scoped commands
# ===========================================================================

def _open(args: argparse.Namespace):
    """Open the themob database this invocation works against.

    ``--home`` overrides where projects live, for automation and tests; without
    it the same default the window uses is honoured (``THEMOB_HOME`` or
    ``~/.themob``). Returns ``(root, database, repos, audit)``; the caller closes
    the database.
    """
    from .audit.attestation import AuditTrail
    from .storage.db import open_database
    from .storage.repositories import Repositories
    from .storage.workspace import default_root

    root = (Path(args.home).expanduser() if getattr(args, "home", None)
            else default_root())
    database = open_database(root / "themob.db")
    repos = Repositories(database)
    return root, database, repos, AuditTrail(repos.audit)


def _resolve_project(repos, token: str):
    """The project a command works on, by id, id-prefix or exact name.

    With no token the most recently created project is used, which is almost
    always the one just worked on. Returns ``(project, error)``: exactly one is
    set, so a caller checks the error and prints it rather than guessing.
    """
    projects = repos.projects.list(limit=500)
    if not projects:
        return None, ("no projects yet. Run 'themob authorize <app>' to ingest "
                      "one, or 'themob scan <app> --engagement ...' to assess it")
    if not token:
        return projects[0], ""
    for project in projects:
        if project.id == token:
            return project, ""
    prefix = [p for p in projects if p.id.startswith(token)]
    named = [p for p in projects if p.name == token]
    if len(prefix) == 1 and not named:
        return prefix[0], ""
    if len(named) == 1 and not prefix:
        return named[0], ""
    if len(prefix) + len(named) > 1:
        return None, (f"{token!r} matches more than one project; use a longer "
                      "id prefix. 'themob projects' lists them")
    if named:
        return named[0], ""
    return None, f"no project matches {token!r}. 'themob projects' lists them"


def _need_project(args, repos, ink: Ink):
    """Resolve ``--project`` or fail with a printed message. Returns the project or None."""
    project, error = _resolve_project(repos, getattr(args, "project", "") or "")
    if project is None:
        print(ink.error(error), file=sys.stderr)
        return None
    return project


def _workspace_for(root, project):
    from .storage.workspace import Workspace

    return Workspace(root, project.id)


def _confirm(prompt: str, args: argparse.Namespace) -> bool:
    """A yes/no the operator answers, or ``--yes`` for automation.

    Without ``--yes`` and without a terminal to ask at, it returns False: an
    unattended run must not silently assume authorization it was never given.
    """
    if getattr(args, "yes", False):
        return True
    if not sys.stdin or not sys.stdin.isatty():
        return False
    try:
        answer = input(f"{prompt} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _severity_arg(value: str):
    try:
        return Severity(value)
    except ValueError:
        return None


# ===========================================================================
# doctor: what is installed, what is missing, and how to fix it
# ===========================================================================

def doctor_command(args: argparse.Namespace) -> int:
    from . import preflight

    ink = _ink(args)
    if not getattr(args, "no_banner", False) and sys.stdout.isatty():
        print(_banner_text(ink), file=sys.stderr)
    return preflight.report()


# ===========================================================================
# projects: what themob has ingested
# ===========================================================================

def projects_command(args: argparse.Namespace) -> int:
    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        projects = repos.projects.list(limit=500)
        if not projects:
            print("no projects yet. Run 'themob authorize <app>' or "
                  "'themob scan <app> --engagement ...'.")
            return 0
        rows = []
        for project in projects:
            auth = (ink.ok("authorized") if project.is_authorized
                    else ink.warn("unauthorized"))
            rows.append([project.id[:12], project.name,
                         project.target_platform.value, auth,
                         project.authorization_ref or "-",
                         project.created_at])
        _print_table(["id", "name", "platform", "gate", "engagement", "created"],
                     rows, ink)
        return 0
    finally:
        database.close_all()


# ===========================================================================
# authorize: ingest a sample and record the attestation, the gate as a command
# ===========================================================================

def authorize_command(args: argparse.Namespace) -> int:
    from .orchestrator.authorize import GateDecision, authorize_target
    from .orchestrator.intake import IntakeError, detect_platform, validate_sample
    from .audit.attestation import AuthorizationError, current_operator

    ink = _ink(args)
    raw = args.sample.strip().strip('"')
    sample = Path(raw).expanduser()
    try:
        sample = validate_sample(sample)
        platform = detect_platform(sample)
    except IntakeError as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2

    operator = args.operator.strip() or current_operator()
    size_mb = sample.stat().st_size / 1024 / 1024
    print(f"{platform.value.upper()}  {sample.name}  {size_mb:,.1f} MB")
    print("themob unpacks and decompiles the app you name to map its attack "
          "surface. Decompiling software you do not own may breach its licence "
          "and, in some jurisdictions, the law.")

    attested = _confirm(
        "Do you own this application, or hold written authorization to assess it?",
        args)
    if not attested:
        if not getattr(args, "yes", False) and not (sys.stdin and sys.stdin.isatty()):
            print(ink.error(
                "authorization was not attested. In a non-interactive run pass "
                "--yes to attest, or run this in a terminal to confirm."),
                file=sys.stderr)
        else:
            print(ink.warn("authorization declined. Nothing was ingested."),
                  file=sys.stderr)
        return 2

    _root, database, repos, audit = _open(args)
    try:
        try:
            result = authorize_target(
                GateDecision(sample_path=sample, project_name=args.name,
                             engagement_ref=args.engagement,
                             scope_note=args.scope_note, attested=True,
                             operator=operator),
                repos, audit, root=_root)
        except IntakeError as exc:
            print(ink.error(f"intake refused the sample: {exc}"), file=sys.stderr)
            return 2
        except AuthorizationError as exc:
            print(ink.error(f"authorization failed: {exc}"), file=sys.stderr)
            return 2

        print(ink.ok(f"authorized. project {result.project.id}"))
        print(f"  workspace: {result.workspace.path}")
        print("  next: 'themob analyze --project "
              f"{result.project.id[:12]}' to run the pipeline.")
        return 0
    finally:
        database.close_all()


# ===========================================================================
# analyze: run the pipeline over an already-authorized project
# ===========================================================================

def _make_emit(ink: Ink, quiet: bool):
    """A pipeline event sink that prints a live log, like the Activity panel."""
    from .orchestrator.events import EventType, LogLevel

    def emit(event) -> None:
        if quiet:
            return
        kind = event.kind
        if kind == EventType.LOG:
            colour = {LogLevel.WARN: ink.warn, LogLevel.ERROR: ink.error,
                      LogLevel.DISCOVERY: ink.accent}.get(event.level, str)
            print("  " + colour(event.text))
        elif kind == EventType.ANALYZER_SKIPPED:
            print("  " + ink.warn(f"{event.analyzer} skipped: {event.text}"))
    return emit


def analyze_command(args: argparse.Namespace) -> int:
    from .adapters import build_registry
    from .audit.attestation import AuthorizationError, require_authorization
    from .model.enums import Stage
    from .orchestrator import IntakeError, Pipeline, target_for
    from .sandbox.runner import SandboxRunner

    ink = _ink(args)
    _root, database, repos, audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        try:
            require_authorization(project)
        except AuthorizationError as exc:
            print(ink.error(f"{exc}"), file=sys.stderr)
            return 2

        stages = None
        if args.stage:
            try:
                stages = [Stage(s) for s in args.stage]
            except ValueError as exc:
                print(ink.error(f"unknown stage: {exc}"), file=sys.stderr)
                return 2

        workspace = _workspace_for(_root, project)
        try:
            target = target_for(project, workspace)
        except IntakeError as exc:
            print(ink.error(f"{exc}"), file=sys.stderr)
            return 2

        sandbox = SandboxRunner()
        if not sandbox.is_available():
            print(ink.error(
                "Docker is not available: the analyzers run in containers, so a "
                "run needs a daemon. Start Docker, then 'themob doctor'."),
                file=sys.stderr)
            return 2

        print(f"analyzing {project.name} ({project.id[:12]})")
        pipeline = Pipeline(build_registry(), repos, sandbox, audit,
                            _make_emit(ink, args.quiet))
        try:
            summary = pipeline.run(project, target, workspace,
                                   stages=stages, analyzers=args.analyzer or None)
        except Exception as exc:                        # noqa: BLE001
            logger.exception("analyze failed")
            print(ink.error(f"the run failed: {exc}"), file=sys.stderr)
            return 2

        print(f"\n{summary.entities} entities, {summary.findings} findings "
              f"in {summary.duration_s:.1f}s ({summary.state.lower()}).")
        for outcome in summary.failed:
            print("  " + ink.error(f"{outcome.analyzer}: {outcome.error}"))
        return _gate_from_findings(repos, project.id, args.fail_on, ink)
    finally:
        database.close_all()


def _gate_from_findings(repos, project_id, fail_on, ink) -> int:
    if _RANK.get(fail_on, 99) >= 99:
        return 0
    from .report import build

    report = build(repos, project_id, None)
    code = gate_exit(report, fail_on)
    if code:
        print("\n" + ink.error(
            f"findings reached the '{fail_on}' threshold."), file=sys.stderr)
    return code


# ===========================================================================
# report: write the deliverable for an existing project
# ===========================================================================

def report_command(args: argparse.Namespace) -> int:
    from .report import export, failed_stages

    ink = _ink(args)
    _root, database, repos, audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2

        sign_key = None
        if args.sign:
            try:
                sign_key = Path(args.sign).read_bytes()
            except OSError as exc:
                print(ink.error(f"the signing key could not be read: {exc}"),
                      file=sys.stderr)
                return 2

        workspace = _workspace_for(_root, project)
        try:
            written = export(repos, audit, project.id, args.out,
                             operator=args.operator or "",
                             stem=args.stem, sarif_report=not args.no_sarif,
                             workspace=workspace, sign_key=sign_key)
        except Exception as exc:                        # noqa: BLE001
            logger.exception("report export failed")
            print(ink.error(f"the report could not be written: {exc}"),
                  file=sys.stderr)
            return 2

        report = written.report
        total = report.total if report else 0
        print(ink.ok(f"report written: {total} findings"
                     + (f", {len(report.suppressed)} dismissed"
                        if report and report.suppressed else "")))
        for kind, path in sorted(written.files.items()):
            print(f"  {kind}: {path}")

        if report is not None:
            for stage in failed_stages(report):
                print("  " + ink.warn(
                    f"{stage.get('analyzer') or stage.get('stage')} did not "
                    "finish; the report says its coverage is incomplete."))
            if not report.provenance.audit_chain_ok:
                print("  " + ink.error(
                    "the audit chain does not verify, and the report says so."))
            if not report.provenance.authorized:
                print("  " + ink.warn(
                    "this project carries no authorization attestation."))
        return 0
    finally:
        database.close_all()


# ===========================================================================
# overview: the 30-second read
# ===========================================================================

def overview_command(args: argparse.Namespace) -> int:
    from .correlate.graph import build_snapshot
    from .model.enums import EntityType

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)
        findings = repos.findings.list(project.id)

        print(ink.bold(project.name) + ink.dim(f"  {project.id[:12]}"))
        print(f"  platform     {project.target_platform.value}")
        print(f"  sha-256      {project.source_sha256}")
        print("  gate         "
              + (ink.ok(project.authorization_ref or "authorized")
                 if project.is_authorized else ink.warn("unauthorized")))

        counts = {s: 0 for s in Severity}
        for finding in findings:
            counts[finding.severity] += 1
        worst = next((s for s in Severity if counts[s]), None)
        print()
        print(f"  entities     {len(snapshot)} "
              f"({snapshot.edge_count} relationships)")
        print(f"  findings     {len(findings)}")
        ramp = "  ".join(
            ink.severity(s, f"{counts[s]} {s.value}") for s in Severity if counts[s])
        if ramp:
            print("  severity     " + ramp)
        if worst is not None:
            print("  highest      " + ink.severity(worst))

        app = next(iter(snapshot.of_type(EntityType.APP)), None)
        if app is not None:
            print("\n  " + ink.dim("application"))
            for key in ("package", "version_name", "min_sdk", "target_sdk"):
                value = app.attributes.get(key)
                if value:
                    print(f"    {key:<12} {value}")
            for flag in ("debuggable", "allow_backup", "uses_cleartext_traffic"):
                value = app.attributes.get(flag)
                if value is True:
                    print("    " + ink.severity(Severity.HIGH, f"{flag}: yes"))

        top = findings[:15]
        if top:
            print("\n  " + ink.dim("top findings"))
            rows = [[ink.severity(f.severity), f"{f.confidence:.0%}", f.title[:60],
                     f.masvs_control or "-"] for f in top]
            _print_table(["severity", "conf", "title", "masvs"], rows, ink)
        return 0
    finally:
        database.close_all()


# ===========================================================================
# section: one tester-facing section (a projection of the graph)
# ===========================================================================

def section_command(args: argparse.Namespace) -> int:
    from .correlate.graph import build_snapshot
    from .correlate.sections import SECTIONS, project as project_sections

    ink = _ink(args)
    known = {s.key for s in SECTIONS}
    if args.section not in known:
        print(ink.error(f"unknown section {args.section!r}. Known: "
                        + ", ".join(sorted(known))), file=sys.stderr)
        return 2

    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)
        findings = repos.findings.list(project.id)
        view = next((v for v in project_sections(snapshot, findings)
                     if v.key == args.section), None)
        if view is None:
            print("nothing in this section.")
            return 0

        print(ink.bold(view.title))
        if view.section.description:
            print(ink.dim("  " + view.section.description))
        if view.findings:
            rows = [[ink.severity(f.severity), f"{f.confidence:.0%}",
                     f.title[:60], f.masvs_control or "-"]
                    for f in _worst_first(view.findings)]
            print("\n  " + ink.dim(f"findings ({len(view.findings)})"))
            _print_table(["severity", "conf", "title", "masvs"], rows, ink)
        else:
            print("\n  " + ink.dim("no findings in this section."))
        if view.entities:
            rows = [[e.type.value, (e.label or e.key)[:70]]
                    for e in view.entities[:200]]
            print("\n  " + ink.dim(f"entities ({len(view.entities)})"))
            _print_table(["type", "name"], rows, ink)
        return 0
    finally:
        database.close_all()


def _worst_first(findings):
    return sorted(findings, key=lambda f: (-_SEVERITY_RANK[f.severity],
                                           -f.confidence, f.title))


# ===========================================================================
# findings / finding: the list, and one in full
# ===========================================================================

def findings_command(args: argparse.Namespace) -> int:
    from .model.enums import FindingStatus

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2

        severity = _severity_arg(args.severity) if args.severity else None
        if args.severity and severity is None:
            print(ink.error(f"unknown severity {args.severity!r}"), file=sys.stderr)
            return 2
        status = None
        if args.status:
            try:
                status = FindingStatus(args.status)
            except ValueError:
                print(ink.error(f"unknown status {args.status!r}"), file=sys.stderr)
                return 2

        findings = repos.findings.list(project.id, severity=severity,
                                       status=status)
        if args.json:
            print(json.dumps([{
                "fingerprint": f.fingerprint, "severity": f.severity.value,
                "confidence": f.confidence, "status": f.status.value,
                "title": f.title, "weakness_key": f.weakness_key,
                "masvs": f.masvs_control} for f in findings], indent=2))
            return 0
        if not findings:
            print("no findings match.")
            return 0
        rows = [[f.fingerprint[:12], ink.severity(f.severity), f"{f.confidence:.0%}",
                 f.status.value, f.title[:56]] for f in findings]
        _print_table(["fingerprint", "severity", "conf", "status", "title"],
                     rows, ink)
        print(ink.dim(f"\n{len(findings)} finding(s)"))
        return 0
    finally:
        database.close_all()


def finding_command(args: argparse.Namespace) -> int:
    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        finding = repos.findings.get_by_fingerprint(project.id, args.fingerprint)
        if finding is None:
            match = [f for f in repos.findings.list(project.id, limit=100000)
                     if f.fingerprint.startswith(args.fingerprint)]
            finding = match[0] if len(match) == 1 else None
        if finding is None:
            print(ink.error(f"no finding {args.fingerprint!r} in this project"),
                  file=sys.stderr)
            return 2

        print(ink.bold(finding.title))
        line = ink.severity(finding.severity) + f"   {finding.confidence:.0%} confidence"
        if finding.risk is not None:
            line += f"   risk {finding.risk:.0f}"
        line += f"   {finding.status.value}"
        print(line)
        if finding.score_rationale:
            print(ink.dim(finding.score_rationale))
        if finding.description:
            print("\n" + finding.description)

        print("\n" + ink.dim("standards"))
        print(f"  weakness   {finding.weakness_key or '-'}")
        print(f"  masvs      {finding.masvs_control or '-'}")
        print(f"  maswe      {finding.maswe_id or 'not mapped'}")
        print(f"  top 10     {finding.mobile_top10 or '-'}")
        print(f"  cwe        {finding.cwe or '-'}")

        if finding.location:
            loc = finding.location
            print("\n" + ink.dim("where"))
            for name, value in (("file", loc.file), ("class", loc.clazz),
                                ("method", loc.method), ("line", loc.line),
                                ("component", loc.component)):
                if value:
                    print(f"  {name:<10} {value}")

        if finding.evidence:
            print("\n" + ink.dim("evidence"))
            for item in finding.evidence[:20]:
                print(f"  {item.value}")

        if finding.remediation:
            print("\n" + ink.dim("remediation"))
            print(f"  {finding.remediation.summary}")

        tools = sorted({s.tool for s in finding.sources})
        if tools:
            print("\n" + ink.dim("reported by") + "  " + ", ".join(tools))

        notes = repos.findings.notes(finding.id)
        if notes:
            print("\n" + ink.dim("notes"))
            for note in notes:
                print(f"  {note.text}  " + ink.dim(f"({note.author} {note.created_at})"))
        return 0
    finally:
        database.close_all()


# ===========================================================================
# verdict: record what a tester concluded about a finding
# ===========================================================================

# CLI verdict word -> FindingStatus value (not the enum member name).
_VERDICT_STATUS = {
    "confirmed": "confirmed",
    "false-positive": "false_positive",
    "accepted-risk": "accepted_risk",
}


def verdict_command(args: argparse.Namespace) -> int:
    from .model.enums import FindingStatus
    from .orchestrator.validation import ValidationError, record
    from .audit.attestation import current_operator

    ink = _ink(args)
    _root, database, repos, audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        finding = repos.findings.get_by_fingerprint(project.id, args.fingerprint)
        if finding is None:
            print(ink.error(f"no finding {args.fingerprint!r} in this project"),
                  file=sys.stderr)
            return 2

        status = FindingStatus(_VERDICT_STATUS[args.status])
        try:
            verdict = record(repos, audit, finding.id, status,
                             operator=args.operator or current_operator(),
                             note=args.note)
        except ValidationError as exc:
            print(ink.error(f"the verdict was refused: {exc}"), file=sys.stderr)
            return 2
        print(ink.ok(f"recorded: {verdict.finding.title} -> {status.value}"))
        return 0
    finally:
        database.close_all()


# ===========================================================================
# graph / entity: the attack-surface graph and one node in it
# ===========================================================================

def graph_command(args: argparse.Namespace) -> int:
    from .correlate.graph import build_snapshot
    from .model.enums import EntityType

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)

        if args.json:
            print(json.dumps({
                "entities": [{"id": e.id, "type": e.type.value, "key": e.key,
                              "label": e.label, "attributes": e.attributes}
                             for e in snapshot.entities],
                "edges": [{"src": e.src_id, "dst": e.dst_id, "type": e.type.value}
                          for e in snapshot.edges]}, indent=2, default=str))
            return 0

        if args.reachable_from:
            reached = snapshot.reachable_from(args.reachable_from)
            rows = []
            for entity_id in sorted(reached):
                entity = snapshot.get(entity_id)
                if entity is not None and entity.id != args.reachable_from:
                    rows.append([entity.type.value, (entity.label or entity.key)[:70]])
            print(ink.dim(f"{len(rows)} entities reachable from {args.reachable_from}"))
            if rows:
                _print_table(["type", "name"], rows, ink)
            return 0

        wanted = None
        if args.type:
            try:
                wanted = EntityType(args.type)
            except ValueError:
                print(ink.error(f"unknown entity type {args.type!r}"),
                      file=sys.stderr)
                return 2

        print(f"{len(snapshot)} entities, {snapshot.edge_count} relationships")
        entities = (snapshot.of_type(wanted) if wanted else snapshot.entities)
        if wanted:
            rows = [[e.id[:12], (e.label or e.key)[:70]] for e in entities[:500]]
            _print_table(["id", "name"], rows, ink)
        else:
            counts = snapshot.counts_by_type()
            rows = [[t.value, str(n)] for t, n in sorted(
                counts.items(), key=lambda kv: -kv[1]) if n]
            _print_table(["type", "count"], rows, ink)
        return 0
    finally:
        database.close_all()


def entity_command(args: argparse.Namespace) -> int:
    from .correlate.graph import build_snapshot

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)
        entity = snapshot.get(args.entity)
        if entity is None:
            entity = next((e for e in snapshot.entities if e.key == args.entity),
                          None)
        if entity is None:
            print(ink.error(f"no entity {args.entity!r} in this project"),
                  file=sys.stderr)
            return 2

        print(ink.bold(entity.label or entity.key))
        print(f"  id           {entity.id}")
        print(f"  type         {entity.type.value}")
        print(f"  key          {entity.key}")
        print(f"  connections  {snapshot.degree(entity.id)}")
        path = snapshot.path_from_root(entity.id)
        if path:
            labels = [(snapshot.get(n).label or snapshot.get(n).key)
                      for n in path if snapshot.get(n) is not None]
            print("  path         " + " -> ".join(labels))
        if entity.attributes:
            print("\n" + ink.dim("attributes"))
            for key, value in sorted(entity.attributes.items()):
                if value not in (None, "", [], {}):
                    print(f"  {key:<16} {str(value)[:200]}")
        return 0
    finally:
        database.close_all()


# ===========================================================================
# code: the decompiled sources
# ===========================================================================

def code_command(args: argparse.Namespace) -> int:
    from .adapters.jadx_decompile import read_class_index
    from .correlate.graph import build_snapshot

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)
        app = snapshot.root
        index_path = app.attributes.get("class_index") if app else None
        if not index_path:
            print("no decompiled sources yet. Run 'themob analyze' so jadx runs.")
            return 0
        workspace = _workspace_for(_root, project)
        index = read_class_index(workspace, str(index_path))
        if not index:
            print("the class index is empty or unreadable.")
            return 0

        if args.open:
            entry = next((e for e in index if e["fqcn"] == args.open), None)
            if entry is None:
                match = [e for e in index if args.open in e["fqcn"]]
                entry = match[0] if len(match) == 1 else None
            if entry is None:
                print(ink.error(f"no class matching {args.open!r}"),
                      file=sys.stderr)
                return 2
            try:
                path = workspace.resolve(entry["path"])
                print(path.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:                    # noqa: BLE001
                print(ink.error(f"could not read the class: {exc}"),
                      file=sys.stderr)
                return 2
            return 0

        needle = (args.filter or "").lower()
        classes = [e for e in index if not needle or needle in e["fqcn"].lower()]
        print(ink.dim(f"{len(classes)} of {len(index)} classes"))
        for entry in classes[:args.limit]:
            print(f"  {entry['fqcn']}")
        if len(classes) > args.limit:
            print(ink.dim(f"  ... {len(classes) - args.limit} more "
                          "(use --filter or raise --limit)"))
        return 0
    finally:
        database.close_all()


# ===========================================================================
# query: the built-in questions, and the ones a tester keeps
# ===========================================================================

def query_command(args: argparse.Namespace) -> int:
    from .correlate import queries as q
    from .correlate.graph import build_snapshot

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        if args.query_action == "list":
            print(ink.dim("built-in"))
            for query in q.BUILTINS:
                print(f"  {query.key:<26} {query.title}")
            saved = repos.queries.list()
            if saved:
                print(ink.dim("\nsaved"))
                for record in saved:
                    print(f"  {record.key:<26} {record.title}")
            return 0

        if args.query_action == "delete":
            if q.builtin(args.key) is not None:
                print(ink.error("a built-in query is not yours to delete"),
                      file=sys.stderr)
                return 2
            repos.queries.delete(args.key)
            print(ink.ok(f"deleted {args.key}"))
            return 0

        if args.query_action == "save":
            source = q.builtin(args.like)
            if source is None:
                print(ink.error(f"no built-in query {args.like!r} to copy"),
                      file=sys.stderr)
                return 2
            from .correlate.queries import Query

            saved = Query(
                key=args.key, title=args.title or source.title,
                description=source.description,
                entity_types=list(source.entity_types),
                attributes=list(source.attributes), exposed=source.exposed,
                severity_at_least=source.severity_at_least,
                has_findings=source.has_findings,
                weakness_prefix=source.weakness_prefix, max_tools=source.max_tools,
                reachable_from=source.reachable_from, limit=source.limit)
            try:
                repos.queries.save(saved)
            except Exception as exc:                    # noqa: BLE001
                print(ink.error(f"{exc}"), file=sys.stderr)
                return 2
            print(ink.ok(f"saved {args.key}"))
            return 0

        # run
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        query = q.builtin(args.key) or repos.queries.load(args.key)
        if query is None:
            print(ink.error(f"no query {args.key!r}. 'themob query list' shows them"),
                  file=sys.stderr)
            return 2
        snapshot = build_snapshot(repos, project.id)
        findings = repos.findings.list(project.id)
        result = q.run(snapshot, findings, query)
        print(ink.dim(query.description))
        print(ink.dim(result.summary) + "\n")
        if not result.matches:
            return 0
        rows = []
        for match in result.matches[:args.limit]:
            worst = match.worst
            rows.append([ink.severity(worst) if worst else "-",
                         (match.entity.label or match.entity.key)[:50],
                         match.entity.type.value, ", ".join(match.reasons)[:40]])
        _print_table(["severity", "entity", "type", "why"], rows, ink)
        return 0
    finally:
        database.close_all()


# ===========================================================================
# audit: the hash-chained trail, and whether it still verifies
# ===========================================================================

def audit_command(args: argparse.Namespace) -> int:
    ink = _ink(args)
    _root, database, repos, audit = _open(args)
    try:
        project = None
        if getattr(args, "project", ""):
            project = _need_project(args, repos, ink)
            if project is None:
                return 2

        if args.verify:
            ok, message = audit.verify_chain()
            mark = ink.ok("OK") if ok else ink.error("BROKEN")
            print(f"{mark}  {message}")
            if not ok:
                return 1

        entries = audit.entries(project.id if project else None, limit=args.limit)
        if not entries:
            print("no audit entries.")
            return 0
        rows = []
        for entry in entries:
            detail = ", ".join(f"{k}={v}" for k, v in entry.detail.items()
                               if not k.startswith("_"))
            rows.append([entry.ts, entry.actor[:24], entry.action, detail[:60]])
        _print_table(["time", "actor", "action", "detail"], rows, ink)
        return 0
    finally:
        database.close_all()


# ===========================================================================
# analyzers: the roster and each one's availability
# ===========================================================================

def analyzers_command(args: argparse.Namespace) -> int:
    from .adapters import build_registry
    from .adapters.base import Availability
    from .sandbox.runner import SandboxRunner

    ink = _ink(args)
    sandbox = SandboxRunner()
    rows = []
    for analyzer in build_registry().all():
        state = analyzer.availability(sandbox)
        painter = ink.ok if state == Availability.READY else ink.warn
        rows.append([analyzer.name, analyzer.stage.value.replace("_", " "),
                     painter(state)])
    _print_table(["analyzer", "stage", "availability"], rows, ink)
    if not sandbox.is_available():
        print(ink.dim("\nDocker is not available; container analyzers show as "
                      "not ready. 'themob doctor' has the detail."))
    return 0


# ===========================================================================
# mcp: serve themob's tools over the Model Context Protocol, on stdio
# ===========================================================================

def mcp_command(args: argparse.Namespace) -> int:
    """Serve themob's tools over the Model Context Protocol, on stdio.

    The server degrades like sign-pack does without its optional dependency: if
    the MCP SDK is not installed it says how to get it and exits, rather than
    with an import traceback.
    """
    try:
        from .mcp.server import main as serve
    except ImportError:
        print('the MCP server needs the MCP SDK: pip install "themob[mcp]"',
              file=sys.stderr)
        return 2
    return serve(getattr(args, "home", "") or None)


# ===========================================================================
# rea: hand a target to REA for deep reverse engineering, then import the result
# ===========================================================================

def rea_command(args: argparse.Namespace) -> int:
    """Prepare a handoff bundle for REA, or import what it reported back.

    themob never runs REA and never reaches the network: prepare writes a bundle
    and prints the command, the operator runs it, and import attaches REA's
    summary to a finding as external evidence. Both are gated and audited.
    """
    from . import rea

    ink = _ink(args)
    home = getattr(args, "home", "") or None
    project = getattr(args, "project", "")

    if args.rea_action == "import":
        summary = args.text
        if not summary and args.file:
            try:
                summary = Path(args.file).read_text(encoding="utf-8",
                                                    errors="replace")
            except OSError as exc:
                print(ink.error(f"could not read {args.file}: {exc}"),
                      file=sys.stderr)
                return 2
        out = rea.import_summary(home, project=project,
                                 fingerprint=args.fingerprint, summary=summary,
                                 operator=args.operator)
        if "error" in out:
            print(ink.error(out["error"]), file=sys.stderr)
            return 2
        print(ink.ok(f"imported REA evidence onto: {out['title']}"))
        return 0

    # prepare
    kind = "native" if args.native else "class"
    target = args.native or args.class_name
    if not target:
        print(ink.error("prepare needs --native <lib> or --class <fqcn>"),
              file=sys.stderr)
        return 2
    out = rea.prepare(home, project=project, kind=kind, target=target,
                      out=args.out)
    if "error" in out:
        print(ink.error(out["error"]), file=sys.stderr)
        return 2
    print(ink.ok(f"bundle: {out['bundle_dir']}"))
    print(f"  file:    {out['file']}")
    print("  run REA yourself (your setup and keys), then import its summary:")
    print("    " + ink.bold(out["command"]))
    print("    themob rea import <fingerprint> --file rea-output.txt")
    return 0


# ===========================================================================
# assist: the AI assistant's licence (status, and issuing for the vendor)
# ===========================================================================

def assist_command(args: argparse.Namespace) -> int:
    """Report the assistant's licence and Claude readiness, and, for the vendor,
    generate a signing keypair and issue licences. The assistant itself is the
    desktop panel; this is the licence setup around it."""
    from . import _signing
    from .assist import core
    from .assist import license as licensing

    ink = _ink(args)
    home = getattr(args, "home", "") or None

    if args.assist_action == "generate-key":
        if not _signing.available():
            print(ink.error("generating a key needs cryptography: "
                            "pip install cryptography"), file=sys.stderr)
            return 2
        try:
            private_pem, public_pem = _signing.generate_keypair()
            priv = Path(args.path)
            priv.write_bytes(private_pem)
            pub = priv.with_suffix(".pub")
            pub.write_bytes(public_pem)
        except OSError as exc:
            print(ink.error(f"could not write the key: {exc}"), file=sys.stderr)
            return 2
        print(ink.ok(f"private key: {priv}"))
        print(f"public key:  {pub}")
        print("keep the private key secret. Put the public key as 'license.pub' "
              "in each install's themob home, or set THEMOB_LICENSE_PUBKEY.")
        return 0

    if args.assist_action == "issue":
        try:
            private_pem = Path(args.key).read_bytes()
            token = licensing.issue(private_pem, args.licensee, args.tier, args.days)
        except Exception as exc:                            # noqa: BLE001
            print(ink.error(f"could not issue the licence: {exc}"), file=sys.stderr)
            return 2
        print(token)
        return 0

    # status
    state = core.status(home)
    if state["enforced"]:
        licensed = (ink.ok("licensed") if state["licensed"]
                    else ink.warn("not licensed"))
        suffix = f"  ({state['licensee']})" if state["licensee"] else ""
        print(f"licence   {licensed}{suffix}")
        if not state["licensed"]:
            print(ink.dim(f"          {state['license_reason']}"))
    else:
        print("licence   " + ink.dim("not enforced"))
    model = ink.ok("ready") if state["llm_ready"] else ink.warn("not ready")
    provider = f"  ({state['provider']})" if state.get("provider") else ""
    print(f"model     {model}{provider}")
    if not state["llm_ready"]:
        print(ink.dim(f"          {state['llm_reason']}"))
    return 0


# ===========================================================================
# dynamic: Phase 3, the console's door into running the app
# ===========================================================================

def intel_command(args: argparse.Namespace) -> int:
    """Show the local corpus across every scan, or preview/write opt-in telemetry.

    'show' is read-only and local. 'export' previews the anonymised payload
    (categories and counts, no app content) and writes it only with --consent.
    """
    ink = _ink(args)
    home = getattr(args, "home", "") or None
    action = getattr(args, "intel_action", "show")

    if action == "export":
        from .intel import telemetry

        if not getattr(args, "consent", False):
            print(json.dumps(telemetry.preview(home), indent=2, sort_keys=True))
            print(ink.warn("\nThis is exactly what would be shared: weakness "
                           "categories and counts, no app names, paths, hashes, "
                           "endpoints or evidence."))
            print("Re-run with --consent --out <file> to write it. Nothing was "
                  "written.")
            return 0
        result = telemetry.export(home, out=args.out, consent=True)
        if not result.ok:
            print(ink.error(result.error), file=sys.stderr)
            return 2
        print(ink.ok(f"wrote anonymised stats for {result.findings} findings "
                     f"to {result.path}"))
        return 0

    from .intel import corpus as corpus_mod

    corpus = corpus_mod.summarize(home)
    if corpus.is_empty:
        print("no findings yet. Authorize and analyze a few apps, then this "
              "shows what recurs across them.")
        return 0
    print(f"{corpus.projects} apps · {corpus.findings} findings "
          f"(as of {corpus.generated_at})")
    print("by severity: " + ", ".join(f"{k} {v}"
                                       for k, v in corpus.by_severity.items()))
    print("by platform: " + ", ".join(f"{k} {v}"
                                       for k, v in corpus.by_platform.items()))
    print("\nmost common weaknesses:")
    for w in corpus.weaknesses[:15]:
        rate = w.false_positive_rate
        fp = f", {round(rate * 100)}% dismissed" if rate is not None else ""
        print(f"  {w.apps:>3} apps  {w.severity:<8} {w.key}  "
              f"({w.occurrences} found, {w.confirmed} confirmed{fp})")
    if corpus.co_occurrence:
        print("\noften found together:")
        for key_a, key_b, shared in corpus.co_occurrence[:10]:
            print(f"  {shared:>3} apps  {key_a}  +  {key_b}")
    return 0


def dynamic_command(args: argparse.Namespace) -> int:
    ink = _ink(args)
    action = args.dynamic_action

    # Listing devices asks adb, not the project store, so it needs neither a
    # project nor an open database.
    if action == "devices":
        return _dynamic_devices(ink)

    _root, database, repos, audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2

        if action == "status":
            return _dynamic_status(repos, project, ink)
        if action == "authorize":
            return _dynamic_authorize(repos, audit, project, args, ink)
        if action == "prepare":
            return _dynamic_prepare(repos, project, args, ink, _root)
        if action in ("import-frida", "import-capture"):
            return _dynamic_import(repos, audit, project, args, ink, action)
        print(ink.error(f"unknown dynamic action {action!r}"), file=sys.stderr)
        return 2
    finally:
        database.close_all()


def _dynamic_devices(ink: Ink) -> int:
    from .dynamic import Adb, AdbError

    adb = Adb()
    if not adb.is_available():
        print(ink.warn("adb is not on PATH. Install the Android platform tools."))
        return 0
    try:
        devices = adb.devices(with_properties=True)
    except AdbError as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    if not devices:
        print("no devices connected.")
        return 0
    rows = [[d.serial, d.state,
             "personal?" if d.looks_like_a_daily_driver else ""] for d in devices]
    _print_table(["serial", "state", "note"], rows, ink)
    return 0


def _dynamic_status(repos, project, ink: Ink) -> int:
    from .dynamic.gate import ExecutionNotAuthorized, require_execution

    try:
        detail = require_execution(repos, project.id)
    except ExecutionNotAuthorized as exc:
        print(ink.warn(f"{exc}"))
        return 0
    scope = ", ".join(detail.get("interception_scope") or []) or "nothing"
    print(ink.ok(f"authorized on {detail.get('device_id')}"))
    print(f"  intercepting: {scope}")
    return 0


def _dynamic_authorize(repos, audit, project, args, ink: Ink) -> int:
    from .dynamic import DeviceAttestation, ExecutionAttestation, gate
    from .dynamic.gate import ExecutionNotAuthorized
    from .audit.attestation import current_operator

    if not args.device:
        print(ink.error("dynamic authorize needs --device (the adb serial)"),
              file=sys.stderr)
        return 2
    if not _confirm(
            f"Is {args.device} a dedicated test device or emulator, not a "
            "personal phone, and is generating live traffic authorized?", args):
        print(ink.error(
            "not attested. Running an app on a personal device, or generating "
            "traffic you are not cleared for, is exactly what this gate exists "
            "to stop. Pass --yes in automation only when both are true."),
            file=sys.stderr)
        return 2
    scope = [h.strip() for h in (args.scope or "").split(",") if h.strip()]
    attestation = ExecutionAttestation(
        operator=args.operator or current_operator(),
        engagement_ref=args.engagement or "",
        device=DeviceAttestation(
            identifier=args.device, dedicated_test_device=True,
            is_emulator=args.device.startswith("emulator-")),
        traffic_authorized=True, interception_scope=scope)
    try:
        gate.authorize(attestation, project.id, audit)
    except ExecutionNotAuthorized as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    print(ink.ok(f"dynamic analysis authorized on {args.device}"))
    print(f"  intercepting: {', '.join(scope) or 'nothing'}")
    return 0


def _dynamic_prepare(repos, project, args, ink: Ink, root) -> int:
    from .dynamic import Instrumentation, capture
    from .dynamic.gate import ExecutionNotAuthorized

    job = args.job or ""
    try:
        if job == "capture":
            workspace = _workspace_for(root, project)
            work = workspace.reports_dir / "capture"
            plan = capture.mitmproxy_capture(repos, project.id, work)
            command, instructions = plan.command, plan.instructions
            description = "mitmproxy capture, scoped to the attestation"
        elif job.startswith("frida:") or job.startswith("objection:"):
            kind, _, name = job.partition(":")
            package = _package_of(repos, project.id)
            instr = Instrumentation()
            if kind == "frida":
                plan = instr.frida_script(repos, project.id, package, name)
            else:
                plan = instr.objection_job(repos, project.id, package, name)
            command, instructions, description = plan.command, [], plan.description
        else:
            print(ink.error(
                "give --job as 'capture', 'frida:<agent.js>' or "
                "'objection:<job>'. 'themob dynamic prepare --help' lists them."),
                file=sys.stderr)
            return 2
    except ExecutionNotAuthorized as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    except Exception as exc:                            # noqa: BLE001
        print(ink.error(f"could not prepare that run: {exc}"), file=sys.stderr)
        return 2

    print(ink.dim(description))
    print("\n  " + ink.bold(" ".join(command) if command else "(no command)"))
    for line in instructions:
        print("  " + line)
    print(ink.dim("\nthemob prepares the command; you run it against the device, "
                  "then 'themob dynamic import-*' merges what it saw."))
    return 0


def _dynamic_import(repos, audit, project, args, ink: Ink, action: str) -> int:
    from .dynamic import capture
    from .dynamic.gate import ExecutionNotAuthorized
    from .dynamic.session import DynamicSession

    path = Path(args.file)
    if not path.is_file():
        print(ink.error(f"no such file: {path}"), file=sys.stderr)
        return 2
    session = DynamicSession(repos, audit)
    try:
        if action == "import-frida":
            text = path.read_text(encoding="utf-8", errors="replace")
            outcome = session.record_frida(project.id, text, raw_ref=str(path))
        else:
            result = capture.read_capture(path)
            outcome = session.record_capture(project.id, result, raw_ref=str(path))
        session.finalize(project.id)
    except ExecutionNotAuthorized as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    if not outcome.ok:
        print(ink.error(f"import failed: {outcome.error}"), file=sys.stderr)
        return 2
    print(ink.ok(f"{outcome.findings} runtime finding(s), "
                 f"{outcome.merged} merged with a static finding."))
    return 0


def _package_of(repos, project_id: str) -> str:
    from .model.enums import EntityType

    for app in repos.entities.list(project_id, EntityType.APP):
        package = app.attributes.get("package")
        if isinstance(package, str) and package:
            return package
    return ""


# ===========================================================================
# handoff: the backend attack surface, out to TOPRECON and back
# ===========================================================================

def handoff_command(args: argparse.Namespace) -> int:
    from .correlate.graph import build_snapshot
    from .handoff import toprecon

    ink = _ink(args)
    _root, database, repos, _audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2
        snapshot = build_snapshot(repos, project.id)

        if args.handoff_action == "export":
            document = toprecon.build(snapshot, project)
            if args.out:
                path = toprecon.write(document, args.out)
                print(ink.ok(f"handoff written: {path}"))
                print(ink.dim(f"  {len(document.seeds)} seed(s), "
                              f"{len(document.candidates)} first-party candidate(s)."))
                print(ink.warn("  scope_domains is empty on purpose: fill it with "
                               "the apexes this engagement authorises."))
            else:
                print(json.dumps(toprecon.to_dict(document), indent=2))
            return 0

        # import
        path = Path(args.file)
        if not path.is_file():
            print(ink.error(f"no such file: {path}"), file=sys.stderr)
            return 2
        report = toprecon.apply(repos, project.id, snapshot, path)
        if not report.ok:
            print(ink.error(report.summary), file=sys.stderr)
            return 2
        print(ink.ok(report.summary))
        return 0
    finally:
        database.close_all()


# ===========================================================================
# validate: test whether a found credential is live, gated on its own
# ===========================================================================

def validate_command(args: argparse.Namespace) -> int:
    ink = _ink(args)
    action = args.validate_action
    _root, database, repos, audit = _open(args)
    try:
        project = _need_project(args, repos, ink)
        if project is None:
            return 2

        if action == "authorize":
            return _validate_authorize(repos, audit, project, args, ink)
        if action == "plan":
            return _validate_plan(repos, project, args, ink)
        if action == "record":
            return _validate_record(repos, audit, project, args, ink)
        print(ink.error(f"unknown validate action {action!r}"), file=sys.stderr)
        return 2
    finally:
        database.close_all()


def _validate_authorize(repos, audit, project, args, ink: Ink) -> int:
    from .validate import ValidationAttestation, ValidationNotAuthorized, authorize
    from .audit.attestation import current_operator

    if not _confirm(
            "Testing a credential contacts the provider that owns it and can "
            "trip an alert on the account under assessment. Is that authorized?",
            args):
        print(ink.error("not acknowledged. Validation stays off for this project."),
              file=sys.stderr)
        return 2
    attestation = ValidationAttestation(
        operator=args.operator or current_operator(),
        engagement_ref=args.engagement or "", acknowledged=True,
        scope_note=args.scope_note or "")
    try:
        authorize(attestation, project.id, audit)
    except ValidationNotAuthorized as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    print(ink.ok("credential validation authorized for this project."))
    return 0


def _validate_plan(repos, project, args, ink: Ink) -> int:
    from .validate import plan
    from .validate.gate import ValidationNotAuthorized

    try:
        tasks = plan(repos, project.id)
    except ValidationNotAuthorized as exc:
        print(ink.warn(f"{exc}"))
        return 0
    if not tasks:
        print("no secret findings to validate.")
        return 0
    print(ink.dim("themob never holds the secret; run each probe with the value "
                  "you read from the cited file.\n"))
    for task in tasks:
        print(ink.bold(f"{task.fingerprint[:12]}  {task.title}"))
        print(f"  provider   {task.provider or 'unknown'}")
        if task.probe:
            print(f"  probe      {task.probe.command}")
            print(ink.dim(f"  live when  {task.probe.live_when}"))
        if task.note:
            print(ink.dim(f"  note       {task.note}"))
    return 0


def _validate_record(repos, audit, project, args, ink: Ink) -> int:
    from .validate import record_result
    from .validate.gate import ValidationNotAuthorized
    from .audit.attestation import current_operator

    finding = repos.findings.get_by_fingerprint(project.id, args.fingerprint)
    if finding is None:
        print(ink.error(f"no finding {args.fingerprint!r} in this project"),
              file=sys.stderr)
        return 2
    live = {"live": True, "dead": False, "inconclusive": None}[args.result]
    try:
        record_result(repos, audit, finding.id, live=live,
                      operator=args.operator or current_operator(),
                      note=args.note or "")
    except ValidationNotAuthorized as exc:
        print(ink.error(f"{exc}"), file=sys.stderr)
        return 2
    print(ink.ok(f"recorded validation result for {finding.title}: {args.result}"))
    return 0


# ===========================================================================
# build-workers: build or list the sandboxed analyzer images
# ===========================================================================

def build_workers_command(args: argparse.Namespace) -> int:
    from .sandbox import build as sandbox_build

    if args.list:
        return sandbox_build.report()
    return sandbox_build.build(args.workers or None)


# ===========================================================================
# gui: open the desktop console
# ===========================================================================

def gui_command(args: argparse.Namespace) -> int:
    try:
        from .app.main import main as launch
    except Exception as exc:                            # noqa: BLE001
        print(f"the desktop console could not start: {exc}\n"
              "It needs PyQt6 and a display. Everything it does is also a "
              "subcommand here; run 'themob --help'.", file=sys.stderr)
        return 2
    return launch([])


# ===========================================================================
# The top-level parser: one command per capability
# ===========================================================================

def build_app_parser() -> argparse.ArgumentParser:
    # Defined on subparsers too, so the flags work in either position
    # ('themob --no-color overview' and 'themob overview --no-color'). SUPPRESS
    # is what makes that safe: without it the subparser's own default would
    # overwrite a value the top-level parser already set before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true",
                        default=argparse.SUPPRESS,
                        help="never colour the output")
    common.add_argument("--home", default=argparse.SUPPRESS,
                        help="the themob home directory to work in "
                             "(default: $THEMOB_HOME or ~/.themob)")

    # SUPPRESS, like the common flags: a nested sub-action (e.g. 'dynamic
    # status') carries --project too, and without SUPPRESS its default would
    # overwrite a --project given before it. Every reader uses _need_project /
    # getattr with a "" fallback, so an absent value still means "most recent".
    projected = argparse.ArgumentParser(add_help=False, parents=[common])
    projected.add_argument("--project", "-p", default=argparse.SUPPRESS,
                           help="project id, id-prefix or name "
                                "(default: the most recent)")

    parser = argparse.ArgumentParser(
        prog="themob",
        description="Authorization-gated mobile attack-surface intelligence, "
                    "the whole console without the window.",
        epilog="Every subcommand has its own --help. 'themob doctor' reports "
               "what is installed and what is missing.")
    parser.add_argument("--no-color", action="store_true",
                        help="never colour the output")
    parser.add_argument("--home", default="",
                        help="the themob home directory to work in "
                             "(default: $THEMOB_HOME or ~/.themob)")
    subs = parser.add_subparsers(dest="command", metavar="<command>")

    # -- assessment lifecycle ------------------------------------------------
    p = subs.add_parser("doctor", parents=[common],
                        help="check deps, tools and config; say what is missing")
    p.add_argument("--no-banner", action="store_true", help="skip the banner")
    p.set_defaults(func=doctor_command)

    p = subs.add_parser("projects", parents=[common],
                        help="list the projects themob has ingested")
    p.set_defaults(func=projects_command)

    p = subs.add_parser("authorize", parents=[common],
                        help="ingest a sample and record the attestation")
    p.add_argument("sample", help="the .apk / .xapk / .ipa to authorize")
    p.add_argument("--engagement", default="",
                   help="engagement or ticket reference")
    p.add_argument("--name", default="", help="project name (default: file stem)")
    p.add_argument("--scope-note", default="", help="note for the attestation")
    p.add_argument("--operator", default="", help="who is attesting")
    p.add_argument("--yes", "-y", action="store_true",
                   help="attest authorization non-interactively (automation)")
    p.set_defaults(func=authorize_command)

    # scan/diff/verify/sign-pack are routed straight to their standalone
    # parsers by __main__, so they carry only their own flags, not the
    # project-store common ones (they take explicit paths, not a --home).
    p = subs.add_parser("scan",
                        help="authorize, analyze and export in one headless step")
    _add_scan_args(p)
    p.set_defaults(func=scan)

    p = subs.add_parser("analyze", parents=[projected],
                        help="run the analyzer pipeline over a project")
    p.add_argument("--stage", action="append", default=[],
                   help="limit to a stage (repeatable), e.g. --stage secrets")
    p.add_argument("--analyzer", action="append", default=[],
                   help="limit to an analyzer (repeatable), e.g. --analyzer jadx")
    p.add_argument("--fail-on", default="none", choices=sorted(_RANK),
                   help="exit non-zero if a finding reaches this severity")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="do not stream the run log")
    p.set_defaults(func=analyze_command)

    p = subs.add_parser("report", parents=[projected],
                        help="write the HTML/JSON/SARIF deliverable and manifest")
    p.add_argument("--out", default="themob-out",
                   help="directory for the report files")
    p.add_argument("--stem", default="themob-report",
                   help="base filename for the report files")
    p.add_argument("--no-sarif", action="store_true",
                   help="skip the SARIF file")
    p.add_argument("--sign", default="",
                   help="an Ed25519 private key (PEM) to sign the manifest with")
    p.add_argument("--operator", default="", help="who exported it, for the trail")
    p.set_defaults(func=report_command)

    # -- reading a project ---------------------------------------------------
    p = subs.add_parser("overview", parents=[projected],
                        help="the 30-second read: risk, entities, top findings")
    p.set_defaults(func=overview_command)

    p = subs.add_parser("section", parents=[projected],
                        help="one tester-facing section of the graph")
    p.add_argument("section", help="platform, network, secrets, crypto, storage, "
                                    "dependencies or code")
    p.set_defaults(func=section_command)

    p = subs.add_parser("findings", parents=[projected],
                        help="list findings, filterable")
    p.add_argument("--severity", default="",
                   help="only this severity (critical/high/medium/low/info)")
    p.add_argument("--status", default="",
                   help="only this status (new/confirmed/false_positive/accepted_risk)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.set_defaults(func=findings_command)

    p = subs.add_parser("finding", parents=[projected],
                        help="one finding in full, by fingerprint (or a prefix)")
    p.add_argument("fingerprint", help="the finding's fingerprint or a prefix")
    p.set_defaults(func=finding_command)

    p = subs.add_parser("verdict", parents=[projected],
                        help="record a tester's verdict on a finding")
    p.add_argument("fingerprint", help="the finding's fingerprint")
    p.add_argument("--status", required=True, choices=sorted(_VERDICT_STATUS),
                   help="the verdict to record")
    p.add_argument("--note", default="",
                   help="the reason (required for false-positive/accepted-risk)")
    p.add_argument("--operator", default="", help="who is deciding")
    p.set_defaults(func=verdict_command)

    p = subs.add_parser("graph", parents=[projected],
                        help="the attack-surface graph: counts, a type, or JSON")
    p.add_argument("--type", default="", help="list entities of this type")
    p.add_argument("--reachable-from", default="",
                   help="list everything reachable from this entity id")
    p.add_argument("--json", action="store_true", help="dump entities and edges")
    p.set_defaults(func=graph_command)

    p = subs.add_parser("entity", parents=[projected],
                        help="inspect one entity and its path from the app")
    p.add_argument("entity", help="the entity id or key")
    p.set_defaults(func=entity_command)

    p = subs.add_parser("code", parents=[projected],
                        help="the decompiled classes: list, filter, or open one")
    p.add_argument("--open", default="", help="print one class by fully-qualified name")
    p.add_argument("--filter", default="", help="only classes matching this text")
    p.add_argument("--limit", type=int, default=100, help="how many to list")
    p.set_defaults(func=code_command)

    p = subs.add_parser("query", parents=[projected],
                        help="the built-in questions, and the ones you keep")
    qsub = p.add_subparsers(dest="query_action", metavar="<action>")
    qsub.add_parser("list", parents=[common], help="list built-in and saved queries")
    qr = qsub.add_parser("run", parents=[projected], help="run a query")
    qr.add_argument("key", help="the query key")
    qr.add_argument("--limit", type=int, default=200, help="max rows")
    qsv = qsub.add_parser("save", parents=[common], help="save a built-in under a new key")
    qsv.add_argument("key", help="the new key")
    qsv.add_argument("--like", required=True, help="the built-in query to copy")
    qsv.add_argument("--title", default="", help="a title for it")
    qd = qsub.add_parser("delete", parents=[common], help="delete a saved query")
    qd.add_argument("key", help="the saved query key")
    p.set_defaults(func=query_command, query_action="list", limit=200)

    p = subs.add_parser("audit", parents=[projected],
                        help="the hash-chained trail, and whether it verifies")
    p.add_argument("--verify", action="store_true", help="verify the hash chain")
    p.add_argument("--limit", type=int, default=100, help="how many entries")
    p.set_defaults(func=audit_command)

    p = subs.add_parser("analyzers", parents=[common],
                        help="the analyzer roster and each one's availability")
    p.set_defaults(func=analyzers_command)

    # -- dynamic (Phase 3) ---------------------------------------------------
    p = subs.add_parser("dynamic", parents=[projected],
                        help="run the app: attest, list devices, prepare, import")
    dsub = p.add_subparsers(dest="dynamic_action", metavar="<action>")
    dsub.add_parser("devices", parents=[common], help="list connected adb devices")
    dsub.add_parser("status", parents=[projected], help="show the execution gate state")
    da = dsub.add_parser("authorize", parents=[projected],
                         help="attest device, traffic and interception scope")
    da.add_argument("--device", required=True, help="the adb serial")
    da.add_argument("--scope", default="",
                    help="hosts to intercept, comma separated; .example.com covers "
                         "subdomains")
    da.add_argument("--engagement", default="", help="engagement reference")
    da.add_argument("--operator", default="", help="who is attesting")
    da.add_argument("--yes", "-y", action="store_true",
                    help="attest the device and traffic clauses non-interactively")
    dp = dsub.add_parser("prepare", parents=[projected],
                         help="prepare a run command for the device")
    dp.add_argument("--job", required=True,
                    help="'capture', 'frida:<agent.js>' or 'objection:<job>'")
    di = dsub.add_parser("import-frida", parents=[projected],
                         help="merge a Frida agent's output onto the graph")
    di.add_argument("file", help="the Frida output to import")
    dc = dsub.add_parser("import-capture", parents=[projected],
                         help="merge a mitmproxy capture log onto the graph")
    dc.add_argument("file", help="the capture .jsonl to import")
    p.set_defaults(func=dynamic_command, dynamic_action="status")

    # -- handoff and validation ----------------------------------------------
    p = subs.add_parser("handoff", parents=[projected],
                        help="the backend surface, out to TOPRECON and back")
    hsub = p.add_subparsers(dest="handoff_action", metavar="<action>")
    he = hsub.add_parser("export", parents=[projected],
                         help="export the endpoint/cloud subgraph")
    he.add_argument("--out", default="", help="write JSON here (default: stdout)")
    hi = hsub.add_parser("import", parents=[projected],
                         help="fold TOPRECON's results back onto the endpoints")
    hi.add_argument("file", help="the TOPRECON export to import")
    p.set_defaults(func=handoff_command, handoff_action="export", out="")

    p = subs.add_parser("validate", parents=[projected],
                        help="test whether a found credential is live (gated)")
    vsub = p.add_subparsers(dest="validate_action", metavar="<action>")
    va = vsub.add_parser("authorize", parents=[projected],
                         help="acknowledge that probing credentials is authorized")
    va.add_argument("--engagement", default="", help="engagement reference")
    va.add_argument("--scope-note", default="", help="note for the attestation")
    va.add_argument("--operator", default="", help="who is attesting")
    va.add_argument("--yes", "-y", action="store_true",
                    help="acknowledge non-interactively (automation)")
    vsub.add_parser("plan", parents=[projected],
                    help="prepare a read-only probe for each secret finding")
    vr = vsub.add_parser("record", parents=[projected],
                         help="record what a probe found, as a verdict")
    vr.add_argument("fingerprint", help="the finding's fingerprint")
    vr.add_argument("--result", required=True,
                    choices=["live", "dead", "inconclusive"],
                    help="what the probe found")
    vr.add_argument("--note", default="", help="detail for the trail")
    vr.add_argument("--operator", default="", help="who ran the probe")
    p.set_defaults(func=validate_command, validate_action="plan")

    # -- maintenance ---------------------------------------------------------
    p = subs.add_parser("sign-pack",
                        help="sign a weakness pack so themob loads it as trusted")
    _add_sign_pack_args(p)
    p.set_defaults(func=sign_pack_command)

    p = subs.add_parser("diff",
                        help="compare two JSON reports and show what changed")
    _add_diff_args(p)
    p.set_defaults(func=diff_command)

    p = subs.add_parser("verify",
                        help="check a deliverable against its manifest/signature")
    _add_verify_args(p)
    p.set_defaults(func=verify_command)

    p = subs.add_parser("build-workers", parents=[common],
                        help="build or list the sandboxed analyzer images")
    p.add_argument("workers", nargs="*", help="worker names to build (default: all)")
    p.add_argument("--list", action="store_true",
                   help="list images and whether they are built")
    p.set_defaults(func=build_workers_command)

    p = subs.add_parser("gui", parents=[common], help="open the desktop console")
    p.set_defaults(func=gui_command)

    p = subs.add_parser("mcp", parents=[common],
                        help="serve themob's tools over the Model Context "
                             "Protocol (stdio), for an agent")
    p.set_defaults(func=mcp_command)

    p = subs.add_parser("rea", parents=[projected],
                        help="hand a native lib or class to REA for deep reverse "
                             "engineering, then import its result")
    rsub = p.add_subparsers(dest="rea_action", metavar="<action>")
    rp = rsub.add_parser("prepare", parents=[projected],
                         help="prepare a handoff bundle and print the rea command")
    rp.add_argument("--native", default="",
                    help="a native library by key or entity id (lib/<abi>/<name>.so)")
    rp.add_argument("--class", dest="class_name", default="",
                    help="a decompiled class by its fully-qualified name")
    rp.add_argument("--out", default="rea-handoff",
                    help="directory for the bundle (default: rea-handoff)")
    ri = rsub.add_parser("import", parents=[projected],
                         help="attach REA's summary to a finding as evidence")
    ri.add_argument("fingerprint", help="the finding's fingerprint (or a prefix)")
    ri.add_argument("--file", default="", help="a file holding REA's output")
    ri.add_argument("--text", default="", help="REA's summary inline")
    ri.add_argument("--operator", default="", help="who ran REA")
    p.set_defaults(func=rea_command, rea_action="prepare", native="",
                   class_name="", out="rea-handoff")

    p = subs.add_parser("assist", parents=[common],
                        help="the AI assistant: licence status, and issuing "
                             "licences (vendor)")
    asub = p.add_subparsers(dest="assist_action", metavar="<action>")
    asub.add_parser("status", parents=[common],
                    help="show licence and Claude readiness")
    ag = asub.add_parser("generate-key", parents=[common],
                         help="generate a licence signing keypair (vendor)")
    ag.add_argument("path", help="where to write the private key "
                                 "(its .pub is written beside it)")
    ai = asub.add_parser("issue", parents=[common],
                         help="mint a licence token (vendor)")
    ai.add_argument("--key", required=True,
                    help="the private key (PEM) to sign the licence with")
    ai.add_argument("--licensee", required=True, help="who the licence is for")
    ai.add_argument("--tier", default="standard", help="licence tier")
    ai.add_argument("--days", type=int, default=365, help="days until expiry")
    p.set_defaults(func=assist_command, assist_action="status")

    p = subs.add_parser("intel", parents=[common],
                        help="local intelligence across your scans: the corpus, "
                             "and opt-in anonymised telemetry")
    isub = p.add_subparsers(dest="intel_action", metavar="<action>")
    isub.add_parser("show", parents=[common],
                    help="the local corpus: recurring weaknesses, verdicts, "
                         "co-occurrence (read-only, local)")
    ie = isub.add_parser("export", parents=[common],
                         help="preview the anonymised telemetry; --consent writes it")
    ie.add_argument("--consent", action="store_true",
                    help="opt in and actually write the anonymised payload")
    ie.add_argument("--out", default="themob-telemetry.json",
                    help="file to write when --consent is given")
    p.set_defaults(func=intel_command, intel_action="show")

    return parser


def run(argv: list[str] | None = None) -> int:
    """The single dispatcher: parse a subcommand and run it.

    ``python -m themob`` routes the machine-facing subcommands here directly so
    their entry points stay stable; everything else, and ``--help``, comes
    through this, which is why every subcommand carries its own handler.
    """
    logging.basicConfig(level=os.environ.get("THEMOB_LOG_LEVEL", "WARNING").upper(),
                        format="%(levelname)s %(name)s: %(message)s")
    parser = build_app_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        if sys.stdout.isatty():
            print(_banner_text(_ink(args)), file=sys.stderr)
        parser.print_help()
        return 0
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:                             # piped into head, etc.
        return 0


# ===========================================================================
# Entry points kept stable for `python -m themob` and the test suite
# ===========================================================================

def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level="WARNING",
        format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    return scan(args)


def diff_main(argv: list[str] | None = None) -> int:
    return diff_command(build_diff_parser().parse_args(argv))


def verify_main(argv: list[str] | None = None) -> int:
    return verify_command(build_verify_parser().parse_args(argv))


def sign_pack_main(argv: list[str] | None = None) -> int:
    return sign_pack_command(build_sign_pack_parser().parse_args(argv))


if __name__ == "__main__":                                # pragma: no cover
    sys.exit(run())
