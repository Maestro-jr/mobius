"""The MCP server: themob's tools over the Model Context Protocol.

This is the only module that imports the MCP SDK. It wraps the plain functions
in :mod:`themob.mcp.tools` as MCP tools, so an agent drives themob's contained,
reproducible analysis the same way the CLI does. Install the SDK with
``pip install "themob[mcp]"``, then run ``themob mcp`` or ``python -m themob.mcp``.
"""
from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import tools

_INSTRUCTIONS = (
    "themob: authorization-gated mobile attack-surface analysis. The read-only "
    "tools read an existing project. The gated tools (authorize_target, analyze, "
    "scan, record_verdict) append to a hash-chained audit trail; authorize_target "
    "and scan refuse without attested=true, an operator and an engagement, "
    "because decompiling software is authorised only for targets you own or hold "
    "written permission to assess."
)


def build_server(home: str | Path | None = None) -> FastMCP:
    """Build the FastMCP server, bound to one project store (``home``)."""
    mcp = FastMCP("themob", instructions=_INSTRUCTIONS)
    root = tools.resolve_home(home)

    # -- read-only ----------------------------------------------------------

    @mcp.tool()
    def list_projects() -> dict:
        """Every project themob has ingested, newest first, with its gate state."""
        return tools.list_projects(root)

    @mcp.tool()
    def overview(project: str = "") -> dict:
        """The 30-second read of a project: counts, app facts, top findings."""
        return tools.overview(root, project)

    @mcp.tool()
    def corpus(top: int = 50) -> dict:
        """The local corpus across all projects: which weaknesses recur, how
        often they are confirmed or dismissed, and which travel together. Names
        no app; local only."""
        return tools.corpus(root, top)

    @mcp.tool()
    def list_findings(project: str = "", severity: str = "",
                      status: str = "") -> dict:
        """A project's findings, optionally filtered by severity and status."""
        return tools.list_findings(root, project, severity or None,
                                   status or None)

    @mcp.tool()
    def get_finding(fingerprint: str, project: str = "") -> dict:
        """One finding in full: standards, location, evidence, remediation, notes."""
        return tools.get_finding(root, project, fingerprint)

    @mcp.tool()
    def get_section(section: str, project: str = "") -> dict:
        """One tester-facing section (platform, network, secrets, crypto, storage,
        dependencies): its findings and entities."""
        return tools.get_section(root, project, section)

    @mcp.tool()
    def graph(project: str = "", type: str = "", reachable_from: str = "") -> dict:
        """The attack-surface graph: counts by type, one type's entities, or what
        is reachable from an entity id."""
        return tools.graph(root, project, type or None, reachable_from or None)

    @mcp.tool()
    def get_entity(entity: str, project: str = "") -> dict:
        """One node by id or key: its attributes, connectivity and path from the app."""
        return tools.get_entity(root, project, entity)

    @mcp.tool()
    def list_code(project: str = "", filter: str = "", limit: int = 200) -> dict:
        """The decompiled class list (needs a prior analyze so jadx has run)."""
        return tools.list_code(root, project, filter, limit)

    @mcp.tool()
    def read_class(fqcn: str, project: str = "") -> dict:
        """The decompiled source of one class, read from inside the workspace only."""
        return tools.read_class(root, project, fqcn)

    @mcp.tool()
    def list_queries() -> dict:
        """The built-in questions, plus any a tester saved."""
        return tools.list_queries(root)

    @mcp.tool()
    def run_query(key: str, project: str = "") -> dict:
        """Run a built-in or saved query over a project and return its matches."""
        return tools.run_query(root, project, key)

    @mcp.tool()
    def audit(project: str = "", verify: bool = False, limit: int = 100) -> dict:
        """The hash-chained audit trail, optionally for one project, optionally
        with the result of re-walking the chain."""
        return tools.audit(root, project, verify, limit)

    @mcp.tool()
    def list_analyzers() -> dict:
        """The analyzer roster and whether each can run right now."""
        return tools.list_analyzers(root)

    @mcp.tool()
    def doctor() -> dict:
        """A quick environment read: Docker, and what each analyzer needs."""
        return tools.doctor(root)

    # -- gated (attestation + audit) ---------------------------------------

    @mcp.tool()
    def authorize_target(sample_path: str, engagement_ref: str,
                         operator: str = "", name: str = "",
                         scope_note: str = "", attested: bool = False) -> dict:
        """Ingest a sample and record the authorization attestation. Refuses
        unless attested=true with an engagement; decompiling software may be
        authorised only for targets you own or may assess in writing."""
        return tools.authorize_target(root, sample_path, engagement_ref,
                                      operator, name, scope_note, attested)

    @mcp.tool()
    def analyze(project: str = "", stages: list[str] | None = None,
                analyzers: list[str] | None = None) -> dict:
        """Run the analysis pipeline over an already-authorized project. Refuses
        an unauthorized project; needs a running Docker daemon."""
        return tools.analyze(root, project, stages, analyzers)

    @mcp.tool()
    def scan(sample_path: str, engagement_ref: str, operator: str = "",
             name: str = "", scope_note: str = "", out: str = "themob-out",
             attested: bool = False) -> dict:
        """Authorize, analyze and export a report in one gated step. Same gate as
        authorize_target; needs Docker for the pipeline."""
        return tools.scan(root, sample_path, engagement_ref, operator, name,
                          scope_note, out, attested)

    @mcp.tool()
    def record_verdict(fingerprint: str, status: str, project: str = "",
                       note: str = "", operator: str = "") -> dict:
        """Record a tester's verdict on a finding (confirmed, false-positive or
        accepted-risk). The two that suppress a finding need a note."""
        return tools.record_verdict(root, project, fingerprint, status, note,
                                    operator)

    @mcp.tool()
    def rea_prepare(kind: str, target: str, project: str = "",
                    out: str = "rea-handoff") -> dict:
        """Prepare a REA handoff bundle for a native library (kind='native', the
        lib key or entity id) or a decompiled class (kind='class', the fqcn), and
        return the rea command to run. themob does not run REA or reach the
        network; the operator runs it. Gated and audited."""
        from .. import rea
        return rea.prepare(root, project, kind, target, out)

    @mcp.tool()
    def rea_import(fingerprint: str, summary: str, project: str = "",
                   operator: str = "") -> dict:
        """Attach REA's summary to a finding as external reverse-engineering
        evidence: a note marked with its provenance, no severity or status
        change. Gated and audited."""
        from .. import rea
        return rea.import_summary(root, project, fingerprint, summary, operator)

    return mcp


def main(home: str | Path | None = None) -> int:
    """Build the server and serve over stdio until the client disconnects."""
    build_server(home).run()
    return 0
