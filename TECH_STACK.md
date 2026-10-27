# themob: technology stack

What themob is built from, and the one boundary that explains most of it. This
reflects the repository as of 2026-10-11; the authoritative sources are
[README.md](README.md), [PROGRESS.md](PROGRESS.md), `pyproject.toml`, and the
`TOPMOBILE-build-plan.md` design. A planned expansion (reverse engineering and an
MCP server) is listed last and is clearly marked as not yet built.

## The one rule that shapes the stack

Every third-party tool is invoked **arms-length**: a subprocess, a REST call, or
a container, never a library import. That single boundary is both the
containment boundary (hostile input never runs in themob's own process) and the
licensing boundary (a GPL tool stays a separate program). Read the rest of this
document with that in mind: almost nothing below is a Python dependency; most of
it is a program themob drives and reads the output of.

## Language and runtime

| Area | Choice | Note |
|---|---|---|
| Language | Python, `>=3.11` | tested on 3.11 and 3.12 |
| License | GPL-3.0-or-later | PyQt6 is GPL, so themob is. PySide6 (LGPL) is the escape hatch if it must ever ship closed; nothing outside `themob/app/` imports Qt |
| Distribution | `pyproject.toml` (setuptools), console script `themob` -> `themob.__main__:main`, plus `themob.sh` / `themob.cmd` launchers | `python -m themob` from a checkout is the same entry point |

## Core libraries (the only real Python dependencies)

| Library | Version | Used for |
|---|---|---|
| PyQt6 | `>=6.6` | the desktop shell: frameless window, QSS theme, sidebar + `QStackedWidget`, the `QGraphicsView` attack-surface graph, a `QSyntaxHighlighter` code browser, work on a background `QThread` |
| pydantic | `>=2.6` | the fixed data model: `Entity`, `Edge`, `Finding`, and the enums |
| networkx | `>=3.2` | the graph read model: entry points, directed reachability, sections |
| cryptography | `>=42` (optional, `themob[sign]`) | Ed25519 signatures on the report manifest and on extra rule packs |
| sqlite3 | standard library | the project store (schema in `storage/migrations/*.sql`) |
| argparse | standard library | the whole CLI, with ANSI colour gated by TTY / `--no-color` / `NO_COLOR` and VT enabled on Windows |
| pytest, pytest-qt | `>=8`, `>=4.4` (dev) | the test suite, including offscreen Qt |

## Package layout (what runs the engine)

```
themob/
  app/            PyQt6 shell: theme, sidebar, panels, the graph widget
  model/          Pydantic v2: Entity, Edge, Finding, enums
  storage/        SQLite schema + migrations, repositories, per-project workspace
  orchestrator/   intake, the staged pipeline, its event stream   (no Qt)
  adapters/       one per tool: the Analyzer interface + registry
  sandbox/        the Docker runner and the worker-image builder
  normalize/      canonical weakness keys, dedup, method-aware cross-tool voting
  correlate/      the attack-surface graph, entry points, exposure, sections
  dataflow/       does a flagged value reach a sink   (a text heuristic, and says so)
  scoring/        severity from reachability, confidence from agreement, risk
  handoff/        the endpoint subgraph, out to TOPRECON and back
  dynamic/        Phase 3: the execution gate, adb, Frida/objection, mitmproxy capture
  report/         HTML, JSON, SARIF export, and version diffing   (no Qt import)
  validate/       the secret-validation gate and read-only probe planning
  audit/          attestation + the append-only, hash-chained audit trail
  knowledge/      the loader for the weakness packs
  cli.py          headless subcommands; __main__.py; preflight.py (--check)
workers/          a Dockerfile per sandboxed tool, or a pinned upstream digest
knowledge/        weakness packs: canonical keys + MASVS / Mobile Top 10 / CWE mapping
```

## The sandbox

Disposable Docker containers run every parser. Each one gets `--network none`, a
read-only root filesystem, the sample mounted read-only, all capabilities
dropped, an unprivileged uid, and hard CPU / memory / pid / time limits. There is
**no host fallback**: if Docker is unavailable, an analyzer is skipped, never run
locally. Worker images are built locally from `workers/<tool>/`, and any upstream
image a worker pulls (MobSF) is pinned by digest, not a moving tag. `python -m
themob --check` reports which images are built without starting one.

## The analysis tools (arms-length)

| Tool | Stage | How it runs | What it gives |
|---|---|---|---|
| androguard | unpack | container | App / Component / Permission entities |
| apktool (pinned 2.11.1) | unpack | container | decoded resources and the plain-text manifest |
| jadx (pinned 1.5.3) | reverse engineering | container | decompiled Java and a class index |
| nativelib (themob's own) | reverse engineering | container | ELF `.so` hardening: NX, PIE, RELRO, stack canary, stripped |
| gitleaks | secrets | container | secrets in the decoded tree |
| apkleaks | secrets | container | endpoint and secret patterns |
| semgrep | SAST | container | pattern and semantic findings from rule packs (`knowledge/semgrep/*.yml`) |
| syft -> grype | dependencies | container | an SBOM, then advisory matches against it |
| MobSF (pinned image) | second opinion | REST, own container, own network | a second scanner's JSON, merged by canonical key, never vendored |
| config / manifest auditor | config | in-process, no container | judges the graph the unpackers built (does not re-open attacker XML in the engine) |
| endpoint extractor | endpoints | in-process, no container | endpoints pulled from the decoded evidence (apkleaks on Android, ios-unpack's URL list on iOS) |
| ios-unpack (themob's own) | unpack | container | decodes the `.ipa`, reads the Info.plist, frameworks and the Mach-O's hardening with **lief**, parses the provisioning-profile entitlements, scans the bundle for URLs |
| Mach-O hardening auditor | reverse engineering | in-process, no container | turns the Mach-O hardening flags ios-unpack read (PIE, stack canary, ARC, NX, signature, FairPlay) into findings |
| iOS Info.plist / entitlements auditor | config | in-process, no container | ATS, hijackable URL schemes, file sharing, get-task-allow, over-broad entitlements |

On iOS the tool roster is the same engine with iOS-specific unpack and audit
stages: `gitleaks` and `syft` already scan the decoded bundle (ios-unpack writes
it to the artifacts tree), `apkleaks` stays Android-only by design (it is an APK
tool), and its URL-extraction role is filled by ios-unpack. **lief** (Apache-2.0)
runs only inside the ios-unpack container, never imported into the engine, the
same arms-length rule the other tools keep.

Downstream of the tools, themob does the thinking the tools do not: `normalize`
keys every finding to a **canonical weakness id** (a MASWE or internal id, never a
tool's own rule name) and runs method-aware cross-tool voting; `correlate` builds
one graph and marks a finding externally reachable only when a directed path runs
from an exported entry point to it; `dataflow` reads the decompiled Java to say
whether a flagged value actually reaches a sink (a co-mention heuristic, declared
as such, adjusting confidence not severity); `scoring` sets severity, confidence
and risk.

## Dynamic analysis (Phase 3, built and unit-tested, live paths await a device)

| Tool | Role | Constraint |
|---|---|---|
| adb | drive one device | bound to a single attested serial; `root` / `remount` refused by name |
| Frida + objection | instrument | loads only agents shipped in `dynamic/agents/*.js`; they observe, they do not alter, and they emit lengths and algorithm names, never key bytes |
| mitmproxy | intercept TLS | decrypts only hosts in the attested scope (`dynamic/addons/*.py`); everything else relayed untouched |

Whatever any of it observes becomes an ordinary finding on the same graph, merged
by fingerprint with the static finding that suspected it.

## Standards and knowledge

- **OWASP MASVS**, the **Mobile Top 10**, and **CWE** are mapped on every weakness;
  MASWE ids exist as a field but are not yet filled (named as a known gap).
- The weakness catalogue is **data, not code**: `knowledge/*-weaknesses.json`. A
  team can add packs through `THEMOB_KNOWLEDGE_EXTRA`; with strict mode an extra
  pack loads only if Ed25519-signed by a trusted key, because a pack sets a
  finding's severity and key.

## Reporting and interchange

- **HTML**, self-contained with no external fonts, scripts or images, so it still
  renders years later offline.
- **JSON** for diffing, and **SARIF 2.1.0** carrying each finding's stable
  fingerprint and a `security-severity`, so code-scanning tools track a triaged
  issue instead of re-reporting it.
- **`manifest.json`**: the SHA-256 of each deliverable, a digest of the raw
  evidence, and the tip of the audit chain at export; `themob verify` recomputes
  them. `--sign` adds an Ed25519 signature on top.
- **`themob diff`** compares two reports by fingerprint, so "the same finding" is
  exact, not a fuzzy text match.

## Integrity and authorization

- Every run is refused unless the operator attests authorization, and the attested
  SHA-256 must match the ingested sample.
- The audit log is append-only: the database rejects `UPDATE` and `DELETE`, and
  each entry hash-chains to the previous one, so an out-of-band edit is
  detectable. The trail outlives the projects it describes.
- A verdict (confirm, false positive, accepted risk) is itself an audited event,
  and the two that remove a finding demand a reason.

## Testing and CI

- Hermetic suite: no Docker, no network, no device, offscreen Qt, around 1,031
  tests. A `docker`-marked end-to-end suite builds a real APK and runs the real
  workers in real containers.
- GitHub Actions runs the hermetic suite on 3.11 and 3.12, a typography gate
  (`tools/check_typography.py`, which enforces the no-em-dash / no-fancy-glyph
  rule for every contributor), a clean-environment wheel install proving the
  report and dynamic-findings paths import without Qt, and a pinned gitleaks scan.

## Sibling integration

`handoff` exports the backend-endpoint subgraph to **TOPRECON** (themob's sibling
attack-surface tool) and folds its results back in, keyed the same way.

---

## MCP tool server (built)

themob exposes its capabilities over the Model Context Protocol, so an agent
(REA, Claude, or themob's own assistant) can drive the same contained,
reproducible tools the CLI and the window use. The capabilities live in
`themob/mcp/tools.py` as plain functions that import neither the MCP SDK nor Qt;
`themob/mcp/server.py` wraps each as a FastMCP tool, and `themob mcp` /
`python -m themob.mcp` serve them over stdio. 18 tools: read-only reads
(projects, overview, findings, section, graph, entity, code, queries, audit,
analyzers, doctor) and gated ones (authorize_target, analyze, scan,
record_verdict). The gate is not softened for an agent: the gated tools refuse
without an attestation and an engagement and append to the hash-chained audit
trail, and `analyze` refuses an unauthorized project. The MCP SDK is an optional
extra (`pip install "themob[mcp]"`); only the server module imports it.

## REA reverse-engineering handoff (built)

themob does the deterministic slice of reverse engineering: decompile, scan, read
`.so` hardening flags. It does **not** reverse the logic inside a native binary or
an obfuscated class. [REA](https://github.com/morluto/rea) does, with LLM agents,
which is non-deterministic and reaches the network, so it sits beside the pipeline,
not in it. `themob/rea.py` is the handoff: `prepare` resolves a chosen native
library or decompiled class to its file in the workspace, bundles it with themob's
context, and returns the exact `rea` command; the operator runs REA with their own
keys; `import_summary` attaches REA's result as a note on a finding, marked
external, changing no severity or status. themob never imports `rea-agents` and
never reaches the network. Exposed as `themob rea prepare` / `import` and the
`rea_prepare` / `rea_import` MCP tools, both gated and audited. This unlocks
reversing native logic `nativelib` currently only measures the armour of (custom
crypto, root/jailbreak checks, anti-Frida, cert-pinning), and it already serves
the iOS Mach-O: `prepare --native` resolves and bundles an `.ipa`'s main binary,
the native-binary case REA exists for.

## AI assistant (built)

The contest-facing product: a licensed surface on top of the deterministic
engine, in `themob/assist/`. It reads the real findings through the MCP tool
layer in-process, asks Claude (the `anthropic` SDK, optional `themob[assist]`
extra, the operator's own key) to explain each finding in plain language and
coach the fix, and never shows anything themob did not find, enforced in both the
briefing and the system prompt. The gate is an Ed25519-signed licence key
(reusing themob's signing layer), verified against a trusted public key the
operator configures; without it the assistant refuses. The surface is the
Assistant page in the violet console, running the call off the UI thread;
`themob assist` is the licence tooling. See `CONTEST_PITCH.md` for the product
framing.
