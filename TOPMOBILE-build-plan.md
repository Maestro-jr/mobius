# TOPMOBILE — Build Plan

An authorization-gated **mobile attack-surface intelligence engine**: a desktop
app that ingests an APK/IPA, runs a staged analysis pipeline, correlates
everything into one attack-surface graph, maps findings to OWASP MASVS/MASWE,
scores severity and confidence, and produces prioritized, actionable remediation
— all in one place, so a tester never has to leave the tool.

> Working name: **TOPMOBILE** (placeholder — rename freely).
> Sibling to TOPRECON: same DNA (authorized targets, entity-driven pivots, full
> audit trail), applied to a binary instead of a domain.

---

## 1. Product definition and scope

**What it is:** a pentester's console that *also* gives the automated overview.
You said "both, leaning pentester" — so the automated pipeline produces the
first-pass report, but the tester can then drill into any stage, re-run
individual analyzers, validate findings by hand, collect evidence, and (later)
drive dynamic testing. It is interactive and re-runnable, not a fire-and-forget
report generator.

**The core interaction (your vision, made concrete):**
Upload APK/IPA → automated pipeline runs → **overview dashboard** (risk summary,
entity counts, top findings, the graph) → tester navigates **sections that map
to testing stages** (Reverse Engineering, Storage, Network & API, Crypto,
Platform/IPC, Dependencies/SDKs, Secrets, Dynamic/Runtime) → each section shows
that stage's findings + artifacts + the relevant slice of the graph → drill down
to a single finding with full evidence and a manual-validation workflow.

**What it is NOT (v1):** not a new decompiler, not a new SAST engine, not a
malware sandbox, not a device farm. It orchestrates best-of-breed tools and adds
the intelligence layer on top.

**MVP boundary:** Android, static analysis, single-machine, local. Dynamic
analysis and iOS are explicitly later phases (Section 11).

---

## 2. Guiding architectural decisions (with tradeoffs)

Each decision states the tradeoff in one line, per how you like to work.

1. **Orchestrator + adapters, not a monolith.** Wrap existing tools behind a
   uniform adapter interface. *Tradeoff:* you inherit N tools' quirks and update
   cadence, but you get breadth you could never build solo and you focus your
   effort on the correlation layer that's actually novel.
2. **One attack-surface graph; sections are projections of it.** *Tradeoff:* more
   upfront data-model design, but every "section" and every pivot becomes a query
   instead of a bespoke feature.
3. **Sandboxed analysis workers (containers).** Untrusted binaries are parsed in
   disposable, network-less Docker workers. *Tradeoff:* Docker is a heavy
   dependency and adds IPC, but it contains malicious-input exploits AND keeps
   copyleft tools at arms length (Section 6/9).
4. **Android-first, static-first.** *Tradeoff:* you ship less on day one, but iOS
   and dynamic analysis each carry infra costs that would sink a v1.
5. **Local-first, thin local service.** A Python engine runs as a localhost
   service behind a desktop shell. *Tradeoff:* not a single binary, but it keeps
   the analysis in Python (where all the tooling lives) and the UI in web tech
   (where the graph/dashboard lives).
6. **Arms-length tool integration (subprocess/REST), never library import.**
   *Tradeoff:* serialization overhead per call, but it is both the sandbox
   boundary and the licensing firewall (GPL tools stay separate processes).

---

## 3. System architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                         DESKTOP SHELL (Tauri/Electron)                  │
│   React + TypeScript UI:  Overview · Sections · Graph · Code · Report   │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ localhost HTTP + WebSocket (job events)
┌───────────────────────────────▼───────────────────────────────────────┐
│                     ANALYSIS ENGINE  (Python / FastAPI)                 │
│                                                                         │
│  Intake ─► Orchestrator (job queue, pipeline DAG)                       │
│                 │                                                       │
│                 ├─► Adapter layer ──► dispatches jobs to sandboxed      │
│                 │                     workers, collects raw output      │
│                 │                                                       │
│                 ├─► Normalizer  (raw tool output → common Finding)      │
│                 ├─► Deduper/Voter (merge findings, confidence)          │
│                 ├─► Correlator  (build entities + edges → the graph)    │
│                 ├─► Scorer/Mapper (severity, MASVS/MASWE/MobileTop10)   │
│                 └─► Reporter                                            │
│                                                                         │
│  Storage: SQLite (findings, entities, edges, jobs, audit)              │
│           Filesystem workspace (decompiled code, extracted artifacts)  │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ spawn (read-only mount, no network)
┌───────────────────────────────▼───────────────────────────────────────┐
│                 SANDBOXED WORKERS  (Docker containers)                  │
│  Static:  androguard · apktool · jadx · Ghidra(headless) · semgrep ·   │
│           MobSF(REST) · gitleaks · osv-scanner/grype · apkleaks        │
│  Dynamic (phase 3, separate isolated net): ADB · Frida · objection ·   │
│           mitmproxy · mobilewright/Appium ──► Emulator / test device   │
└───────────────────────────────────────────────────────────────────────┘
```

Data flows one direction through the pipeline; every stage emits **entities and
findings** into the graph. The UI reads the graph and findings; it never talks to
tools directly.

---

## 4. The core data model — the mobile attack-surface graph

This is the heart of the system and the thing that makes TOPRECON's model
translate. Everything is an **entity**; findings attach to entities; **typed
edges** connect them; sections and pivots are queries over this graph.

**Entity types**

| Entity | Examples / fields |
| --- | --- |
| App | package name, version, min/target SDK, signing cert, hashes |
| Component | Activity / Service / Receiver / Provider; exported flag; permissions |
| Permission | name, protection level, requested vs used |
| DeepLink / URLScheme | scheme, host, path patterns, autoVerify |
| Endpoint | scheme, host, port, path; REST / GraphQL / WebSocket |
| CloudAsset | Firebase project, S3/GCS bucket, API gateway |
| Secret | type (API key/token/cred), value fingerprint, provider, live? |
| Library / SDK | name, version, category (analytics/payments/ads/auth), CVEs |
| NativeLib | .so / framework, arch, protections (PIE/stack canary/RELRO) |
| CryptoUsage | algorithm, mode, key source, call site |
| StorageSink | SharedPreferences / SQLite / Keychain / file / log / clipboard |
| Finding | (see schema below) — always linked to ≥1 entity |

**Edge types:** `declares`, `exports`, `requests-permission`, `calls`,
`talks-to`, `embeds`, `uses`, `stores-in`, `evidences`, `resolves-to`.

**Why this matters:** the "Network & API" section is `entities WHERE type IN
(Endpoint, CloudAsset)` plus their edges; "Reverse Engineering" is the code map;
a pivot is "show every entity reachable from this exported Provider." One model,
many views — and it hands off to TOPRECON by exporting the `Endpoint`/`CloudAsset`
subgraph.

### The Finding schema (get this right first — everything depends on it)

You emphasized this, and it's correct: the finding object is what turns scanners
into an assessment platform. Every analyzer normalizes to this shape.

```jsonc
{
  "id": "uuid",
  "fingerprint": "sha256(rule + location + normalized-evidence)", // for dedup
  "title": "Hardcoded credential material",
  "description": "...",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0,                 // 0–1, boosted when tools agree (voting)
  "requires_manual_validation": true,
  "status": "new|confirmed|false_positive|accepted_risk", // tester workflow
  "masvs_control": "MASVS-STORAGE-1",
  "maswe_id": "MASWE-XXXX",
  "mobile_top10": "M1",
  "cwe": "CWE-798",
  "location": { "file": "...", "class": "...", "method": "...", "line": 0,
                "component": "..." },
  "evidence": [ { "type": "snippet|artifact|screenshot|http", "value": "..." } ],
  "entity_refs": [ "entity-id", "..." ],   // links into the graph
  "data_flow": [ /* source -> sink steps, when available */ ],
  "sources": [ "semgrep:rule-x", "mobsf:check-y" ], // which tools reported it
  "remediation": { "summary": "...", "steps": [], "references": [] }
}
```

**Voting/confidence rule (the VulsTotal insight generalized):** dedup by
`fingerprint`; when multiple independent tools report the same fingerprint, raise
confidence and record all `sources`. A finding reported by three tools is more
trustworthy than one reported by a single noisy scanner. This de-noising layer is
your core value-add — SAST tools individually are false-positive machines.

---

## 5. The analysis pipeline (stages = the tester's sections)

A directed pipeline; each stage is independently re-runnable (pentester
requirement) and emits entities + findings.

| # | Stage | Input | Key tools | Emits |
| --- | --- | --- | --- | --- |
| 0 | **Intake & authorization** | APK/IPA | hashing, signature check | App entity, authorization record, audit entry |
| 1 | **Unpack & inventory** | binary | apktool, androguard (Android); unzip + plist + Mach-O parse (iOS) | Components, Permissions, files, NativeLibs, entitlements |
| 2 | **Reverse engineering** | DEX / native | jadx (DEX→Java), Ghidra headless (.so/Mach-O) | Code map, CryptoUsage, WebView/JS-bridge sites, StorageSinks |
| 3 | **Secrets & sensitive data** | code + resources | gitleaks, apkleaks, semgrep secret rules | Secret entities (with usage context) |
| 4 | **SAST / insecure patterns** | code | semgrep (mobile rulesets), MobSF static, optional VulsTotal roster | Findings |
| 5 | **Dependencies / SBOM** | libs / manifests | syft→grype, osv-scanner | Library/SDK entities, CVE findings |
| 6 | **Config & platform audit** | manifest / entitlements | custom parsers | Findings: debuggable, allowBackup, cleartext, exported comps, network-security-config |
| 7 | **API & endpoint recon** | extracted strings/code | extractors + **TOPRECON handoff** | Endpoint, CloudAsset entities |
| 8 | **Dynamic (phase 3, optional)** | running app | ADB, Frida, objection, mitmproxy, mobilewright | Runtime findings: real storage, SSL-pin status, live traffic |
| 9 | **Correlate, score, map, report** | the graph | internal | Scored findings, MASVS/MASWE map, report |

Stage 7 is your differentiator: extract the backend attack surface from the app
and feed those endpoints straight into TOPRECON's web-recon engine. Nothing else
in the market closes that loop.

---

## 6. Tool integration strategy (adapters + licensing)

**The adapter interface.** Every tool implements the same contract:

```python
class Analyzer(Protocol):
    name: str
    stage: Stage
    def applies_to(self, target: Target) -> bool: ...
    def run(self, target: Target, workspace: Path) -> RawResult: ...   # in sandbox
    def normalize(self, raw: RawResult) -> list[Finding]: ...          # to schema
```

Adding a tool = writing one adapter. This is what keeps the system extensible and
lets you (or the community, later) plug in new scanners without touching the core.

**Licensing — decide before you bundle anything.** This is the most-overlooked
part of wrapping OSS security tools, and it's legally consequential. Verify each
tool's *current* license yourself before shipping; my directional read:

| Tool | License (verify) | Integration rule |
| --- | --- | --- |
| MobSF | GPL (copyleft) | **REST/subprocess only** — never import as a library, or your app inherits GPL |
| jadx, apktool, Ghidra | Apache-2.0 (permissive) | safe to invoke; still run in sandbox |
| androguard | permissive (verify) | can import, but arms-length is safer for sandboxing |
| semgrep | LGPL core; some rules/features commercial | OK to invoke; check ruleset terms |
| Frida | permissive-ish (verify) | subprocess |
| gitleaks | MIT | safe. Prefer over AGPL secret scanners |
| osv-scanner / syft / grype | Apache-2.0 | safe |
| Burp Suite | **commercial** | **cannot bundle.** Ship mitmproxy as default; let users attach their own Burp |

**The rule that solves both problems at once:** integrate every third-party tool
as an **arms-length subprocess or REST call inside a sandbox**. That single
decision gives you (a) protection from malicious-binary exploits, and (b) a clean
licensing boundary for copyleft tools. It's why decision #3 and #6 in Section 2
are the same decision.

---

## 7. Tech stack (with rationale)

| Layer | Choice | Why |
| --- | --- | --- |
| Analysis engine | **Python 3.11+, FastAPI** | every mobile tool (androguard, MobSF, Frida bindings, semgrep) lives in Python/CLI; FastAPI gives a clean local API |
| Job orchestration | lightweight task table + `asyncio` workers (add Celery/Redis only if you outgrow it) | boring, proven, no premature infra |
| Storage | **SQLite** (findings/entities/edges/jobs/audit) + filesystem workspace for artifacts | local-first, zero-config, transactional; graph stored as node/edge tables, loaded into NetworkX in-memory for pivots |
| Sandboxing | **Docker** workers, read-only mount, `--network none`, CPU/mem/time limits | contains hostile input and copyleft tools |
| Frontend | **React + TypeScript**, Radix/shadcn, **Cytoscape.js** for the graph, **Monaco** for decompiled code, virtualized lists for large finding sets | you already used Cytoscape.js for HiveDefend's topology — same competence, same graph problem |
| Desktop shell | **Tauri** (recommended) or Electron | Tauri = small, security-focused binary (fitting for a security tool); Electron = more mature/simpler if you'd rather not add Rust |
| Packaging | platform installers; bundle a JRE (jadx/apktool/Ghidra need Java); require or bundle Docker; download Ghidra on first run (it's large) | manage install weight deliberately |

**Stack tradeoff to decide:** Tauri (Rust shell) + Python sidecar + React is three
languages. If you'd rather stay closer to your HiveDefend stack, **PySide6 +
QWebEngine** (all-Python, embed the Cytoscape graph in a web view) is viable and
removes the Rust/JS split — at the cost of a less rich UI toolkit. Pick based on
how much you want to invest in the frontend.

---

## 8. UX / information architecture

Built directly around your "overview → sections by testing stage" vision.

- **Overview:** risk score, severity histogram, entity counts, top findings, and
  a zoomed-out attack-surface graph. The 30-second read.
- **Left-nav sections (each a projection of the graph + that stage's findings):**
  Reverse Engineering (code browser + crypto/WebView sites) · Storage · Network &
  API (endpoints, cloud assets, TOPRECON handoff button) · Cryptography · Platform
  & IPC (components, deep links, exported surface) · Dependencies & SDKs · Secrets
  · Dynamic/Runtime (phase 3).
- **Finding detail:** the full schema rendered — evidence, location (click through
  to the exact decompiled line in Monaco), MASVS/MASWE mapping, remediation,
  confidence, `sources`, and a **manual-validation workflow** (confirm / mark
  false-positive / accept risk, add notes and evidence). This confirm/annotate
  loop is what makes it a console instead of a report.
- **Graph view:** the full interactive attack-surface graph with pivots — select
  an entity, expand its neighbors, filter by type. This is the TOPRECON
  experience, mobile edition.
- **Re-run controls:** re-run any single stage or analyzer without re-running the
  whole pipeline (fast iteration during manual testing).

---

## 9. Security & threat model of the tool itself

A security tool that isn't secure is embarrassing. Design for these from day one:

- **Hostile input:** APK/IPA is untrusted; parsers have CVEs. → all parsing in
  network-less, resource-limited, disposable containers with read-only mounts.
- **Sensitive findings:** discovered secrets/creds are real and dangerous. →
  encrypt the findings DB at rest; redact secret *values* by default (store
  fingerprints, reveal on explicit action); redact by default in report exports.
- **Authorization gate (extend TOPRECON's):** require an explicit attestation
  that the user is authorized to assess the target, recorded per project. Append
  to an immutable **audit log** (who, what app hash, when, which stages ran) —
  your TOPRECON audit-trail pattern, carried over.
- **Legal edge:** decompiling third-party apps can implicate ToS/DMCA depending on
  jurisdiction. The authorization gate isn't ceremony here — it's your cover.
  Surface a clear "authorized targets only" acknowledgement.
- **Dynamic mode isolation:** never run an untrusted app's dynamic analysis on a
  device holding real data. Require a dedicated emulator/test device on an
  isolated network.
- **Supply chain:** you bundle many third-party tools — pin versions, verify
  checksums on download, and track their advisories. A security tool shipping a
  vulnerable dependency is the worst look. Sign your own auto-updates.

---

## 10. Authorization and audit

Carry TOPRECON's model over and make the boundary explicit:

```
TARGET
  ├── APK/IPA provided ───► authorization attestation ─► static pipeline
  └── Live application ───► authorized device only ─► emulator | test device
                                                       (isolated network)
```

Every run writes an audit entry (target hash, authorization ref, operator, stages
executed, timestamps). Exports carry a provenance header. This is both good
practice and, for a tool that decompiles software, real legal hygiene.

---

## 11. Phased roadmap

Each phase ends in something usable. Phase 1 is the real, shippable product; the
rest are expansions.

**Phase 0 — Foundations (skeleton that proves the architecture)**
- Repo + module layout (Section 13), CI, containerized dev env.
- The Finding schema and the graph model (entities/edges tables in SQLite).
- Orchestrator + job table + the `Analyzer` adapter interface.
- One adapter end-to-end in a sandbox: androguard unpack → entities in the graph.
- Desktop shell + Overview reading real data from the engine.
- Authorization gate + audit log.

**Phase 1 — Static MVP, Android (the shippable v1)**
- Adapters: apktool, jadx (+ Monaco code browser), semgrep (mobile rules),
  gitleaks + apkleaks, syft/grype + osv-scanner, config/manifest auditor,
  endpoint extractor.
- Normalizer + dedup/voting + confidence.
- Correlator builds the full graph; all sections render as projections.
- Scorer + MASVS/MASWE/MobileTop10 mapping.
- Findings UI with the manual-validation workflow; report export (HTML/PDF/JSON).
- **This is a genuinely useful tool on its own** — automated overview + pentester
  drill-down, no dynamic analysis needed.

**Phase 2 — Correlation & intelligence**
- MobSF adapter (REST, sandboxed) + optional VulsTotal-style multi-scanner voting.
- Data-flow enrichment (source→sink) to cut false positives on secrets/injection.
- **TOPRECON handoff:** export the endpoint/cloud subgraph into your web engine;
  round-trip the results back as enriched entities.
- Richer graph pivots and saved queries.

**Phase 3 — Dynamic analysis (pentester mode)**
- Emulator/device management via ADB; Frida + objection integration.
- One-click SSL-unpin; live storage inspection; traffic capture via mitmproxy
  (attach-your-own-Burp option).
- Workflow driving via mobilewright/Appium to exercise app paths during capture.
- Dynamic findings merge into the same graph/schema.

**Phase 4 — iOS support**
- IPA intake, plist/entitlements, Mach-O via Ghidra, class-dump-style headers.
- iOS-specific stages; document the jailbreak / Corellium requirement for iOS
  dynamic analysis honestly.

**Phase 5 — Platform & polish**
- Plugin system: third-party analyzer adapters and custom rule packs.
- Report templates, team/shared-project features, diffing across app versions.

---

## 12. Risks and what to decide before coding

- **Licensing (Section 6)** — settle the GPL/MobSF integration boundary and the
  "no bundling Burp" rule before you write integration code, not after.
- **Install weight** — Docker + JRE + Ghidra + (later) an emulator is a heavy
  footprint. Decide per-dependency: bundle / require / download-on-first-run.
- **Java dependency** — jadx, apktool, and Ghidra all need a JRE; bundle one or
  detect and require it.
- **False positives** — the correlation/voting layer is both your value *and* the
  hard part. Budget real time for it; it's the difference between "scanner
  wrapper" and "assessment platform."
- **Solo scope discipline** — this is a large system. Resist building Phases 2–5
  before Phase 1 ships. The static Android pipeline alone is a credible, portfolio
  -grade tool.
- **iOS asymmetry** — don't promise iOS parity early; the platform won't allow it
  cheaply.

**Two things to decide now:** (1) Tauri vs Electron vs PySide6 for the shell —
governs your frontend investment. (2) Ship name and whether Phase 1 is
open-source (which interacts with the licensing choices above).

---

## 13. Suggested repository structure

```
topmobile/
  apps/
    desktop/                 # Tauri/Electron shell + React frontend
      src/                   # Overview, Sections, Graph (Cytoscape), Code (Monaco)
  engine/                    # Python analysis engine
    topmobile_engine/
      api/                   # FastAPI routes + WebSocket job events
      orchestrator/          # pipeline DAG, job queue, re-run logic
      adapters/              # androguard, apktool, jadx, semgrep, mobsf, ...
      model/                 # entities, edges, Finding schema, graph
      normalize/             # raw output -> Finding
      correlate/             # dedup, voting, graph construction, pivots
      scoring/               # severity, confidence, MASVS/MASWE/Top10 mapping
      report/                # HTML/PDF/JSON report generation
      storage/               # SQLite, encrypted-at-rest, workspace manager
      sandbox/               # container runner, resource limits
      audit/                 # authorization + immutable audit log
  workers/                   # Dockerfiles per sandboxed tool
  knowledge/                 # MASVS/MASWE/MobileTop10 maps, semgrep rule packs
  shared/                    # JSON Schema for findings + generated TS types
```

---

## 14. What to build first (concrete Phase 0/1 task order)

1. Finding schema (JSON Schema) + generated TypeScript types in `shared/`.
2. SQLite migrations for entities, edges, findings, jobs, audit.
3. `Analyzer` interface + `sandbox/` container runner (read-only mount, no net).
4. First adapter: **androguard unpack** → App/Component/Permission entities.
5. Orchestrator: run one stage, persist entities/findings, emit job events.
6. Desktop shell + **Overview** reading real data; authorization gate on intake.
7. Add adapters in this order: apktool → jadx (+ code browser) → config auditor →
   gitleaks/apkleaks → semgrep → syft/grype → endpoint extractor.
8. Normalizer + dedup/voting; then Correlator (build graph); then sections render.
9. Scorer + MASVS/MASWE mapping; then finding detail + validation workflow.
10. Report export. Ship Phase 1.

Get the first vertical slice (upload → androguard → entities → Overview) working
before adding breadth. One tool, end to end, through every layer — then multiply.
