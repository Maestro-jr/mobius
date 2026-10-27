# mobius

**Open Agent Hackathon 2026, Track 2: the agent that can explain why.**

mobius answers the one question a team has to answer before every release:
*can we ship this, and if not, why not?* It reviews the two things most teams
ship today, a **mobile app** and a **website / external surface**, and returns a
verdict (ship, ship with fixes, block) and a report in which every reason cites
the exact SQL query that proved it, the memory that shaped the plan, and the
model that wrote each step.

mobius is built on two of the operator's existing engines, declared here as
**pre-existing components**: **themob** (mobile attack surface, everything below
the "themob" heading) and **TOPRECON** (external/web attack surface, run
arms-length as an unmodified subprocess). They gather what is there. mobius is
the new work: a Planner / Executor / Critic system that reasons over both, and
the sponsor stack it runs on.

Two subjects, one agent loop:

- **App review** (`run --package <id>`): themob scans the APK/IPA; its findings,
  entities and app facts become Zetaris tables.
- **Website review** (`webscan <domain>` then `run --target <domain>`): TOPRECON
  maps the domain (hosts, services, tech, URLs, certs, cloud buckets, code repos,
  leaked secrets, correlated CVEs, breaches, lookalike domains); its graph
  becomes Zetaris tables. A discovered secret's value is kept locally for
  rotation and redacted in the cloud copy.

The same Planner, Executor and Critic, the same H-MEM memory, the same Nemotron
lanes on Nightshift, and the same explain-why report serve both.

## How it works

```
themob scan (pre-existing, sandboxed Docker workers)
   |  export: findings, entities, app facts (secrets stripped)
   v
S3 workspace bucket  ->  Zetaris  <-  CISA KEV feed, FIRST EPSS API (live REST tables)
                            ^
                            |  run_sql (read-only, every query cited)
 Planner (deep lane) -> Executor (fast lane, ReAct over SQL) -> Critic (judge lane)
     ^                        |  retry with critique, escalate to the deep lane
     |                        v
  H-MEM recall           verdict + explain-why report + trace + sponsor ledger
     |                        |
     +---- H-MEM remember <---+  (sector, verdict, rulings, lessons, feedback)
```

1. **Reconnaissance.** The Planner reads the app's profile from Zetaris and
   recalls what H-MEM knows about this package and its sector.
2. **Plan.** It writes up to five investigations. A sector a human confirmed in
   an earlier session overrides the model's guess; a past ruling narrows an
   investigation to "verify it still holds".
3. **Execute.** For each investigation the Executor writes SQL against the
   Zetaris catalog, sees the rows, and makes claims that cite query ids.
4. **Critique.** The Critic re-runs the evidence rules (uncited claims,
   severity the rows do not support, single-tool corroboration, contradiction
   of a past ruling), re-queries KEV for any CVE claimed, and sends weak claims
   back with the critique. After two retries a claim escalates to the deep lane,
   which can mark it as needing a human.
5. **Verdict.** The Planner writes the verdict from accepted claims only. The
   Critic checks it against a severity floor (an exploited CVE cannot ship) and
   sends it back once, then overrides.
6. **Remember.** The sector, verdict, rulings and lessons go back into H-MEM
   with helpful / wrong feedback, so the next run starts smarter.

## What each sponsor does (and what breaks without it)

| Sponsor | Its job in mobius | Remove it and |
|---|---|---|
| **Zetaris** | The only data layer. The Executor's one tool is `run_sql`; the app scan, the web recon surface (S3 file tables), the live CISA KEV feed and FIRST EPSS API (REST tables) and the sector obligations are joined in one SQL namespace through SchemaStore views. | No run: mobius never falls back to local data. |
| **Meterless H-MEM** | Cross-session memory: confirmed sector, past verdicts, human rulings, lessons. Hybrid retrieval, trust feedback, conflict resolution and an append-only trust ledger. Passes the official H-MEM conformance suite 13/13. | `--no-memory`: the sector falls back to a guess, the plan changes, and past rulings are re-litigated. |
| **Meterless Nightshift** | The only model provider. Each agent role is pinned to its own lane, and every request's receipt (route, model, latency, tokens) goes into the trace. | No run. |
| **NVIDIA Nemotron** | Every agent model, served through Nightshift: Planner `nemotron-3-ultra-550b-a55b`, Executor `nemotron-3.5-lightning-30b-a3b`, Critic `nemotron-3.5-bolt-e4b`. The Critic is a different model from the Executor, so no model grades its own work. | `doctor` fails the lane. |

`--no-advisories` removes the KEV and EPSS tables: an exploited dependency CVE
is no longer recognised and the verdict on the test fixture drops from block to
ship with fixes. Both ablations are hermetic tests in
`tests/test_mobius_loop.py`.

Every run writes `trace.jsonl`, `ledger.json` (calls per sponsor),
`verdict.json` and `report.md`.

## Running it

```bash
pip install -e .
cp .env.example .env      # then fill in Nightshift, Zetaris and the S3 bucket
python -m themob.mobius doctor
# an app review
python -m themob scan data/apps/<app>.apk --engagement "<authorization>"
python -m themob.mobius publish
python -m themob.mobius run --package <package id>
python -m themob.mobius run --package <package id> --no-memory      # ablation
python -m themob.mobius run --package <package id> --no-advisories  # ablation

# a website review (you must own the domain or hold written authorization)
python -m themob.mobius webscan <domain>
python -m themob.mobius run --target <domain>
```

`webscan` needs TOPRECON beside this repo (or `MOBIUS_TOPRECON_DIR` set). It
runs passively by default; `--active` and `--dorks` touch the target and need
their own authorization.

`doctor` checks each Nightshift lane answers with a Nemotron model, that Zetaris
answers SQL and serves every catalog table (web tables show `SKIP` until a
`webscan` has run), and where H-MEM keeps its memory.

## New in mobius

- `themob/mobius/`: the agent loop, prompts, Zetaris client and catalog, S3
  publishing, Zetaris registration, trace, report and CLI.
- `themob/mobius/webrecon.py`: the arms-length bridge to TOPRECON that turns a
  website recon into the `mobius_web.*` Zetaris tables, secrets redacted.
- `themob/assist/meterless.py`: the Meterless Runtime provider (Nightshift).
- `themob/hmem/` and `engines/hmem/`: H-MEM in Python, plus the shim that runs
  the official conformance suite against it.
- `knowledge/sectors.json`: sector signals and obligations (advisory, review
  with counsel).

TOPRECON (`../TOPRECON`) is a pre-existing component, used unmodified as a
subprocess, exactly as themob's own rules require of any third-party tool.

---

# themob

[![ci](https://github.com/Maestro-jr/themob/actions/workflows/ci.yml/badge.svg)](https://github.com/Maestro-jr/themob/actions/workflows/ci.yml)

An authorization-gated **mobile attack-surface intelligence engine**: a desktop
app that ingests an APK, runs a staged analysis pipeline in sandboxed
containers, correlates everything into one attack-surface graph, maps findings
to OWASP MASVS, the Mobile Top 10 and CWE, and scores severity and confidence,
so a tester never has to leave the tool.

Sibling to [TOPRECON](../TOPRECON): same DNA, authorized targets, entity-driven
pivots, a full audit trail: applied to a binary instead of a domain.

> **Status: Phase 1 complete.** The static Android pipeline runs end to end:
> authorize, ingest, seven sandboxed analyzers, cross-tool voting, one
> correlated graph, scored findings with a manual-validation workflow, and an
> HTML and JSON report with a provenance header.
>
> **Phase 2 is complete.** MobSF runs as an eighth analyzer, a second opinion
> rather than new coverage: reached over REST in its own container on a network
> with no route out, and what it reports merges with what themob already found
> instead of being counted twice. Data-flow enrichment, the TOPRECON handoff,
> and saved graph queries all landed.
>
> **Phase 3, dynamic analysis, is built and unit-tested, and its live paths
> await a device.** Running the app is a different act from reading it, so it
> sits behind a second gate that attests the test device, the traffic, and
> exactly which hosts may be intercepted. ADB is bound to that one device,
> Frida and objection load only agents this repository ships, mitmproxy
> decrypts only hosts in scope, and what any of it observes becomes an ordinary
> finding on the same graph, merged by fingerprint with the static finding that
> suspected it and re-voted so the corroboration lifts confidence. A **Dynamic**
> console panel drives all of it: attest, prepare the command, import the
> result. The parts that need a real emulator, spawning a process and
> terminating live TLS, are isolated behind seams an integration test drives;
> everything else is covered.
>
> **Phase 4, iOS, is complete.** An `.ipa` runs the same pipeline as an APK: a
> sandboxed worker decodes the bundle, reads the Info.plist, the embedded
> frameworks and the main Mach-O's hardening (PIE, stack canary, ARC, FairPlay,
> signature) with lief, and parses the provisioning profile's entitlements. A
> Mach-O hardening adapter and an Info.plist/entitlements auditor turn the
> absences into findings (App Transport Security, hijackable URL schemes, file
> sharing, get-task-allow, over-broad entitlements), keyed to a new iOS weakness
> pack. gitleaks and syft scan the decoded bundle; endpoints and cloud assets
> are extracted into the same node types as on Android; and the REA handoff
> bundles an iOS Mach-O, the native-binary case it exists for. Every iOS finding
> is just a finding, so the graph, scoring, report, MCP tools and the assistant
> work on it unchanged. Phase 5 (platform and packaging) has not started.
> See [PROGRESS.md](PROGRESS.md) for the detail and
> [Known gaps](#known-gaps) for what is still missing.

---

## What it does today

```
APK / IPA -> authorization gate -> intake
                                |
     +--------------------------+----------------------------+
     |  unpack        androguard, apktool / ios-unpack       |
     |  reverse eng.  jadx, nativelib / Mach-O hardening     |   all in
     |  secrets       gitleaks, apkleaks (gitleaks on iOS)   |   containers,
     |  SAST          semgrep                                |   no network
     |  dependencies  syft -> grype                          |
     |  2nd opinion   MobSF                  (own network)   |
     |  config audit  manifest / Info.plist  (no container)  |
     |  endpoints     endpoint extractor     (no container)  |
     +--------------------------+----------------------------+
                                v
              normalize:  canonical weakness keys, dedup,
                          method-aware cross-tool voting
                                v
              correlate:  one attack-surface graph,
                          entry points, exposure, sections
                                v
              score:      severity raised for reachability,
                          confidence from agreement, risk
                                v
   Overview | 6 section pages | Graph | Code | Findings | Activity | Report
```

Each analyzer records what it saw; none of them decides what it means on its
own. The unpackers note that `android:debuggable` is true. Whether that matters
is a question you can only answer holding the whole picture, so the judgement
lives downstream where the picture exists.

**Every finding is keyed by a canonical weakness id** from
`knowledge/*-weaknesses.json`, never by a tool's own rule name. Get that wrong
and two tools reporting the same issue never merge, cross-tool voting never
fires, and the same problem is reported twice at half the confidence it
deserves.

**Voting is method-aware.** Two pattern scanners agreeing is weaker evidence
than a pattern scanner and a semantic one agreeing, because tools that share a
technique share its blind spots. Confidence combines the strongest vote per
method, not per tool.

**A flagged value that goes nowhere is not the same finding.** A hardcoded
string never referenced again and one passed to `setRequestProperty` look
identical to a scanner. `dataflow/` reads the decompiled Java and says which is
which, as confidence rather than severity. It follows the value through
assignments, so a secret laundered through a local or two before being sent is
still connected to the sink. It is a heuristic over text, co-mention on an
assignment line, not dataflow analysis, and its notes say "appears where it is
sent as an HTTP header" rather than claiming to have proved a path.

**Exposure is directed.** A finding is marked externally reachable only when a
directed path runs from an exported entry point to the entity it sits on. An
undirected walk made the `App` node a hub and marked every finding reachable,
which is the same as marking none of them.

**A verdict is an auditable event.** Confirming a finding, or dismissing it as
a false positive or accepted risk, appends to the hash-chained trail beside the
authorization attestation. The two dismissing verdicts are refused without a
reason, because an unexplained removal cannot be told apart from an oversight.

Every run is refused unless the operator attests authorization, and every step
is appended to a hash-chained audit log.

## The report

`Export report` writes three files from one assembled report, so their numbers
cannot disagree: a self-contained HTML page for a person, a JSON document for a
diff, and a SARIF 2.1.0 log for a build pipeline. The SARIF carries each
finding's stable fingerprint, so a consumer like GitHub code scanning tracks a
triaged issue across runs instead of re-reporting it as new, and a
`security-severity` number so themob's ramp survives into that UI.

The HTML references nothing external. No fonts to fetch, no scripts, no images.
A report gets opened six months later on a machine that has never heard of
themob, and one that needs the network to render is one that will eventually
render blank.

The provenance header states what the report does **not** know. An analyzer that
failed is named as incomplete coverage. A project with no attestation is called
out. An audit chain that no longer verifies is said on the first page rather
than left to read as normal. The vulnerability database's build date is shown
and, past a week old, flagged, because "no vulnerable dependencies" matched
against a stale feed is a false negative, not a clean bill. Dismissed findings
leave the body but keep their own section, with the verdict, the reason and who
recorded it.

No secret value can reach any of them. The workers redact before anything leaves
the container, so themob holds no plaintext to leak, and the export asserts that
rather than assuming it.

Every export also writes a `manifest.json`: the SHA-256 of each deliverable
file, a digest of the raw evidence, and the tip of the audit chain at export
time. `themob verify <folder>` recomputes those hashes and catches an edit made
after export, naming the changed file. `themob scan --sign key.pem` adds an
Ed25519 signature on top, so a recipient can verify authorship and not just
integrity; without a key the manifest is still tamper-evident by checksum. The
signing layer needs the optional `cryptography` extra (`pip install
"themob[sign]"`).

## Comparing versions

`themob diff old-report.json new-report.json` shows what changed between two
scans: new findings, resolved ones, and the attack-surface delta. Because every
finding is keyed by a stable fingerprint, "the same finding" across versions is
"the same fingerprint", so the diff is exact rather than a fuzzy text compare.

In a pipeline this becomes a gate on regressions rather than on inherited debt:

```bash
python -m themob scan app.apk --engagement ENG-1 --baseline last-release.json --fail-on high
```

With a baseline, `--fail-on` counts only findings absent from it, so the build
fails on what this change introduced and stays quiet about the backlog a team is
already working through. A finding dismissed in the baseline that reappears is
not treated as new; it was already judged.

## Running the app (Phase 3)

Everything above reads the package. Phase 3 runs it, and running a hostile app
puts it on a device, sends live requests to production, and terminates TLS. None
of that is covered by "I may assess this binary", so it sits behind a second
gate that attests three more things: that the device is a dedicated test device
or emulator and not somebody's phone, that generating the traffic is authorised,
and exactly which hosts may be intercepted. Nothing runs until all three are
recorded in the same hash-chained trail as the static attestation.

From there:

- **adb** is bound to the one attested serial. A lab with three phones is
  normal, and there is no default device, because picking the wrong one is not
  recoverable. `root`, `remount` and the other escalations are refused by name.
- **Frida and objection** attach to that device. Frida loads only agents this
  repository ships, resolved to a file inside `dynamic/agents/` before a process
  is touched: a downloaded instrumentation script is a downloaded exploit. The
  shipped agents observe, they do not alter, and they emit lengths and algorithm
  names, never key bytes.
- **mitmproxy** decrypts only hosts in the interception scope and relays
  everything else untouched, so a third party the engagement never named is
  never silently read. The scope filter runs inside mitmproxy and carries a copy
  of the gate's matcher; a test asserts the two agree. attach-your-own-Burp is
  the alternative, and themob records that it captured nothing.
- **What any of it observes becomes an ordinary finding** on the same graph,
  keyed by the same canonical weakness. A weakness watched at runtime lands on
  the same fingerprint as the static tool that suspected it, and because
  `runtime` shares a blind spot with no static method, that agreement is the
  strongest corroboration themob can express.

The paths that need a real emulator, spawning the process and terminating live
TLS, are isolated behind seams an integration test drives. Everything decidable
without a device is unit-tested.

## Validating a leaked secret

A hardcoded credential is a hypothesis until someone shows the key still works,
and showing that means sending a request to a third party the engagement never
listed. So validation has its own gate, separate from the assessment's: an
attestation naming the operator, the engagement, and the scope, recorded in the
same audit trail before any probe is planned. themob never holds the plaintext
secret and never sends the request. It classifies the secret to a provider and
prepares a read-only, side-effect-free probe (an identity read such as `aws sts
get-caller-identity`) with the secret left as a placeholder, for the operator to
run. The result comes back as an ordinary verdict on the finding: confirmed when
the key is live, accepted-risk when it was already revoked, recorded either way.

## Extending the rule packs

The weakness catalogue is data, not code, so a team with house rules can add a
pack without forking. Point `THEMOB_KNOWLEDGE_EXTRA` at a directory of
`*-weaknesses.json` files and they load alongside the shipped ones. Because a
pack sets a finding's severity and its canonical key, a pack an attacker dropped
on disk could quietly downgrade a critical finding, so extra packs are signed:

```bash
python -m themob sign-pack --generate-key operator.pem     # once, keep the key secret
python -m themob sign-pack house-weaknesses.json --key operator.pem
```

With `THEMOB_KNOWLEDGE_STRICT=1` an extra pack loads only when it carries a
signature from a key listed in `THEMOB_KNOWLEDGE_PUBKEYS`; a tampered pack, one
signed by an unknown key, or one trying to redefine a built-in key is refused.
Without strict mode an unsigned pack still loads, but the preflight reports that
it was unverified, so a rule that changed a severity is never invisible. The
signing uses the same Ed25519 layer as the report manifest and needs the
optional `cryptography` extra; verification degrades to "not verified" without
it rather than passing by default.

## Architecture

All Python. The UI is PyQt6; the engine runs on a background `QThread` and
dispatches heavy work to disposable Docker workers.

```
themob/
  app/            PyQt6 shell: theme, sidebar, panels, the graph widget
  model/          Pydantic v2: Entity, Edge, Finding, and the enums
  storage/        SQLite (schema + migrations), repositories, workspace
  orchestrator/   intake, the pipeline, its event stream  (no Qt)
  adapters/       one per tool: Analyzer interface + registry
  sandbox/        the Docker runner and the worker-image builder
  normalize/      canonical weakness keys, dedup, cross-tool voting
  correlate/      the graph read model, entry points, exposure, sections
  dataflow/       does a flagged value reach a sink   (a heuristic, and says so)
  handoff/        the endpoint subgraph, out to TOPRECON and back
  dynamic/        Phase 3: the execution gate, adb, Frida/objection, capture
  scoring/        severity from reachability, confidence, risk
  report/         HTML, JSON, SARIF export, and version diffing (no Qt import)
  preflight.py    python -m themob --check
  cli.py          python -m themob scan  (headless, SARIF, exit codes)
  audit/          attestation + the append-only audit trail
workers/          a Dockerfile per sandboxed tool, or a pinned digest
knowledge/        weakness packs: canonical keys + MASVS mapping
tests/            unit tests + a live end-to-end Docker test
```

Four decisions carry the design:

**One graph; every view is a projection of it.** Everything discovered is an
`Entity`; typed `Edge`s connect them; findings attach to entities. "Network &
API" is a query, not a feature. Costs more up-front modelling, but every section
and every pivot comes free afterwards.

**Nothing untrusted is parsed in-process.** An uploaded APK is hostile input and
parsers have CVEs. Tools run in containers with `--network none`, a read-only
root filesystem, the sample mounted read-only, all capabilities dropped, an
unprivileged uid, and hard CPU/memory/pid/time limits. There is no host
fallback: if Docker is unavailable, analyzers are skipped, not run locally.

**Arms-length tool integration.** Every third-party tool is a subprocess or a
REST call, never a library import. That single boundary is both the containment
boundary and the licensing boundary, a GPL tool stays a separate program. MobSF
runs in its own container over REST and is never imported or vendored, settled
before the Phase 2 adapter exists rather than after it. Burp is never bundled;
mitmproxy is the default proxy.

**Fingerprints use the canonical weakness key.** Findings dedup on
`sha256(weakness_key + location + evidence)` where the weakness key is a MASWE
id or an internal canonical rule id, *never* a tool's own rule name. Get that
wrong and cross-tool voting silently never merges, which is the whole
de-noising value proposition.

## Running it

Requires Python 3.11+ and a running Docker daemon.

```bash
pip install -e ".[dev]"
```

Build the worker images (themob never pulls one implicitly, and every pinned
tool is checksum-verified at build time):

```bash
python -m themob.sandbox.build
```

Then check the whole installation before the first assessment. It starts no
container and needs no display, and it prints the command that fixes anything
it finds missing:

```bash
python -m themob --check
```

Worth running whenever a stage reports nothing, because a skipped analyzer and
a clean one look identical from the Overview. themob has no host fallback by
design: if an image is missing, the stage is skipped rather than run outside a
container.

Launch the console, as a module and from the repository root:

```bash
python -m themob
```

Not `python themob/app/main.py`. That file imports its siblings
relatively, so running it as a script fails with "attempted relative
import with no known parent package".

The authorization gate opens first. Nothing is ingested until you name a target
and attest that you are authorized to assess it.

## The command line

Everything the window does is also a subcommand, driving the same engine, gate
and audit trail with no display and no Qt. `pip install .` puts a `themob`
command on your PATH; from a checkout, `python -m themob` is the same thing, and
the `themob.sh` / `themob.cmd` launchers in the repository root find a working
Python and run it for you.

```bash
themob --help          # every command
themob <command> --help   # one command's flags
```

Two flags are global and may go before or after the command: `--no-color` (also
honoured through the conventional `NO_COLOR` variable, and off automatically when
the output is not a terminal) and `--home DIR`, the project store to work in
(default `$THEMOB_HOME` or `~/.themob`). Every command exits `0` on success, `1`
when a gate or a check fails, and `2` when it could not run. Commands that read
or change a project take `--project` (`-p`), which accepts a project id, a unique
id-prefix, or a name, and defaults to the most recently authorized one.

**Getting oriented.**

```bash
themob doctor        # deps, tools and config, with the command that fixes each gap
themob projects      # what has been ingested, and whether the gate passed
themob analyzers     # the analyzer roster and each one's availability
themob build-workers --list   # the sandboxed images, and whether they are built
```

`doctor` is the one whose whole job is to say what is missing; it starts no
container and needs no display, and it is worth running whenever a stage reports
nothing. `build-workers` with names (or none, for all) builds the images;
`themob gui` opens the desktop console.

**Assessing an app.** `authorize` ingests a sample and records the attestation,
the gate as a command. In a terminal it asks you to confirm authorization; for
automation, `--yes` is the attestation and is refused when there is no terminal
and no `--yes` to stand behind it.

```bash
themob authorize app.apk --engagement ENG-1 --name "Example shop"
themob analyze -p ENG          # run the pipeline (needs Docker)
themob report -p ENG --out ./out --sign key.pem
```

`analyze` narrows with repeatable `--stage` / `--analyzer`, streams the run log
(quiet with `-q`), and gates with `--fail-on`. `report` writes the HTML, JSON,
SARIF and a tamper-evident `manifest.json`, signs it with `--sign`, and drops
SARIF with `--no-sarif`. `scan` is all of the above in one headless step for a
build server; see the next section.

**Reading a project.**

```bash
themob overview                       # the 30-second read
themob section secrets                # one tester-facing section
themob findings --severity high       # the list, filterable; --json for a machine
themob finding <fingerprint>          # one finding in full (a prefix is enough)
themob graph --type endpoint          # entity counts, a type, --reachable-from, or --json
themob entity <id>                    # one node, its attributes and path from the app
themob code --open com.example.Main   # the decompiled classes: list, --filter, or --open one
themob query run reachable-secrets    # the built-in questions; 'query list' shows them
themob audit --verify                 # the hash-chained trail, and whether it still verifies
```

`query save <key> --like <builtin>` keeps a question, and `query delete <key>`
drops it; a built-in is never yours to delete.

**Recording judgement.** A verdict is an auditable event, and the two verdicts
that remove a finding from the report demand a reason.

```bash
themob verdict <fingerprint> --status confirmed
themob verdict <fingerprint> --status accepted-risk --note "compensating control X"
```

**Dynamic analysis (Phase 3).** Running the app is a second gate: attest the
device, the traffic and the interception scope before anything touches a device.

```bash
themob dynamic devices                          # connected adb devices
themob dynamic authorize --device emulator-5554 --scope .example.com
themob dynamic prepare --job capture            # the exact command to run
themob dynamic prepare --job frida:crypto-trace.js
themob dynamic import-frida run.log             # merge what it saw onto the graph
themob dynamic status                           # the execution gate's state
```

themob prepares and records; the device runs the prepared command, and
`import-frida` / `import-capture` fold the result back in.

**Handing off, and validating a secret.** `handoff export` writes the backend
subgraph for TOPRECON (`import` folds its results back). `validate` is the third
gate: testing whether a found credential is live contacts the provider, so it is
attested on its own, and themob only ever prepares the read-only probe.

```bash
themob handoff export --out handoff.json
themob validate authorize --engagement ENG-1
themob validate plan                            # a read-only probe per secret finding
themob validate record <fingerprint> --result live
```

**Deliverables and rule packs.** These take explicit paths, not a `--project`.

```bash
themob diff old-report.json new-report.json --fail-on-new high
themob verify ./out                             # manifest, and signature if present
themob sign-pack --generate-key operator.pem
themob sign-pack house-weaknesses.json --key operator.pem
```

## The MCP server

An agent can drive the same tools over the Model Context Protocol. `themob mcp`
(or `python -m themob.mcp`) serves themob's capabilities over stdio, so a client
such as Claude or themob's own assistant reads a project and runs the gated
analysis the way the console does.

```bash
pip install "themob[mcp]"
themob mcp
```

The read-only tools (overview, findings, section, graph, entity, code, queries,
audit) read an existing project. The gated tools (authorize_target, analyze,
scan, record_verdict) are not softened for being driven by an agent: they refuse
without an attestation, an operator and an engagement, and each appends to the
same hash-chained audit trail, so "who authorised what" survives a run no matter
who drove it. The SDK is an optional extra; the engine, the console and the
window run without it.

## Deep reverse engineering, handed off to REA

themob measures native libraries and decompiles Java; reversing the logic inside
a native binary or an obfuscated class is a job for an agent like REA
(github.com/morluto/rea). Because that is non-deterministic and reaches the
network, themob hands off rather than runs it. `themob rea prepare` bundles a
chosen native library or class with themob's context and prints the `rea`
command, you run REA yourself with your own setup, and `themob rea import`
attaches its summary to a finding as external evidence. themob never imports REA
and never reaches the network; both steps are gated and recorded in the audit
trail.

```bash
themob rea prepare --native lib/arm64-v8a/libfoo.so
themob rea import <fingerprint> --file rea-output.txt
```

## The assistant

A licensed assistant explains an app's findings in plain language and coaches the
fix, as the **Assistant** page in the console. It reads the real findings through
themob's own tools and asks Claude to explain and coach; it never shows anything
themob did not find. It is gated by an Ed25519-signed licence and uses your own
`ANTHROPIC_API_KEY`, both optional to the rest of themob.

```bash
pip install "themob[assist]"
themob assist generate-key vendor.pem      # the vendor, once
themob assist issue --key vendor.pem --licensee "Dev Co"   # mint a licence
themob assist status                       # licence and Claude readiness
```

Place the issued token as `license.key` and the public key as `license.pub` in
the themob home (or set `THEMOB_LICENSE` / `THEMOB_LICENSE_PUBKEY`), set
`ANTHROPIC_API_KEY`, and the Assistant page unlocks.

## In a build pipeline

The console is one way in; a build server is another. `themob scan` runs the
whole static assessment headless and gates on the result:

```bash
python -m themob scan app.apk --engagement ENG-1 --operator ci@team --fail-on high
```

It records the authorization attestation exactly as the console gate does, since
the gate is not skipped for being headless, writes the HTML, JSON and SARIF
report to `--out`, and exits 0 when clean, 1 when a finding reaches `--fail-on`,
and 2 when it could not run. Point a code-scanning upload at the `.sarif.json`
and the findings land in the pull request.

## Tests

The default suite is hermetic: no Docker, no network, no device, offscreen Qt.
1,031 tests, a couple of minutes:

```bash
python -m pytest -m "not docker"
```

The end-to-end tests build a real APK, run the real workers in real containers,
and assert the entities, the decoded tree, the class index, the findings, the
scored severities, the exported report and the rendered UI, including that the
container really has no network and really cannot write to the sample. 95 tests,
about an hour, and they need the worker images:

```bash
python -m pytest -m docker
```

The marker is `docker`, not `integration`. Running plain `python -m pytest`
runs both.

Continuous integration runs the hermetic suite on Python 3.11 and 3.12, a
typography gate (`tools/check_typography.py`, which enforces the no-em-dash rule
for any contributor, not just the author's machine), a clean-environment wheel
install that proves the report and dynamic-findings paths import without Qt, and
a pinned gitleaks scan of the tree. The workflow is `.github/workflows/ci.yml`;
the docker suite is not part of it, since it needs a daemon and built images.

There is no third-party APK in this repository. `tests/fixtures/` generates one,
including a hand-encoded binary `AndroidManifest.xml`, so the fixture is
deterministic, tiny, and carries no licensing questions.

## Known gaps

Phase 1 is complete against its own checklist. Three things the build plan names
for Phase 1 are not in it, listed here rather than discovered later:

**MASWE ids are null.** MASVS controls, Mobile Top 10 categories and CWE ids all
map; the MAS Weakness Enumeration ids do not. They could not be verified against
the OWASP source, and a wrong standards reference in a pentest report is worse
than a missing one. The field exists throughout, the report renders it as "not
mapped", and `python -m themob --check` warns about it every run. Filling them
in `knowledge/*-weaknesses.json` needs no code change.

**No PDF export.** HTML and JSON ship. The HTML is self-contained and prints to
PDF from any browser, which covers the need without a rendering dependency.

**No osv-scanner.** syft builds the SBOM and grype matches it against advisories.
osv-scanner asks OSV.dev the same question about the same SBOM, so it would be a
second opinion for the voting layer to merge rather than new coverage.

One deliberate substitution, recorded as locked decision 9: the plan called for
a Monaco code browser, which needs a web view. The shell is PyQt6, so the code
page is a Qt `QSyntaxHighlighter` that loads classes lazily and bundles no
JavaScript.

**Phase 3's live behaviour is unverified.** The gate, the adb argv, the agent
resolution, the scope matching and the finding construction are all unit-tested,
but spawning Frida against a running app and terminating TLS through mitmproxy
need a real device, and there is not one in CI. Those seams are built so an
integration test on an emulator drives exactly what an operator would; the test
does not exist yet. Treat dynamic analysis as ready to try, not as proven.

## Authorization and audit

themob decompiles software, which can implicate licence terms and, depending on
jurisdiction, the law. The gate is the record, not ceremony:

- no project is analyzed without an attestation (`require_authorization` fails
  closed on anything unexpected);
- the attested SHA-256 must match the ingested sample, so authorizing one binary
  cannot analyze another;
- `audit_log` rejects `UPDATE` and `DELETE` at the database level, and each entry
  hash-chains to the previous one, so an out-of-band edit is detectable,
  Activity -> **Verify chain** re-walks it;
- the audit trail deliberately outlives the projects it describes.

## Look and feel

The console is violet throughout, keyed to the ring in the MOB mark. One
deliberate exception: the **severity ramp stays semantic**, critical is red,
low is green. Colouring a risk ramp for aesthetics makes a security console
misreport, which is worse than being off-palette. `INFO` is the one level that
turns violet, because it carries no urgency.

The MOB mark ships as artwork at `themob/app/assets/mob-logo.png` and is drawn
as-is, scaled. To replace it:

```bash
python tools/install_logo.py path/to/logo.png
```

That keys the background out: flood-filling from the edges inward, so the white
`M O B` letters on the black hexagon survive, crops to the mark, and downscales.
A painted fallback in `app/widgets/logo.py` covers a checkout with no asset, so
the app always has a mark.

## Licence

GPL-3.0-or-later. PyQt6 is GPL, so themob is too. If this ever has to ship
closed, the UI moves to PySide6 (LGPL, near-identical API); nothing outside
`themob/app/` imports Qt, so that change is contained.

The full licence text is in [LICENSE](LICENSE), verbatim and unmodified:
35,149 bytes, sha256
`3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`.

Bundled tools keep their own licences and are invoked at arms length,
see the licensing table in `TOPMOBILE-build-plan.md` §6.
