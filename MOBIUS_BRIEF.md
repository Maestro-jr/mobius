# mobius: Open Agent Hackathon 2026 brief

Read this first, fully, then keep it open. This is the single source of truth
for the hackathon build. A session opened here starts with empty memory (memory
is keyed per project folder, and this is a new folder), so everything you need
is in this file and in the repo docs it points to.

**Work from two documents.** This brief (`MOBIUS_BRIEF.md`) is the plan and the
map of the existing engine. The **Participant Setup Guide** (the operator pastes
it in) is the ground truth for setting up Zetaris, the Meterless Engines,
Nightshift and NVIDIA: the exact steps, endpoints and variable names. Read both
before building; where they differ on a setup detail, the Setup Guide wins.

**Git and GitHub are the operator's, not yours.** Do not run `git` or `gh`, do
not init/create/push a repo or change its visibility. The operator handles every
git and GitHub step. Your job is the code and the docs in this folder.

## 0. Time check (read this first)

- Build window: 22 Oct 2026 00:00 UTC to 27 Oct 2026 23:45 UTC (144 hours).
- Submission deadline: **27 Oct 2026, 23:45 UTC. Hard. No extension.**
- It is already 26 Oct. There is roughly **one to one-and-a-half days left.**
  Plan for the smallest build that fully qualifies, submit early, do not gold-plate.

## 1. What mobius is

mobius is a hackathon fork of **themob** (`C:\Users\HP\Documents\GitHub\themob`),
the operator's authorization-gated mobile attack-surface engine: a PyQt6 desktop
app + CLI that scans an Android/iOS package inside sandboxed Docker workers,
correlates the results into an attack-surface graph, scores findings, and has an
AI assistant and an investigation agent over the findings. It is mature (1000+
hermetic tests) and is the operator's own product, so it is a **pre-existing
component** and must be declared as such in the submission.

mobius = that engine, extended for the Open Agent Hackathon 2026 with the
required sponsor technology and a visible multi-agent system. The hackathon
scores the **new work**, not the prior product.

## 2. Heads-up the operator relayed

The latest Meterless Nightshift builds are live (Mac, Windows, DGX Spark) at
https://meterless.ai . If an earlier build is installed, update to the newest one
before building. The NVIDIA API key goes in Nightshift's Providers tab, not in
this repo.

## 3. The hackathon in one screen

Build a **working multi-agent system that does real work** for a real user, using
the sponsor tech for the plumbing so the time goes into the solution.

What wins:
- Agents that delegate, critique, validate, retry, escalate, and recover.
- A real problem with a real user and a usable output.
- Logs/traces that show how the system reached its answer, including which model
  handled each request.
- Reliable execution from a clean setup, and a sample mode judges can run.

What loses:
- A linear pipeline (Agent A -> B -> C), a chatbot, or a prompt wrapper.
- UI polish over a weak system.
- Sponsor tech "in name only" (an unused dependency, a copied prompt).
- Over-broad scope that does not run.

Scoring (100): Impact 30, Technical 20, Innovation 15, Demo 15, Product/UX 10,
Sponsor Tech 10. Ties break on Impact, then submission timestamp.

## 4. The hard gate: required sponsor technology

Every submission MUST, and the integration must actually work in the project:
1. **Zetaris** as the data layer (runs locally in Docker, queries many sources
   via SQL from one place).
2. **At least one Meterless Engine** in a working feature, with a test that shows
   it works. The engines: **H-MEM** (memory across sessions), **Markovian**
   (long-running tasks), **World Model** (shared state between agents), **Scout
   Intent** (routing a request to the right tool).
3. **Meterless Nightshift** as the primary AI provider (route NVIDIA and other
   models through it).
4. **NVIDIA** wherever it contributes. Nemotron through Nightshift, in a working
   feature, logging which model handled each request, is eligible for the NVIDIA
   DGX Spark prize.
Cursor is optional. Setup is in the Participant Setup Guide on HackOS; start the
Zetaris install first (30-45 min, needs 16 GB RAM or AWS).

## 5. Recommended track and the pitch

**Primary track: Track 2, "The Agent That Can Explain Why."** themob investigates
a hard question (is this app safe to ship, and why), connects findings across
many sources, and produces evidence-backed answers and recommendations, which is
exactly this track. It also touches **Track 1, "Solving Fragmented Intelligence"**
(security data is fragmented across the manifest, decompiled code, native
libraries, secrets, endpoints, dependencies, and the memory of past scans, and
Zetaris unifies it). Pick one primary track in the team workspace; it can be
changed until the deadline. (Not Wildcard: the operator wants to compete in a
main track.)

themob is the operator's pre-existing product, so whatever track is chosen,
**declare themob as a pre-existing component** in the submission form. Only the
new work (the sponsor integration and the agent loop) is scored.

One-sentence use case (the APPROACH format the guide asks for):

> mobius helps a mobile app developer or security reviewer decide whether their
> app is safe to ship and WHY, by investigating findings across fragmented
> sources (manifest, decompiled code, native libs, secrets, endpoints,
> dependencies, and a memory of past scans) unified through Zetaris, with a
> Planner/Executor/Evaluator loop that validates evidence, retries and escalates,
> remembering prior scans and the app's sector via a Meterless H-MEM engine,
> powered by NVIDIA Nemotron through Nightshift, and producing an evidence-backed,
> sector-aware security verdict with the reasoning behind each conclusion.

This also lines up with a product direction the operator already wants (below).

## 6. How the existing engine maps to the requirements (the gold)

Most of the product exists. The new work is wiring the sponsor tech in and making
the agent loop visible. Concretely:

- **Agent system (the "new work" judges score).** Build an explicit
  **Planner -> Executor -> Evaluator/Critic** loop with real back-and-forth:
  - Planner: decides what to investigate (which analyzers to run, which findings
    to dig into, what external data to pull).
  - Executor: runs analyzers / queries Zetaris / fetches advisory data. The
    existing pipeline (`themob/orchestrator/pipeline.py`) and the MCP tools
    (`themob/mcp/tools.py`) are its hands.
  - Evaluator/Critic: validates findings (false-positive check, is the evidence
    sufficient, confidence, cross-tool agreement), flags gaps, and sends work
    back or escalates a risky finding. themob already has confidence, cross-tool
    voting, verdicts and scoring to lean on.
  - The loop, retries, branching on confidence/risk, and escalation are what make
    this a system, not a pipeline. The existing investigation agent
    (`themob/assist/agent.py`) is the skeleton; it is currently mostly a
    read-only single pass, so the new work is the critique/retry/escalation loop
    and shared state.
- **Zetaris = the data layer.** Today findings/entities/graph live in SQLite.
  Serve them (and at least one external source, e.g. a CVE/advisory feed or the
  decompiled-string corpus) **through Zetaris**, and have the Executor query via
  SQL. This is the fragmented-intelligence story.
- **Meterless Engine (pick one, make it work, test it).** Best fit: **H-MEM** over
  themob's local intelligence corpus (`themob/intel`, surfaced in the Trends
  page), so the agent remembers past scans, prior verdicts, and the app's sector
  across sessions. Alternatives: **World Model** = the attack-surface graph
  (`themob/correlate/graph.py`) as shared agent state; **Scout Intent** = route a
  question to the right analyzer/tool. Do ONE well with a passing test.
- **Nightshift = primary AI provider.** The assistant already supports any
  OpenAI-compatible provider (`themob/assist/llm.py`, the `OpenAICompatibleClient`
  and the `_PROVIDERS` map). Add Nightshift as a provider (base URL + key),
  default to it, and route a **Nemotron** model for the agents. Log which model
  handled each request (the audit trail / run log already give you traceability).
- **NVIDIA.** Nemotron through Nightshift in a working feature + the per-request
  model log = eligible for the DGX Spark prize.

Traces judges want already exist in themob: the **audit trail**, the **run log**,
the **agent step trace**, finding **confidence/votes**. Surface them as the
"how it reasoned" evidence.

## 7. Minimum qualifying build, in priority order

If time runs short, this is the order. Each step is a gate; do not move on until
the one before it works.

1. **Nightshift as the provider** (small; llm.py already does this pattern). Route
   one Nemotron model. Confirm a model call works and is logged.
2. **One Meterless Engine working + a test** (H-MEM over the corpus is the
   shortest path). The test shows it recalling a prior scan/verdict.
3. **Zetaris serving one source the agent queries over SQL.** Start the Zetaris
   install FIRST (it is the long pole). Register one source; have the Executor
   query it.
4. **Make the Planner/Executor/Evaluator loop visible** with critique + retry +
   escalation, and a trace of the run. Log which model handled each request.
5. **Sample mode:** `SAMPLE_MODE=true` runs the whole thing on a bundled sample
   scan with no live Zetaris/Nightshift/keys, so a judge can see it work.
6. **Submission:** public repo + README (setup, usage, deps, sponsor-tech
   explanation), declare themob as a pre-existing component, 1-4 min demo video,
   slide deck. Submit EARLY.

Absolute floor to qualify: Zetaris data layer + one working+tested Meterless
Engine + Nightshift primary provider + NVIDIA via Nightshift + a multi-agent loop
with visible critique/retry + the four submission components. Cut anything else.

## 8. Non-negotiables

- **Secrets:** never commit keys. `.env` is gitignored; `.env.example` ships with
  placeholders only (both are already in this repo). The NVIDIA key lives in
  Nightshift's Providers tab, not here.
- **Sample mode** that runs with no live credentials.
- **Keep the repo light.** The large sample APK/AAB binaries were removed from
  this clone. Use a small sample (put it under `data/sample/` or provide a
  download script); do not commit big binaries.
- **Declare pre-existing components** (themob) in the submission form. Only the
  new work is scored.
- **Git and GitHub are the operator's.** Do not run `git` or `gh`, create or push
  a repo, or change visibility. The submission needs a public repo with a README
  (setup/usage/deps) and a sponsor-tech explanation (Zetaris integration; which
  Meterless Engine and its test; Nightshift connection; where NVIDIA contributes),
  but the operator does all the git/GitHub steps. You write the code and the docs.
- The operator's standing rules still apply: no em dashes / curly quotes / arrow
  glyphs in code or user-facing text (a global hook enforces it); secure
  primitives; never commit or push.

## 9. Orientation: where things are in the code

- `PROGRESS.md` - the full themob build history and recent fixes. Read for context.
- `themob/assist/` - `core.py` (one-shot assistant), `agent.py` (the ReAct
  investigation loop), `llm.py` (provider layer; add Nightshift here).
- `themob/mcp/tools.py` - the read-only tool surface the agent calls.
- `themob/orchestrator/pipeline.py` - the analyzer pipeline + audit trail.
- `themob/correlate/graph.py` - the attack-surface graph (World Model candidate).
- `themob/intel/` and the Trends page - the local corpus (H-MEM candidate).
- `themob/storage/` - SQLite layer the data currently lives in (serve via Zetaris).
- `tests/` - 1000+ hermetic tests; keep them green, add tests for the new work.

## 10. Product direction this build advances (operator context)

The operator already wants themob to grow toward **sector-aware, compliance- and
memory-driven scanning**: guess the app's sector (fintech, education/kids, health,
...) and confirm with the user; map it to the laws it likely must meet (including
Cameroonian and African law alongside GDPR/HIPAA/FERPA/COPPA/PCI); and use the
corpus of past scans to predict and prioritize likely issues. That is exactly the
H-MEM + "explain why" story this hackathon rewards, so building the hackathon
slice also advances the real product. Keep any compliance output ADVISORY (review
with counsel), never a certification.

## 11. Open decisions to confirm with the operator

- Final track: Track 2 (recommended) vs Track 1 or 3. Not Wildcard.
- Which single Meterless Engine to make the hero (H-MEM recommended).
- The one app / scan the demo runs on (needs the scan to succeed; keep it small).
- Exact sponsor env-var names and Nightshift/Zetaris endpoints (from the
  Participant Setup Guide / workshop recordings).
- (Git, GitHub, repo creation, visibility and licensing are the operator's, not
  an agent task.)

## 12. The operator will provide the full hackathon guides

The two documents you build from are this brief and the **Participant Setup
Guide** (the operator pastes it in). The Setup Guide is the one with the real
install steps, endpoints and variable names for Zetaris, the Meterless Engines,
Nightshift and NVIDIA; read it before wiring any sponsor service, and where it
differs from this brief on a setup detail, it wins.

The operator may also paste the other official docs (the Welcome Guide, the
Journey Map, the Hackathon Overview, the "How to APPROACH Solutioning" guide, and
the FAQ) for context. This brief distills them; defer to them and to the Official
Rules on any detail. Information will arrive haphazardly; ask clarifying questions
as it does.
