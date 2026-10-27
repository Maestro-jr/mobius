# themob: build progress

Authorization-gated mobile attack-surface intelligence engine (desktop, all-Python).
Source of truth for scope: `TOPMOBILE-build-plan.md` ("TOPMOBILE" = old working name).

**Resume rule:** read this file at the start of every session and continue from the
first unchecked box.

---

## Locked decisions

| # | Decision | Note |
| - | -------- | ---- |
| 1 | UI is **PyQt6**, reusing HiveDefend's shell conventions | frameless window, QSS theme, sidebar + QStackedWidget |
| 2 | Graph is **native `QGraphicsView`**, adapted from TOPRECON's `EntityGraphView` | HiveDefend and TOPRECON *both* render graphs this way, neither uses Cytoscape.js/QWebEngine, and PyQt6-WebEngine is not installed. Renderer is isolated in `app/widgets/graph_view.py` so a web renderer can replace it later. |
| 3 | Everything Python; engine on a background `QThread`, heavy work in Docker workers | no FastAPI/HTTP layer |
| 4 | Data model is fixed: Pydantic v2 + `0001_init.sql` | do not regenerate |
| 5 | Third-party tools invoked **arms-length** (subprocess/REST), never imported | sandbox boundary == licensing boundary |
| 6 | License: **GPL-3.0** (open source) | required by PyQt6; switch to PySide6 if this must ever close |
| 7 | Theme is **violet**, keyed to the MOB mark's ring | one exception: the severity ramp stays semantic (critical red -> low green). A console that colours risk for aesthetics misreports. `INFO` is violet, since it carries no urgency. |
| 8 | The logo is the **shipped artwork** at `themob/app/assets/mob-logo.png` | installed with `python tools/install_logo.py <image>`, which keys the background out and crops to the mark. Drawn **as supplied. No added halo or outline**; the lockup carries its own hexagon edge. It is a full lockup (hexagon + photo + wordmark), so it needs ~58px to read: the title bar is 64px to fit the artwork, not the artwork squeezed into the bar. A painted fallback in `app/widgets/logo.py` covers a checkout with no asset, and that one *does* get a halo. |
| 9 | The code browser is **Qt-native**, not Monaco | the plan called for Monaco, which needs a web view; a Java `QSyntaxHighlighter` keeps the no-bundled-JavaScript rule and loads files lazily. |
| 10 | **No em dashes** anywhere: code, comments, docs, UI strings | also no en dashes, curly quotes, ellipsis characters or arrow glyphs. They read as machine-written. Recast the sentence rather than swapping one dash for another. Enforced globally by `~/.claude/hooks/house_style.py`, which blocks the write. |
| 11 | **MobSF is reached over REST, in its own container, and never imported** | Decided 2026-09-03, before the Phase 2 adapter exists, because the boundary is architectural and retrofitting one means rewriting the adapter. No MobSF source is vendored here and no MobSF output format is re-implemented: the adapter reads its JSON and maps it onto themob's canonical weakness keys like any other tool. The licences are already compatible (themob is GPL-3.0 via PyQt6); the boundary protects the *option* in decision 6, since an arms-length MobSF survives a move to PySide6 and a linked one does not. |
| 12 | **Three chrome bands, and the step has to be visible** | Dark rail and footer, the page, a lighter title bar. Docker Desktop separates its sidebar from its content by tone and it is what makes the layout legible without a border. The first attempt put the rail 4.7 luminance points below the page, which passed a threshold and failed an eye: both were near black and there was nowhere darker to go, so the fix was lifting the *page*. The gap is 9.8 now and the test floor is 8. Bands are chrome only; content keeps one ground, or this becomes cards by another name. |

---

## Phase 0: Foundations

- [x] 0.1  `storage/db.py`: SQLite connection (`PRAGMA foreign_keys = ON`), migration runner
- [x] 0.2  `storage/workspace.py`: per-project artifact workspace on disk
- [x] 0.3  `storage/repositories.py`, CRUD for projects / entities / edges / findings / jobs / audit
- [x] 0.4  `audit/attestation.py`: authorization attestation + append-only audit log
- [x] 0.5  `adapters/base.py`: the `Analyzer` interface, `Target`, `RawResult`, `AnalyzerResult`
- [x] 0.6  `sandbox/runner.py`: Docker runner: read-only mount, `--network none`, cpu/mem/pids/time limits
- [x] 0.7  `workers/androguard/`: Dockerfile + entrypoint emitting JSON on stdout
- [x] 0.8  `adapters/androguard_unpack.py`, first adapter: App / Component / Permission entities
- [x] 0.9  `orchestrator/`: events, pipeline (one stage), job persistence
- [x] 0.10 `app/`: theme, titlebar, sidebar, main window shell
- [x] 0.11 `app/panels/overview.py`, Overview reading real data
- [x] 0.12 `app/widgets/graph_view.py`, attack-surface graph
- [x] 0.13 `app/auth_gate.py`: authorization gate blocking the pipeline
- [~] 0.14 **Verify the vertical slice**: intake APK -> androguard -> entities in graph -> Overview renders
      - [x] the whole path is covered by tests with a stubbed sandbox (`tests/test_pipeline.py`)
      - [x] the Overview and graph render real project data (`tests/test_ui.py`, screenshots)
      - [x] a real, parseable APK fixture is generated, not downloaded (`tests/fixtures/`)
      - [x] the live end-to-end test is written (`tests/test_integration_docker.py`, `-m docker`)
      - [x] **done.** Docker's startup failure was orphaned socket entries under
            `%LOCALAPPDATA%\Docker\run\` and `%LOCALAPPDATA%\docker-secrets-engine\`
            that Windows lists but will not stat or delete. The individual file
            cannot be renamed *or* deleted, but renaming its parent directory
            aside and recreating it empty works, and Docker 4.77 recreates the
            orphan on every start, so this is a per-start workaround, not a
            cure. The durable fix is turning off Docker's Model Runner /
            Inference manager, which is the component that leaks the socket.
- [x] 0.15 `tests/`: storage, fingerprint, sandbox-arg, adapter-normalize tests green

## Phase 1: Static MVP, Android

- [x] 1.1  apktool adapter (resources + decoded manifest)
      - jar pinned to 2.11.1 and verified by SHA-256 at image build time
      - `--no-src`: resources and the plain-text manifest only, jadx owns code
      - emits artifacts + App enrichment, no findings (that is 1.3's job)
      - live end-to-end assertions written; they run under `-m docker`
- [x] 1.2  jadx adapter + code browser panel
      - jadx pinned to 1.5.3 and verified by SHA-256 at image build time
      - `--no-res` (apktool owns resources), `--show-bad-code` (partial output beats a hole)
      - class index written to a file, not stdout: a large app has tens of thousands
      - `Target.app_key`: jadx never reads the manifest, so the orchestrator hands it
        the App node's key: otherwise it forks a second App keyed by hash
      - `app/panels/code.py` + a Qt-native Java highlighter (no Monaco, no web view)
- [x] 1.3  config / manifest auditor (debuggable, allowBackup, cleartext, exported, NSC)
      - `knowledge/android-weaknesses.json`: the canonical weakness catalogue,
        built first because a fingerprint keyed on a tool's own rule name never
        merges. The pack sits at the repo root beside `workers/` and `shared/`,
        per the plan's §13; `themob/knowledge/` is the loader that validates it
        and refuses to start on a duplicate key or a bad severity.
      - MASWE ids and Mobile Top 10 left `None` rather than guessed; 1.11 imports
        the real mapping pack. A wrong standards reference is worse than none.
      - runs **no container**: it judges the graph the unpackers built rather than
        re-opening attacker-controlled XML in the engine process
      - `AnalysisContext` + `Analyzer.wants_graph`: the read model is built per
        analyzer and only on request, since it costs a full graph read
      - its own verdict document lands in `raw/config-audit/`, so themob's own
        findings cite tool output exactly like a third party's
      - false-positive guards, each tested against the real manifest: the launcher
        activity, a permission-guarded receiver, a signature-level custom
        permission, and an unresolved NSC reference (claims nothing either way)
- [x] 1.4  gitleaks + apkleaks adapters (Secret entities)
      - [x] gitleaks worker, pinned to 8.30.1 and verified by SHA-256 at build
      - [x] `adapters/gitleaks_scan.py`, Secret entities + findings, stage 3
      - [x] four canonical secret weaknesses in the pack, split by what the hit
            actually costs: private key and cloud credential are critical, a
            named service key is high, a generic entropy hit is medium
      - [x] scans `artifacts/` only. The APK is never mounted: the text was
            already extracted by tools built for it
      - [x] the secret value never enters themob. The worker returns a redacted
            match and a SHA-256; the tester reads the real value from the cited
            file. A console that copies live credentials into its own database
            and then its report has made two more places to leak them from
      - [x] one node and one finding per distinct credential, with each place it
            appears attached as evidence. Rotating the key fixes every copy, so
            a report listing it eight times is a worse report. Leaving the file
            out of the fingerprint is also what lets a second tool agree
      - [x] apkleaks worker + adapter, pinned to 2.6.3 with jadx 1.5.3 baked in
            so it never tries to download one under --network none
      - [x] **the strings.xml gap is closed.** apkleaks finds the Stripe key in
            res/values/strings.xml that gitleaks cannot match, and the strict
            xfail that held the gap open is now a real assertion
      - [x] **the two scanners converge.** One canonical mapping serves both, so
            gitleaks' `aws-access-token` and apkleaks' `Amazon_AWS_Access_Key_ID`
            reach the same weakness, the same node key and the same fingerprint.
            The credential is one node with one finding carrying both tools in
            `sources`, which is the agreement signal the scorer will read
      - [x] links and bucket names are deliberately left alone: they are not
            secrets, and 1.7 reads them from the persisted raw output
- [x] 1.5  semgrep adapter (mobile rulesets)
      - [x] the fixture can express call sites. `Method.invokes` emits a real
            invoke-static, so jadx recovers
            `Cipher.getInstance("AES/ECB/PKCS5Padding")` and
            `MessageDigest.getInstance("MD5")` as ordinary Java
      - [x] `knowledge/semgrep/`: themob's own rule pack, where the plan's §13
            puts rule packs. Every rule declares `metadata.themob-weakness`, so
            finding identity never depends on what a rule is called, and a test
            asserts every key resolves against the weakness catalogue.
      - [x] `workers/semgrep/`: rules baked in at build time. The container has
            no network, so a registry-configured run would either fail or scan
            with nothing loaded and call every app clean. The worker refuses to
            run with an empty rule directory for the same reason.
      - [x] **The `semgrep-core` question is answered.** It is a platform wheel
            holding the OCaml matcher semgrep shells out to; `pip install
            semgrep` on a base without a matching wheel installs the Python half
            alone, producing a semgrep that runs and matches nothing. Built FROM
            the vendor image instead, with a build-time check that both halves
            are present.
      - [x] `adapters/semgrep_scan.py`: one finding per (weakness, file), not
            per line. CryptoUsage nodes wired to the App.
      - [x] `sandbox/build.py` grew a `stage.txt` hook, because Docker cannot
            COPY from outside the build context and the rules live in
            `knowledge/` on purpose. Duplicating them under `workers/` would
            mean two copies drifting apart.
      - [x] 37 unit tests, 6 integration tests, image built and verified
      - [x] **The rules do fire.** Both match the fixture's decompiled Java on a
            live run. Confirmed, not assumed.
      - [x] semgrep image pinned by digest, as workers/sbom does
- [x] 1.6  syft + grype adapters (Library entities, CVE findings)
      - [x] `workers/sbom/`: syft + grype in one image, both pinned by digest,
            grype's vulnerability database baked in at build time
      - [x] **themob catalogs Android dependencies itself.** syft has no Android
            cataloger: it reports zero artifacts for an APK, and zero for a
            directory of META-INF markers, because its Java support reads inside
            JAR archives and an APK has none. Verified by running it, not assumed.
            The worker reads the two conventions Android really carries and hands
            grype a CycloneDX SBOM built from them.
      - [x] `adapters/sbom_scan.py`: Library entities + EMBEDS edges + CVE
            findings. Severity comes from the advisory, not the house default.
      - [x] fixture carries real dependency evidence, one clean and one with a
            published advisory, so "found a library" and "found a vulnerability"
            can be told apart
      - [x] CVE findings link to their Library node via the pipeline's
            `type:key` placeholder, so the graph can be asked what reaches a
            vulnerable dependency
      - [x] 39 unit tests, 10 integration tests, image built and verified
      - [x] **grype's real JSON matches the parser.** Passed on the first live
            run, so the schema assumption held.
- [x] 1.7  endpoint extractor (Endpoint / CloudAsset entities)
      - [x] **No second extractor.** apkleaks already runs LinkFinder over the
            package in stage 3, and its worker passes URL-shaped hits through
            unredacted for exactly this stage. Re-scanning would duplicate a
            tool themob already runs at arms length.
      - [x] **The work is judgement, not extraction.** On this fixture
            LinkFinder returns seven hits and three are not endpoints: the
            `schemas.android.com` XML namespace that every Android package
            carries, the bare path `/order`, and `AES/ECB/PKCS5Padding`, a
            cipher transformation that happens to contain slashes. Feeding
            those to a recon engine would have it scanning the W3C on behalf
            of every app, which is how an integration gets switched off.
      - [x] Every rejection is recorded with a reason in the verdict document.
            A filter nobody can inspect is a black box, and the first question
            a tester asks is why a URL they can see is not in the report.
      - [x] Cloud stores are classified apart from APIs: a named bucket that
            may be world readable is a different question from an API the app
            talks to. Six providers, and both S3 addressing styles.
      - [x] URLs normalise to one form (case, port, trailing slash, query
            dropped) so two spellings of one endpoint are one node
      - [x] `android.network.cleartext-endpoint`: distinct from the policy
            check, because a plaintext URL in the code is evidence the app
            really does address a host that way
      - [x] runs no container: its input is JSON another worker already
            produced in one
      - [x] 42 unit tests, 7 integration tests
- [x] 1.8  `normalize/`: canonical weakness keys, dedup + cross-tool voting, confidence
      - [x] **The weakness key is now stored** (migration 0003). It only ever
            fed the fingerprint, which is a SHA-256 and therefore one-way, so
            a stored finding could not say what class of issue it was. Two
            adapters happened to put it in `finding_sources.rule`; the other
            four put the tool's own rule id there, which is what that column
            means. 1.11 and 1.13 both need this.
      - [x] **Each reporter's own confidence is stored** (migration 0004).
            The merge keeps the higher of two, so the weaker opinion was gone
            the moment two tools agreed. Voting asks how likely it is that
            *every* reporter is wrong, which that value cannot answer.
      - [x] `normalize/voting.py`: noisy-or over reporters, so agreement
            raises confidence with diminishing returns and never reaches 1.
      - [x] **Agreement only counts across detection methods.** gitleaks and
            apkleaks both run regular expressions over the same decompiled
            text: they share their blind spots, so both firing is close to one
            detector reporting twice. Counting it as two votes would raise
            confidence most on the findings most likely to be a shared false
            positive. Reporters are grouped by method, the strongest wins
            within a method, and only those are combined. Verified on the real
            package, where both scanners do find the same AWS key.
      - [x] the pass runs after every analyzer, never between them: scoring
            mid-run would make the result depend on stage ordering
      - [x] it reports findings whose weakness no pack defines, which is an
            adapter bug that would otherwise reach a report unmapped
      - [x] severity is left alone. That is the scorer's job (1.11), and two
            stages adjusting one number is how a rating stops being explainable
      - [x] 23 unit tests, 6 integration tests
- [x] 1.9  `correlate/`: build the full graph, pivots
      - [x] `sections.py`: the plan's left-nav as data, not screens. A section
            is a query ("Network & API is entities WHERE type IN (Endpoint,
            CloudAsset)"), and the panel that draws it is a consequence. Kept
            out of `app/` because the report (1.13) needs the same grouping
            without importing Qt.
      - [x] a finding is filed by **what it is about**, not by the stage that
            found it: a hardcoded key is a Secrets finding whether semgrep or
            gitleaks noticed it. Every finding lands in exactly one section,
            so a total across sections is a real total.
      - [x] a type claimed by two sections is refused at import, and a test
            asserts no type is left without a home
      - [x] `pivots.py`: entry points, exposure and attack paths. An app's
            attack surface is not its findings, it is the findings something
            else on the device can reach.
      - [x] **The App node is not a conduit.** The first version traced
            exposure on the undirected view, reasoning that themob's edges
            record a relationship rather than a direction of control. True of
            one edge, wrong for a path: every entity hangs off the App, so the
            traversal walked up from any exported component and back down into
            every unrelated branch, and everything came out exposed. Directed
            traversal is both correct and what the edges already mean.
      - [x] a deep link seeds from the component it routes into, since
            `Activity --declares--> DeepLink` means descending from the link
            itself reaches nothing
      - [x] a permission-guarded component is still an entry point: a
            permission narrows who may knock, it does not remove the door
      - [x] `handoff.py`: the TOPRECON export, grouped by host because a recon
            engine works per host. Private addresses are marked rather than
            dropped, and nothing is included that the app did not name.
      - [x] 29 unit tests, 4 integration tests
- [x] 1.10 Section panels render as graph projections
      - [x] **One panel, seven projections.** The plan lists seven left-nav
            destinations, and writing seven near-identical files would have
            been the obvious mistake. They are one screen over seven queries,
            so `SectionPanel` is configured by a `SectionView`.
      - [x] the nav entries are generated from `correlate.sections`, not a
            second hand-written list that could disagree with the queries
      - [x] **the Exposed column** carries 1.9's work into the UI. Severity
            says how bad a finding would be; exposure says whether anything
            outside the app can reach it, and it is the only coloured thing on
            the row because it is the one that changes what a tester does
            first. Tooltip gives the hop count from the entry point.
      - [x] entities are listed below the findings, because what shipped is
            worth reading even when nothing is wrong with it
      - [x] two defects found by rendering it and looking: Qt reads `&` in
            button text as a mnemonic marker, so "Network & API" drew as
            "Network _API"; and stretch factors left a dead gap under a short
            findings table. Tables now size to their rows and the page scrolls.
      - [x] 6 UI tests, `docs/screens/themob-section.png`
- [x] 1.11 `scoring/` + `knowledge/`, severity, MASVS / MASWE / MobileTop10 mapping
      - [x] **OWASP Mobile Top 10 (2024) mapped** for all 19 weaknesses, with
            the reasoning for each recorded beside it in the pack
      - [x] **MASWE ids are still null, on purpose.** Unlike the ten Top 10
            categories, MASWE ids are specific numbers that cannot be derived
            from the weakness itself, and they could not be verified against
            the OWASP source from here. Writing plausible ones would put a
            wrong standards reference in a pentest report, which is worse than
            a missing one. The loader carries the field, so filling it from
            https://mas.owasp.org/MASWE/ is a data edit with no code change,
            and a test fails the moment an id appears so it has to be
            deliberate. **This is the one part of 1.11 left open.**
      - [x] **Exposure now adjusts severity**, which is what 1.9 and 1.10 were
            building toward. One level, upward only, with the reason stored:
            "raised from high because an exported entry point reaches it
            directly". A rating a report cannot explain in a sentence is one
            nobody trusts.
      - [x] **It never lowers a severity.** Failing to find a path is not
            evidence that no path exists; themob may simply not have looked in
            the right place. Downgrading on that turns a gap in the analysis
            into a reassurance.
      - [x] **Confidence never touches severity.** How likely a finding is to
            be real and how bad it would be are different axes; folding them
            into one number loses both. Confidence feeds the risk ranking.
      - [x] `base_severity` (migration 0005) makes the pass idempotent by
            construction. Severity is stored, so raising from the stored value
            would compound on every run. A CVE also keeps the advisory's
            rating as its base, which is more specific than the pack default.
      - [x] two bugs caught by the tests: NaN survives `min(max(x, 0), 1)`
            because every comparison with it is false, and my own tie-break
            test asserted the wrong premise
      - [x] 22 unit tests, 5 integration tests
- [x] 1.12 Finding detail + manual-validation workflow (confirm / FP / accept risk)
      - [x] **A verdict is an auditable event, not a database update.** It
            lands in the hash-chained trail beside the authorization
            attestation, because "who decided this was a false positive, and
            when" is the question a disputed report turns on, and an answer
            living only in a mutable column is not an answer.
      - [x] **False positive and accepted risk are refused without a reason.**
            They are the verdicts that remove a finding from the report, and
            an unexplained removal cannot be told apart from an oversight. The
            engine refuses it; the panel disables the button so the refusal is
            not a surprise after the click.
      - [x] an unattributed verdict is refused too: an audit record with no
            actor answers none of the questions it exists for
      - [x] notes accumulate rather than replace (migration 0006). The
            sequence of a doubt, a reproduction attempt and the client's
            answer is often the useful part.
      - [x] **the score rationale sits next to the severity**, not in a
            tooltip. The scorer may have raised the rating, and a tester who
            cannot see why has no way to argue with it.
      - [x] MASWE renders as "not mapped" rather than blank, because that
            says the pack has no verified id rather than that none exists
      - [x] a verdict never touches severity, confidence or the mapping: a
            human conclusion is recorded beside the evidence, not over it
      - [x] findings open from the Overview and from any section panel; both
            now emit the fingerprint, so one handler serves them
      - [x] 17 validation tests, 8 UI tests, 2 integration tests
- [x] 1.13 `report/`: HTML / JSON export with provenance header
      - [x] **One document, two renderings.** `report/model.py` assembles the
            report once and the writers only lay it out. Building each format
            from the database separately is how the number on the page stops
            matching the number in the export.
      - [x] **The HTML is self-contained.** No fonts to fetch, no scripts, no
            images. A report is opened six months later on a machine that has
            never heard of themob, and one that needs the network to render is
            one that will eventually render blank. It shares `app/theme.py`,
            which is Qt-free, so the console and the report cannot drift into
            two palettes.
      - [x] **No secret value can reach either export.** The workers redact
            before anything leaves the container, so themob holds no plaintext
            to leak, but the export asserts it anyway: "we do not store it" and
            "it cannot appear here" are different claims and only the second
            one is about this file.
      - [x] **Dismissed findings are counted, not dropped.** They leave the
            body and get their own section with the verdict, the reason and who
            recorded it. A report that silently omits them is one nobody can
            audit.
      - [x] **The provenance header says what it does not know.** An analyzer
            that failed is named as incomplete coverage, a missing attestation
            is called out, and a chain that no longer verifies is stated on the
            first page rather than left to read as normal.
      - [x] tool versions travel with the report, pulled from what the adapters
            stored: a finding is only reproducible against the tool that made it
      - [x] exporting is itself an audited event. A report leaving the tool is
            the moment findings about someone's app become a file that can be
            forwarded.
      - [x] the JSON is sorted throughout, so two exports of an unchanged
            project differ only in `generated_at` and the diff is readable
      - [x] `report/` imports without PyQt6, so a headless export stays possible
      - [x] `Export` carries the report back with the paths, so the console can
            describe what it wrote without assembling it a second time
      - [x] **Found by writing it:** `FindingRepository._insert` never wrote
            `risk` or `score_rationale`, so a `Finding` that arrived carrying a
            score lost it silently. Only the scorer's `UPDATE` path had ever
            set them.
      - [x] the report's prose agrees with its numbers ("1 endpoint", not
            "1 endpoints"), derived from the plural labels in `theme` rather
            than a second map that could disagree with them
      - [x] wired into the console: "Export report" sits under the run controls,
            off until there is a project and off again mid-run, and the
            confirmation repeats the report's own caveats
      - [x] 25 report tests, 6 UI tests, 2 integration tests
- [x] 1.14 Ship + verify Phase 1
      - [x] **The wheel was broken, and nothing would have told you.** A built
            wheel carried none of the weakness packs, none of the semgrep rules
            and not the logo, because they live at the repository root by
            design and setuptools only ships the package tree. An installed
            copy could not key a single finding. Found by building one and
            installing it, which is the only way this ever surfaces.
      - [x] the packs now install to `share/themob/` and the loader resolves
            `THEMOB_KNOWLEDGE_DIR`, then the checkout, then the installed
            prefix; `app/assets/*.png` is package data
      - [x] `python -m themob --check`: a preflight that starts no container
            and needs no display. Python, the three imports and their versions,
            the packs and their MASWE gap, the semgrep rules, the migrations
            applied to a throwaway database, the logo, a writable workspace,
            the daemon, and every image the **registry** asks for.
      - [x] **the image check asks the registry, not `workers/`.** Each
            analyzer names its own image, and an installed copy has no
            `workers/` yet runs perfectly well on images already built.
            Checking the directory would fail every install that is not a git
            checkout.
      - [x] a missing image is a failure, not a warning: themob has no host
            fallback, so the stage is skipped, and a skipped stage reads
            exactly like a clean one
      - [x] **the report now names the themob that made it.** The tool versions
            say what found each finding; `themob_version` says what correlated,
            scored and wrote them up, which is a different question when a
            report is disputed a year later.
      - [x] version 1.0.0. Phase 1 is the shippable v1 the plan describes.
      - [x] README brought current: the real pipeline, the report, the
            preflight, the test markers, and a **Known gaps** section naming
            the three things Phase 1 does not do rather than leaving them to be
            discovered
      - [x] proven end to end from an installed wheel in a clean venv: the
            preflight passes and a full report exports, with the packs resolved
            from `share/` and no checkout in sight
      - [x] the console script now goes through `__main__`, not straight at
            the GUI entry: pointing it at `app.main` meant `themob --check`
            silently ignored the flag and opened a window
      - [x] **the authorization gate had no test at all.** The engine half
            (`require_authorization`, the attestation) was covered; the dialog
            and the `authorize` call that binds it to intake were not, and that
            is the one control every other safeguard here assumes held. Now
            tested for what it refuses: a sample with no attestation, an
            attestation not ticked, a file that is not a package, and a
            rejected attestation that must leave nothing on disk while staying
            in the trail.
      - [x] 17 preflight tests, 14 authorization-gate tests
      - [x] **verified green on the shipping tree:** 705 unit tests
            (`-m "not docker"`, 1m36s) and 88 container tests (`-m docker`,
            46m31s) against real workers, plus the console rendered offscreen,
            the gate built offscreen, and a full report exported from an
            installed wheel in a clean venv
      - [x] **LICENSE.** themob is GPL-3.0-or-later and the repository had no
            copy of the licence text, which the GPL requires to accompany the
            work. gnu.org was unreachable from here and from the operator's
            machine, so the text was taken from the complete copy numpy bundles
            and verified rather than trusted: 35,149 bytes, sha256
            `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`,
            matching the size the interrupted download itself reported.

## Notes

### Found by running it for real (2026-09-01)

The first live container run paid for itself immediately:

* **The androguard image shipped without androguard.** `--require-hashes=false`
  is not a pip flag, so pip exited non-zero, and a trailing `|| true` turned that
  into a successful build. All three Dockerfiles now verify their tool at build
  time and none of them swallow a failure.
* **The graph read model lost parallel typed edges.** `GraphSnapshot` used a
  `nx.DiGraph`, which collapses `App --declares--> X` and `App --exports--> X`
  into one edge: under-reporting the relationship count and losing the
  distinction the graph exists to carry. Now a `MultiDiGraph` keyed by edge type.
* **A permission enforced by a component but never requested had no node**, so
  the edge from the component dangled and was dropped. `android:permission` on a
  Receiver names a permission the *caller* must hold; it is attack surface
  whether or not the app requests it.
* **The fixture's `readPermission` resource id was wrong** (`0x01010004` is
  `manageSpaceActivity`). A wrong id does not yield a wrong name. It yields a
  different attribute, and the one you meant silently vanishes.
* **The pinned jadx checksum was computed from a truncated download.** The hash
  matched a corrupt 34 MB file that is not a valid zip; the real archive is
  111 MB. The build's `sha256sum -c` caught it, which is the entire point of
  pinning. When bumping a pin, open the archive before trusting its hash.
* **Both JVM workers died before reading the sample.** jadx and apktool take
  `user.home` from a JVM property, not `$HOME`, and uid 65534 has no passwd
  entry, so it resolved to `/`, and jadx tried to create `/.config` on the
  read-only root filesystem. Fixed with `-Duser.home=/tmp` in both images.
* **A worker's own diagnosis was masked by the sandbox's exit code.** "exited
  with code 1" replaced "Failed to read zip entry: classes.dex". The sandbox
  message now only outranks the worker's for a sandbox-level failure, a
  timeout or an output flood.
* **A null from a later analyzer erased what an earlier one found.**
  `json_patch` is RFC 7396, where a null member *deletes* the key. androguard
  reads the network-security-config reference out of the manifest; apktool then
  writes null for the same attribute whenever it cannot resolve the file, so
  the reference vanished, and the config auditor would have reported "no NSC"
  for an app that declares one. The merge now strips nulls: absence of
  knowledge in one tool must not destroy another tool's knowledge. Explicit
  nulls still survive on *insert*, because `exported_declared = None` means the
  manifest omitted `android:exported`, which is itself worth auditing.
* **Every offscreen screenshot was lying about the UI.** Qt's `offscreen`
  QPA plugin exposes *zero* font families on this box, so every glyph came out
  as tofu and text metrics ran about twice as wide as reality, pushing panels
  off the right edge. Renders now use the real platform plugin with
  `WA_DontShowOnScreen`, which lays the window out fully without ever mapping
  it to the screen. `tools/render_ui.py` does this reproducibly; output lands
  in `docs/screens/`.
* **A guessed attribute id silently became a different attribute.**
  `android:networkSecurityConfig` was written as `0x010104ED`, one past
  `usesCleartextTraffic`. That id is `lockTaskMode`, so apktool decoded the
  manifest as `android:lockTaskMode="@xml/network_security_config"` and the
  auditor saw no NSC at all. The real id is `0x01010527`. All 21 ids in
  `ATTRIBUTE_IDS` are now checked against the framework resource table that
  ships inside apktool, and the other 20 were right. This is the second time
  this exact trap has been hit in this fixture, which is why the module comment
  about it exists.
* **The class index pointed at paths that did not resolve.** The jadx worker
  writes paths relative to its own `/output` mount, and every other path in the
  adapter got the `artifacts/jadx/` prefix except the per-class ones inside the
  index, so the code browser resolved `sources/...` against the project root and
  found nothing. Invisible until the DEX became real: the tests that would have
  caught it were skipping because jadx could not decompile the stub.
* **A test asserted the wrong thing about `--no-res`.** It required jadx's
  `resources/` directory not to exist. jadx creates it either way; the flag
  governs what goes into it. The assertion is now that it stays empty.
* **The Phase 0 fixture ran every stage, not phase 0's.** `slice_run` called
  `pipeline.run()` unscoped, so every adapter added to a later stage silently
  joined the Phase 0 slice. Registering jadx is what exposed it: a test named
  for phase 0 began failing for a phase 2 reason. The fixture is now scoped to
  `Stage.UNPACK`, the only stage its assertions actually read.

### Found by running gitleaks for real (2026-09-01)

* **The built image was a version behind its own source.** `analyze.py` had
  already dropped `--redact`, with a comment explaining why, but the image was
  built before that edit. gitleaks writes the literal string `REDACTED` into
  its report under that flag, so every secret hashed to the same digest, every
  finding shared one identity, and the graph would have shown a single secret
  no matter how many the package held. A regression test now asserts distinct
  digests and specifically refuses that placeholder hash. Rebuild a worker
  image after touching its entrypoint: the source being right is not the same
  as the tool running it.
* **The fixture's AWS key was AWS's own documentation key.** Every scanner
  worth using allowlists `AKIAIOSFODNN7EXAMPLE`, so the suite would have
  passed while asserting that a secret scanner found no secrets. Changed to a
  fake that is not allowlisted, with a test pinning the old one out.
* **Two apktool tests were asserting a world without a resources.arsc.** Once
  the fixture gained one, apktool started resolving resource references, and
  it also moved `versionCode` and `versionName` out of the decoded manifest
  into `apktool.yml`, which is where it keeps them so a rebuild can restore
  them. The tests now assert the resolved `@xml/network_security_config` and
  read the version info from `apktool.yml`. The same change let the config
  auditor find two more real findings on the fixture, a user-trusted CA anchor
  and a per-domain cleartext override, both now asserted end to end.
* **gitleaks does not match a secret sitting between XML tags.** It flags
  `analytics_key = "sk_live_..."` in a .txt, a .java and a .xml, but not
  `<string name="k">sk_live_...</string>`. `res/values/strings.xml` is where
  Android apps really keep API keys, so this is a blind spot in the tool
  rather than a problem with the fixture. Recorded as a strict `xfail` so it
  fails loudly the day apkleaks closes it.

### syft cannot see Android dependencies (2026-09-02)

The build plan names "syft to grype" for SBOM work. Run against the real
fixture, syft returns `"artifacts":[]`, and its cataloger list has no Android
entry at all. Pointed at a directory holding
`META-INF/androidx.core_core.version` and a shaded
`META-INF/maven/<group>/<artifact>/pom.properties`, still zero: its Java
support reads *inside* JAR archives, and an APK has none, because Gradle
merged every dependency into `classes.dex` before shipping.

Taking the plan at its word here would have produced a stage that ran, passed,
and found nothing, for every app, forever. The failure mode looks like good
news, which is the kind worth probing before building on.

So the worker catalogs the two conventions Android actually carries and hands
grype a CycloneDX SBOM built from them. grype accepts a hand-built SBOM: that
was verified first, against gson 2.8.5, before any of this was written. syft
stays in the image for the cases it does cover, an embedded JAR or a
recognisable binary, but it is no longer the thing the stage rests on.

### The scan that ran clean without running (2026-09-02)

1.5's three integration assertions existed for one reason: to catch a SAST
stage that runs, passes, and finds nothing. On the first live run they caught
exactly that. Three faults, stacked:

* **semgrep never started.** `PermissionError: /.semgrep`. uid 65534 has no
  passwd entry, so its home resolved to `/` and the log directory could not be
  created on the read-only root. The same shape as the jadx `user.home` bug.
  `HOME`, `XDG_CONFIG_HOME` and the semgrep settings path now point at the
  tmpfs, and the worker recreates them at startup because the sandbox mounts a
  fresh tmpfs over `/tmp` after the image is built.
* **The worker reported the crash as a clean scan.** The serious one.
  `json.loads(completed.stdout or "{}")` turned empty output into a valid
  document with no results. semgrep exits 1 for "findings found" and Python
  exits 1 on a traceback, so the exit code could not settle it. Empty output
  is now a failure, and the document must carry a `results` key.
* **The build check proved nothing.** It ran `semgrep --version` as root,
  before `USER 65534`. The build now compiles the rules and scans a sample
  carrying both weaknesses **as the runtime user**, failing unless both fire.
  That check immediately found two more problems on its own: the config
  directories did not exist, and root's `settings.yml` was unreadable by uid
  65534.

The rules themselves were correct from the start. Once semgrep could run, both
matched on the first honest attempt. The only real change after that was
cosmetic: semgrep prefixes rule ids with the config path, so findings recorded
as `opt.themob.rules.themob-weak-cipher-mode`, leaking the container's
directory layout into the report. Stripped in the worker, derived from
`RULES_DIR` so moving the rules cannot quietly bring it back.

The lesson is the one the plan keeps making: a green suite is not evidence a
scanner works. Only an assertion that a known-bad input produces a known
finding is.

### Window chrome, after Docker Desktop (2026-09-02)

Six changes, all taken from what Docker Desktop does well:

* **Rounded window corners.** `WA_TranslucentBackground` plus a radius on
  `#root`, so the corners are cut rather than painted over. The title bar
  rounds its top pair and the footer its bottom pair, or they paint square
  over the radius and it reads as a rendering fault. Squares off when
  maximised, since a rounded maximised window leaves notches on the desktop.
* **The title bar is lighter than the page**, the one band that is. It reads
  as window chrome rather than document, which is what makes the rounding
  look deliberate. This is a considered exception to the one-ground-colour
  rule, not a drift away from it.
* **Window controls are painted, not typed.** They were text glyphs in a
  QPushButton, so the font set the weight and `-` sat on the text baseline
  instead of the middle. Now 1px strokes in a 10px box on 46x32 hit areas,
  the Windows standard. The close button rounds its top-right corner to
  match the window and squares off when maximised.
* **The sidebar toggle appears on hover only.** A round control straddling
  the rail's edge, parented to the body rather than the sidebar so the
  sidebar cannot clip its own control. The glyph is a panel with one side
  filled, which says which way the panel moves.
* **Collapsed run controls keep a glyph.** Analyze and Stop kept their text
  labels on the 52px rail, so they rendered as two blank buttons that were
  still live and still clickable. They become their glyphs and keep their
  tooltips.
* **The window has an icon.** Without `setWindowIcon` themob was a blank
  placeholder in the taskbar and on hover, next to every other program.

### The DEX fixture learned to make a call (2026-09-01)

`tests/fixtures/dex.py` could only emit `return "constant";`, so the package
held strings and no code. semgrep matches call sites, so 1.5 would have been
asserted against an app with nothing to match.

Adding one static call with a string argument needed a parameterised proto,
which needed a `type_list` item in the data section and a matching map entry,
plus external method references in `method_ids`.

* **The bug worth remembering: an under-length instruction still assembles.**
  `invoke-static` is format 35c and takes three code units; emitting two
  produced a valid-looking DEX where every following opcode was shifted one
  unit. jadx read the next instruction as the register operand and reported a
  call on `r12` in a method with one register. Nothing checks this: the file
  passes its checksum, the class loads, and only a decompiler notices.
  The integration test now asserts the method bodies came back and that no
  `JADX ERROR` block appears, because a refused method still writes a .java
  file and asserting the file exists proves nothing.

### Found by running apkleaks for real (2026-09-01)

* **`python -m apkleaks.cli` silently does nothing.** Its `cli.py` defines
  `main()` and has no `if __name__ == "__main__"` guard, so running it as a
  module imports the file, executes no scan, and exits 0. The console script
  is the entry point. A tool that fails by succeeding is the worst kind.
* **apkleaks deletes its own report when it matches nothing**, so a missing
  file means either a clean scan or a crash. Only a non-zero exit is treated
  as a failure now; reporting an error on every clean app is crying wolf.
* **Its rules disagree about delimiters.** `Amazon_AWS_Access_Key_ID` returns
  the key with a leading quote while `AWS_API_Key` returns it bare, so one
  credential hashed two ways and appeared as two nodes. It also broke
  agreement with gitleaks, which captures the bare value. The worker strips
  captured delimiters before hashing.
* **`Amazon_AWS_S3_Bucket` is not a credential.** The rule name contains
  "aws", so the credential heuristic redacted a bucket URL: hiding what the
  endpoint stage wants and claiming a leaked credential that was not there.
* **A trailing `|| true` swallowed a failed pip again.** The androguard
  Dockerfile carries a comment about exactly this and the apkleaks one still
  repeated it, shipping an image with no apkleaks in it. Installing now gets
  its own layer; only cache trimming is allowed to fail.

### Fixture gaps

**Closed: the DEX.** `tests/fixtures/dex.py` builds a real, decompilable
`classes.dex` (format 035) holding the four classes the manifest names, with
sorted string/type/proto/method tables, real bytecode and a map list. jadx
decompiles it, so the four reverse-engineering tests that used to skip now
assert instead. Its constants are chosen for what comes next: an HTTPS endpoint
and a cleartext one for the endpoint extractor (1.7), and secret-shaped strings
for gitleaks and apkleaks (1.4).

**Closed: the resource table.** `tests/fixtures/arsc.py` builds a real
`resources.arsc`, so apktool decodes "with resources" and emits a `res/` tree
(`values/strings.xml`, the layout, the network security config) instead of
nothing. The manifest references the NSC by resource id, so the config auditor's
network-security-config checks now run end to end rather than in unit tests
only.

Both fixture gaps are closed. The generated APK is now a coherent package: every
component the manifest names is a class in the DEX, and every resource it
references is in the table.

* Two schema/DB bugs were found and fixed while wiring Phase 0, both with
  regression tests: `audit_log.project_id`'s `ON DELETE SET NULL` cascade was an
  UPDATE that the append-only trigger aborted, making any audited project
  undeletable (migration `0002`); and `executescript()` COMMITs before it runs,
  so migrations were not atomic.
* Two UI bugs were found by rendering the window and looking at it: the graph
  fitted to a not-yet-laid-out viewport and never re-fitted, and the Overview
  read a pre-attestation copy of the project.
* Two more found the same way while building the mark: `setClipRect` defaults to
  `ReplaceClip`, so the noir plate escaped the hexagon; and the graph's spring
  layout ignored the viewport's aspect, wasting most of the canvas.
* `read_class_index` called `Workspace.resolve` on all 40,000 indexed classes,
  a syscall per class the tester will never open, 35s in tests. The structural
  check is now a string check; the authoritative containment check runs at the
  moment a file is read, which is also where symlinks are caught.
* The apktool worker's `read_meta` would have returned nothing on every real
  `apktool.yml`: apktool tags the document `!!brut.androlib.meta.MetaInfo` and
  `yaml.safe_load` refuses unknown tags. Fixed with a tag-tolerant SafeLoader
  that still refuses object construction. Both behaviours are tested.

## Phase 2: Correlation and intelligence

Started 2026-09-03, after Phase 1 shipped and verified.

- [x] 2.1 `sandbox/`: service mode, a long-lived container on an isolated network
      - [x] **the obvious design does not work, and the one it forces is
            stronger.** Publishing the service port to `127.0.0.1` and having
            the engine speak HTTP to it is what you would write first. Docker
            refuses to publish a port from an `--internal` network, which was
            a favour: the alternative is a client container on the *same*
            internal network, writing its JSON to `/output` like any other
            worker. So the engine never opens a socket to a hostile service,
            and the sample never touches a network with a route out.
      - [x] the hole in the invariant is "two containers can talk to each
            other", not "a container can reach the network"
      - [x] `--network none` is still the default on every existing worker,
            asserted by a test, so the invariant cannot erode by omission
      - [x] the network name is validated like every other string that reaches
            argv: it is the one that decides whether there is a network at all
      - [x] joining a network buys a network and nothing else: read-only root,
            dropped capabilities, `no-new-privileges`, uid 65534, memory and
            pid limits all still apply, asserted against a live container
      - [x] teardown in a `finally`, container before network, and it runs when
            the body raises and when readiness times out. A leaked container
            holds a copy of someone's app.
      - [x] a readiness timeout reports the container's own logs. "It timed
            out" on its own sends the reader to the wrong place, and this
            caught a real mistake within a minute of being written: the probe
            image's entrypoint is its analyzer, so the service needed an
            entrypoint override the spec did not yet have.
      - [x] 10 unit tests, 5 container tests, including that the network really
            has no route out and that DNS really does not resolve off it,
            proven against a live daemon rather than against the argv
- [x] 2.2 MobSF adapter (REST, sandboxed), held to locked decision 11
      - [x] **every rule id written from memory was wrong.** All four. MobSF
            v4.3.2 calls them `allowbackup_not_set`,
            `exported_intent_filter_exists`, `android_aes_ecb` and
            `android_md5`, not the names that seemed obvious. The mapping is
            now read off a live scan by `tools/probe_mobsf.py`, which is kept
            so the next image bump is a re-read rather than another guess.
      - [x] **a canonical key is not enough: the place has to match too.** A
            fingerprint is the weakness plus the location, so a MobSF finding
            naming the same weakness somewhere else becomes a *second* finding
            and the report shows one problem twice at half the confidence
            each. Every mapping entry now declares the scope the config auditor
            would use, and a test compares the two fingerprints against the
            real auditor rather than a copy of it.
      - [x] a rule themob cannot place is dropped and counted, not emitted:
            better to say nothing than to report the same problem twice. The
            App node carries `not_mergeable` beside `unmapped` so both are
            visible rather than quietly absent.
      - [x] **MobSF is not one witness.** It is a manifest reader, a pattern
            matcher and a certificate parser under one name, so it reports as
            `mobsf/<section>` and the voting model maps `mobsf/manifest` to the
            same method as `config-audit`. Their agreement therefore does not
            raise confidence, which is correct: both read the same manifest.
      - [x] the fallback for an unrecognised section collapses onto the tool
            name, not onto the shared default. Landing in "other" would have
            invented the independent corroboration the whole model refuses,
            and the first version did exactly that.
      - [x] pulled, not built, and pinned by digest: rebuilding someone else's
            GPL server here would be vendoring it in all but name. The pull
            verifies the image carries the digest asked for before tagging it,
            which is the checksum guarantee the built workers get.
      - [x] **a third-party image does not fit a worker's hardening profile.**
            MobSF ships its own unprivileged user and owns its home, so uid
            65534 leaves it unable to read its own files and a tmpfs over that
            home masks the installation outright, which is how the first
            attempt failed. `user` and `read_only` are per-service and
            explicit; everything carrying the containment still applies and
            cannot be opted out of, and the service is never given a mount of
            the sample at all.
      - [x] a fresh 32-byte API key per run, so no credential outlives the
            container that used it
      - [x] the adapter owns the service spec and the test uses it rather than
            a copy, because a copy is how a test and the thing it tests drift
      - [x] both images are required for the analyzer to report ready: a client
            with no server would have arrived as an empty scan
      - [x] the preflight now asks each analyzer whether *it* is ready instead
            of looking its image up, which is what made the two-image case
            correct without a special case
      - [x] **found by running it:** a transient `docker image inspect` timeout
            was cached as "the image is missing", permanently, and told the
            operator to build an image they already had. Only a real answer is
            cached now.
      - [x] 19 unit tests, 2 container tests against a live MobSF
- [x] 2.3 Data-flow enrichment, source to sink
      - [x] **it is not dataflow analysis, and the module says so in its own
            docstring.** No SSA, no aliasing, no interprocedural anything. It
            reads the Java jadx already decompiled, finds the identifier a
            flagged literal was assigned to, and looks at where that identifier
            appears. The notes it writes say "appears where it is sent as an
            HTTP header", never "flows to", because a report that overstates
            its method is worse than one that omits it.
      - [x] the question it answers is the one voting cannot: two findings a
            scanner reports identically, `KEY = "AKIA..."` never referenced
            again and `KEY = "AKIA..."` passed to `setRequestProperty`, are not
            the same finding
      - [x] **corroboration is a vote; its absence is not.** Reaching a sink
            enters the existing noisy-or model as a `dataflow` vote, so one
            model still decides confidence. Never being referenced is the
            absence of evidence, which cannot be a negative vote, so it is a
            bounded discount with a floor: a secret nothing references is still
            compiled into the package and still extractable.
      - [x] sink categories are weighted. An Authorization header says far more
            about a value being a live credential than a log line does, and a
            model that treated them alike would be easy to argue with.
      - [x] **confidence, never severity.** Reaching a sink says the reporting
            tool was right about what it found. How bad that is belongs to the
            scorer, which raises for reachability from an exported entry point.
      - [x] runs between normalize and score, and the order is the design:
            normalize recomputes confidence from the votes every run, so this
            always starts from a freshly voted number and re-running converges
            instead of drifting upward. Asserted by an idempotency test.
      - [x] fills `Finding.data_flow`, a field the locked model reserved from
            the start, replacing rather than appending so a re-run does not
            grow the same path every time
      - [x] "I could not look" is never reported as "I looked and found
            nothing": a missing file, an unreadable line, an identifier too
            noisy to follow and a path outside the workspace are all
            undetermined, and undetermined changes nothing
      - [x] a path that escapes the workspace is refused, not clamped: it came
            from a tool that parsed a hostile package
      - [x] only weaknesses with a value worth following are traced. A
            debuggable manifest flag has nothing to follow, and tracing it
            would invite a meaningless discount on a fact read from the
            manifest.
      - [x] bounded throughout: file size, files searched, uses collected and
            steps recorded all have ceilings, and crossing one reports
            undetermined rather than a partial answer
      - [x] 21 tests
- [x] 2.4 TOPRECON handoff
      - [x] **this is the one place a mistake stops being a wrong finding and
            becomes scanning somebody's servers without permission.** themob
            learns every host a package contacts; TOPRECON maps infrastructure
            and probes it actively when told to. Nothing in a package says who
            owns any of it: a shopping app contacts its own backend, Google,
            Facebook, a payment provider and three ad networks.
      - [x] **so the handoff refuses to decide.** `scope_domains` is exported
            empty, by design, and it is the field TOPRECON reads to decide what
            it may pivot into. A human fills it or nothing is touched.
      - [x] `first_party_candidate` is derived from the package name, which is
            a reverse domain by convention and a lie whenever the developer
            felt like it. It is a hint that shortens a review list, and the
            document says in a field a reader cannot miss that it is never an
            authorization.
      - [x] a known third-party host is never marked a candidate, so the list a
            human reads stays short enough that they actually read it
      - [x] the attestation travels with the document: ref, operator and the
            sample digest, so the recon run inherits the engagement it came from
      - [x] a private address is not handed over at all. It is somebody's LAN,
            not an internet asset, and pointing a recon engine at one aims it at
            a network it cannot reach and should not try to.
      - [x] **coming back, results enrich the endpoint that already exists**
            rather than adding nodes. The locked model has no entity type for
            an address or a certificate, and "this endpoint resolves here and
            runs these services" is a property of the endpoint anyway.
      - [x] a re-import converges: the keys are the ones themob already
            assigned, so the entity upsert merges instead of duplicating
      - [x] a host TOPRECON found that the app never calls is reported as
            unmatched, not adopted. Recon finds more than an app talks to, and
            that surplus is not the app's attack surface.
      - [x] the import treats the file as untrusted throughout: it came from a
            program that talked to the internet. A malformed document fails
            whole rather than half-importing, and hostile node content is
            bounded rather than trusted.
      - [x] no import of TOPRECON anywhere. The two are separate programs that
            exchange a file, which is the same arms-length rule every other
            integration here follows.
      - [x] 18 tests
- [x] 2.5 Richer graph pivots and saved queries
      - [x] **not an expression language.** The obvious design is a filter
            string that gets parsed, and it is wrong twice over: a parser over
            operator-supplied text is a surface nobody asked for, and a general
            language means every consumer implements its own half of it. What
            ships is a small fixed predicate set that composes, and no operator
            in it can run anything.
      - [x] ten built-in questions, because a query builder handed over empty
            is a feature nobody uses. Exported components with no permission,
            secrets something outside can reach, cleartext endpoints, the
            triage queue, dangerous permissions, and the rest.
      - [x] **an unset attribute is unknown, not false.** "falsy" matches an
            attribute explicitly set false and never one nobody set. Reporting
            an unknown as False is how a scanner invents facts.
      - [x] a match carries its reasons, so "why did this match" is answered by
            the result rather than rediscovered by the reader
      - [x] the build plan's own pivot example, everything reachable from one
            node, is `pivot_from` and uses the directed graph
      - [x] **a saved query that this version cannot honour exactly is refused,
            not narrowed.** A row can outlive the code reading it. Dropping a
            clause silently answers a *broader* question, and for "exported
            components with no permission" that means quietly returning every
            component while still looking like it worked.
      - [x] a saved query cannot shadow a builtin key: the collision would
            silently change what the builtin does, so it is refused by name
      - [x] a corrupt row is reported. "Your saved query is corrupt" is an
            answer; returning nothing is not.
      - [x] saved queries are not scoped to a project, deliberately. A saved
            question is a way of working, not a fact about one APK, and
            re-scoping it per project means recreating it for every app it was
            invented to be run against. Migration 0007.
      - [x] a Questions page in the console: builtins and saved questions kept
            visually apart, because they answer to different people
      - [x] 25 engine and storage tests, 9 UI tests

### A note on the order

The plan lists MobSF first and that order is kept, but 2.1 exists because of
it. MobSF is the one tool in the roadmap that cannot run with the network off,
and "nothing untrusted is parsed in-process, nothing reaches the network" is
themob's central claim. Widening it is a security change, so it is its own item
with its own tests rather than a flag added quietly inside an adapter.

If that hole turns out to be wider than it looks, 2.3 and 2.4 are both
independent of MobSF and can ship without it.

## Phase 3: Dynamic analysis

Started 2026-09-04, after Phase 2. Built and unit-tested the same day; its live
paths await a device (see the note at the end of 3.3 and 3.5).

Phase 1 and 2 never execute the sample. Phase 3 does, and that changes what
themob is: an app under test sends real requests to real servers, ADB is a
shell on a device, and Frida injects into a running process. The containment
story that carried the static pipeline does not carry any of that, so the
policy comes first and the tools attach to it, exactly as 2.1 preceded 2.2.

**Status: the module, the gate, and every decision that can be made without a
device are built and tested (83 dynamic tests, plus two preflight checks). What is deliberately not proven
is the live behaviour: spawning Frida against a running process and terminating
TLS through mitmproxy need a real emulator, and the equivalent of the Docker
integration suite waits for one. The seams are built so that suite drives
exactly what an operator runs.**

- [x] 3.1 `dynamic/`: the execution gate
      - [x] **static analysis needs one attestation; running the app needs
            three more.** Reading a package and executing it are different acts
            with different victims, and treating one permission as covering
            both is how an assessment quietly becomes an incident.
      - [x] **the device clause protects a person, not a company.** A test
            device is a burner; a phone with somebody's mail and banking on it
            is not, and running a hostile package beside real data has a victim
            who never agreed to anything. themob cannot check what a device
            holds, so it makes the operator say it by name in a record that
            outlives the project.
      - [x] **traffic is its own permission.** Executing an app sends live
            requests to the client's backend and to every third party it
            embeds. That is interaction with production systems, and an
            engagement covering "read this binary" frequently does not cover it.
      - [x] **the interception scope is entered by hand and defaults to
            nothing.** An empty scope decrypts nothing rather than everything.
            A host nobody listed is a host nobody authorised, the same rule the
            TOPRECON handoff follows for the same reason: themob knows what an
            app talks to and not who owns it.
      - [x] a wildcard is refused outright. `*`, `all`, `0.0.0.0/0` and the
            rest would mean "terminate everyone's TLS", which is the one thing
            this list exists to stop somebody typing by accident. `*.x.com`
            points at `.x.com` instead, because a star is too easy to write
            wider than intended.
      - [x] `example.com.evil.net` does not match `.example.com`: suffix
            matching is on a dot boundary, not a string ending
      - [x] a refused attestation is never recorded. A rejection that left a
            row behind would read as permission that had been granted.
      - [x] the gate fails closed on anything unexpected, including a
            hand-written audit row missing a clause, and one project's
            attestation never carries over to another
      - [x] `Action.EXECUTION_AUTHORIZED` lives in the audit vocabulary, not
            inlined, per that module's own rule
      - [x] 19 tests
- [x] 3.2 `dynamic/adb.py`: device discovery and control
      - [x] **there is no default device.** Every call names a serial and the
            serial must be the attested one. A lab with three phones plugged in
            is normal, and "themob picked the wrong one" is a sentence nobody
            should have to say. An unattested serial is refused even when it is
            the only device connected.
      - [x] **nothing goes through a shell.** argv lists only. A serial arrives
            from a USB descriptor and a package name from a hostile APK, so
            neither is trusted with quoting; both are pattern-validated before
            they can reach `adb`.
      - [x] **no privilege escalation.** `root`, `unroot`, `remount`,
            `disable-verity`, `reboot`, `tcpip` and `sideload` are refused by
            name rather than merely unimplemented, so adding one is a
            deliberate act. A rooted phone answers questions about a rooted
            phone rather than about the app.
      - [x] `install` re-checks the gate itself rather than trusting a caller
            to have done it: it is the one verb here that cannot be undone by
            re-running something
      - [x] **`adb install` prints "Failure" and exits 0**, which is how a
            failed install passes for a working one. Both are checked.
      - [x] a device that is unauthorized or offline is reported rather than
            filtered out, and the message says to accept the prompt on the
            device. "No devices found" with a phone plugged in sends the
            operator looking in the wrong place.
      - [x] `looks_like_a_daily_driver` is a hint for the UI, not a decision: a
            stock user build with verified boot is what a shop sells. It is
            never a substitute for the attestation, and says so.
      - [x] the preflight learned `adb`, as a warning rather than a failure.
            Phases 1 and 2 never need it, and a preflight that cries wolf over
            a tool nothing has asked for teaches an operator to ignore it.
      - [x] 18 tests, plus one preflight test
- [x] 3.3 Frida and objection, attached to a gated device
      - [x] **the agent is a file this repository owns.** Loaded from
            `dynamic/agents/` on disk, never fetched at runtime, never taken
            from the app. A downloaded agent is a downloaded exploit, and "the
            instrumentation script came from the thing being instrumented" is a
            sentence that should be impossible to write.
      - [x] `resolve_agent` guards twice: the name must look like a bare `.js`
            filename, and the *resolved* path must stay inside `agents/`. The
            second is the real check, since `..`, absolute paths and symlinks
            all survive a pattern that only reads the string. Every traversal
            case is tested and refused.
      - [x] **the agents observe, they do not disable.** observe-crypto watches
            Cipher, MessageDigest and SecretKeySpec; observe-tls watches the
            trust managers and pinning. Hooking crypto to alter it would make
            the app under test a different app.
      - [x] **the agents never emit key or certificate bytes**, only lengths
            and algorithm names. An assessment tool, not a key logger, and a
            test asserts the shipped source stays that way.
      - [x] objection's bounded jobs (SSL bypass, pinning search, root-detection
            bypass) are a named map; loading a raw Frida script is a separate,
            sharper call that says so, and still only loads from `agents/`
      - [x] nothing reaches a process without `adb.bind`, so instrumentation
            runs only on the one serial the gate attested
      - [x] **the runnable seam is isolated in `FridaSession._launch`.** Every
            check that does not need a device is tested here; the one thing that
            genuinely needs an emulator is the only thing behind it. `run`
            re-checks the gate, because a plan is a value that can be held and
            the attestation must still hold when it fires.
      - [x] agents ship as package data; 16 tests
      - [ ] **live verification is deferred.** Frida and objection cannot be
            proven without a real device or emulator, and there is none here.
            The equivalent of the Docker integration tests waits for one; the
            seam is built so that test drives exactly what an operator would.
- [x] 3.4 mitmproxy capture, with an attach-your-own-Burp option
      - [x] **the interception scope from the gate is law.** Terminating TLS
            for a host reads traffic that may belong to somebody the engagement
            never named, so only hosts in scope are decrypted and everything
            else is relayed untouched. Out of scope means passthrough, not
            block: the app behaves normally and no third party is silently
            MITMed.
      - [x] **the addon and the gate cannot drift.** The scope filter runs
            inside mitmproxy's own interpreter and cannot import themob, so it
            carries a copy of `host_in_scope`. A test loads both and asserts
            they agree across a battery of hosts and scopes: the copy is
            allowed, drifting is not. `host_in_scope` was extracted to one
            place so `may_intercept` and the addon share the same rule.
      - [x] **the addon fails closed.** An unreadable or missing scope file
            means intercept nothing, never everything, which is the one reading
            that must not go the wrong way.
      - [x] the scope travels as a file the addon reads, not on the command
            line: a path on argv is a path a shell could touch, and this one
            decides what gets decrypted
      - [x] **themob reads the addon's own JSON log**, so it never parses
            mitmproxy's binary format and the "which hosts were decrypted"
            record is one themob owns. A passed-through host yields no flow,
            because it was never decrypted and there is nothing to have seen.
      - [x] the capture log is treated as untrusted, like everything from a
            running hostile app: a malformed line is skipped, the parse never
            raises on content
      - [x] **attach-your-own-Burp**: themob runs no proxy and decrypts
            nothing, records that capture is delegated and to where. A
            pentester's Burp setup is theirs, not something to duplicate.
      - [x] a scoped capture tells the operator to install the CA and says
            plainly that a pinned release defeats it regardless, which is the
            seam back to the SSL-unpin job in 3.3
      - [x] an empty scope is a real mode: record which hosts the app contacts,
            decrypt none of it
      - [x] the live proxy is the one seam left for a device; everything else
            is tested. addon ships as package data. preflight learned
            mitmproxy as a warning. 16 tests.
- [x] 3.5 dynamic findings merge into the same graph and schema
      - [x] **a runtime finding is an ordinary Finding.** Same schema, same
            graph entities, same fingerprint construction. Built any other way
            it would sit outside the correlator, the scorer and the report,
            which is exactly where it must not sit.
      - [x] **the merge is the whole payoff, and it works.** A weakness watched
            at runtime builds its fingerprint from the canonical key and the
            observed value, the same construction the static adapters use, so
            "we watched it happen" lands on the same fingerprint as "semgrep
            suspected it" and the storage upsert folds them into one finding
            with two sources. Asserted directly.
      - [x] **`runtime` is a method that shares a blind spot with nobody.**
            Every static reporter reads code or the manifest; this one watched
            the app run. So frida agreeing with semgrep is two independent
            methods converging, the strongest corroboration the voting model
            can express, and it raises confidence where a second static reader
            of the same code would not. Both asserted against `combine`.
      - [x] **a runtime observation confirms; it rarely accuses alone.**
            Watching AES/GCM is not a finding; watching DES, RC4, ECB, MD5 or
            SHA-1 is. A secret-key or pin-check observation is behaviour for the
            tester to weigh, not an accusation on its own.
      - [x] cleartext seen on the wire is a finding mitmproxy can make with
            confidence: a plain-HTTP request was observed, not suspected, and it
            merges with the static endpoint extractor's cleartext key and links
            to the endpoint entity when the graph has one
      - [x] the same weakness seen a hundred times is one finding, not a hundred
      - [x] the Frida event stream is parsed as untrusted: only `themob-observe`
            lines are read, ready/error are not observations, a malformed line
            is skipped. It came off a hostile app's process.
      - [x] agents emit lengths and algorithm names, never key or certificate
            bytes, so the findings built from them cannot carry secrets either
      - [x] 14 tests
      - a runtime finding is a Finding with a canonical weakness key like any
        other, so voting merges "semgrep thought so" with "we watched it
        happen", which is the strongest agreement themob can express

## Post-Phase-3 hardening (senior-researcher top 10)

A review of the whole project at the end of Phase 3 produced ten things worth
adding before iOS. Worked in the order 1, 2, 3, then the rest; all ten are done.
iOS (Phase 4) was then built on top of them and is complete (see the Phase 4
section above).

- [x] 1. **Wire Phase 3 into the pipeline and console.** Until now the dynamic
      engine was reachable only from Python. `dynamic/session.py` is the
      coordinator: it re-checks the execution gate, resolves the App and
      endpoint nodes, builds findings from Frida output and captured traffic,
      upserts them so a runtime observation merges by fingerprint with the
      static finding that suspected it, and re-runs voting and scoring so the
      new corroboration lifts confidence. A `Stage.DYNAMIC` job row makes the
      run show up in the report's provenance. The console gains a **Dynamic**
      panel: attest the device/traffic/interception scope, list devices,
      prepare the exact command to run, and import the result to merge it. The
      device still runs the command; themob prepares and records. 8 session
      tests, 5 panel tests.
- [x] 2. **CI (`.github/workflows/ci.yml`).** Three jobs: the hermetic suite on
      Python 3.11 and 3.12 with offscreen Qt; a clean-room wheel install that
      imports the report and dynamic paths with no Qt present and checks the
      knowledge packs shipped; and a pinned gitleaks scan. A portable
      typography gate, `tools/check_typography.py`, enforces the no-em-dash
      rule independent of the author's global hook, and `tests/test_typography.py`
      makes the suite fail on a violation too. A `.gitleaks.toml` allowlists the
      test fixtures' deliberately fake keys so the scan flags only real leaks.
- [x] 3. **Headless `themob scan` CLI plus SARIF export.** `themob/cli.py` runs
      the whole static assessment without a window: `python -m themob scan
      app.apk --engagement ENG-1 --fail-on high`. It records the authorization
      attestation the same way the console gate does (the gate is not skipped
      for being headless), writes the report, and exits 0 / 1 / 2 so a build
      step can gate on it. `report/sarif.py` emits SARIF 2.1.0 with a rule per
      canonical weakness, a `security-severity` number so GitHub ranks the ramp,
      and each finding's stable fingerprint as a `partialFingerprint` so a
      triaged issue is not re-reported as new. `export()` writes it by default,
      so the console gets it too. 10 SARIF tests, 9 CLI tests.
- [x] 4. **Vulnerability-feed freshness in the provenance header.** grype
      matches against a database baked into the worker image, and a stale one
      turns "no vulnerable dependencies" into a silent false negative. The
      database build date now travels from grype's own `descriptor.db.status`
      through the sbom adapter onto the App node and into the report's
      provenance, which states how old it was and warns past
      `VULN_DB_STALE_AFTER_DAYS` (7). Absent when no dependency scan ran, so the
      report says "we do not know" rather than fabricating freshness. Carried in
      HTML, JSON and SARIF. 8 tests.
- [x] 5. **Baseline and diff across app versions.** `report/diff.py` answers
      "what changed since the last release", the question a triaged programme
      actually asks. The stable fingerprint makes it a set operation: new,
      resolved, persisting, plus the attack-surface delta (new endpoints, new
      permissions) when comparing two projects. `themob diff a.json b.json`
      compares two report files; `themob scan --baseline prev.json` gates the
      build on newly introduced findings only, ignoring inherited debt, which
      is the pattern every code scanner settled on. Suppressed findings count
      as known, so a dismissed issue that returns does not re-gate. 9 diff
      tests, 4 CLI tests.
- [x] 6. **Native code analysis (a `.so` worker).** androguard listed the
      native libraries; nothing looked inside them. The `nativelib` worker
      reads each `.so`'s ELF headers in the sandbox (reading `/scan`, never the
      APK, with a small hand-rolled reader that executes nothing) and reports
      the exploit mitigations: executable stack, RELRO level, stack-canary and
      fortify symbols. The adapter turns a missing mitigation into a finding on
      the same NativeLib node, keyed by the in-APK path so it merges rather than
      forks. Severities are conservative (executable stack medium, no RELRO low,
      no canary info): a missing mitigation weakens a defence, it is not itself
      a vulnerability. New weakness pack `android-native-weaknesses.json`, new
      `binary` voting method. 9 worker tests, 11 adapter tests. Live container
      run deferred like the others until the image is built.
- [x] 7. **Source-to-sink taint over the decompiled code.** `dataflow/trace.py`
      followed a flagged value only one hop: it checked whether the identifier
      the literal was bound to appeared at a sink. A secret copied through a
      local or two before being sent slipped through as "used", not "reaches a
      sink", which is the exact false negative a tester most wants caught. It
      now runs a bounded textual taint fixpoint: an assignment whose right-hand
      side names a tainted identifier taints its left-hand side, repeated up to
      the step ceiling, so SECRET -> token -> header -> setRequestProperty is
      connected. The honesty holds: it is co-mention on an assignment line, not
      real dataflow, so a hop reads "copied into" and a sink "appears where it
      is sent", never "flows to". The assignment chain is recorded as
      propagation steps in the finding. An unrelated local never carries the
      taint. 3 new tests; the single-hop contract still passes.
- [x] 8. **A tamper-evident deliverable (manifest + optional signature).**
      themob hash-chains its own audit trail; this extends that property to the
      files that leave the tool. `export()` now always writes a `manifest.json`
      listing every deliverable file with its SHA-256, a single digest over the
      raw evidence, and the tip of the audit chain at export time. `themob
      verify <dir>` recomputes the hashes and catches any edit; a changed or
      missing file is named. On top of that, `report/signing.py` adds an
      optional Ed25519 detached signature (`themob scan --sign key.pem`), so a
      recipient verifies authorship, not just integrity, with the bundled or a
      trusted public key. cryptography is an optional `[sign]` extra: without
      it the manifest still stands on its checksums, and the difference between
      tamper-evidence and tamper-proofing is stated, not blurred. `manifest` and
      `signing` import with no Qt and no cryptography. 8 deliverable tests, 5
      CLI tests.
- [x] 9. **Secret validation, opt-in and separately gated.** A leaked-credential
      finding is a hypothesis until someone proves the secret is live, and that
      proof means touching a third party, so it gets its own authorization, apart
      from the assessment's. `validate/gate.py` requires a `ValidationAttestation`
      (operator, engagement ref, explicit acknowledgement, scope note) recorded as
      a `VALIDATION_AUTHORIZED` audit event before any probe is planned; without it
      `require_validation()` refuses. `validate/providers.py` classifies a secret
      to a provider and holds only read-only, side-effect-free probes (aws `sts
      get-caller-identity`, github/gitlab/slack/stripe identity reads) with the
      secret left as a `<SECRET>` placeholder: themob never holds the plaintext and
      never runs the probe, it prepares the command for the operator. `planner.py`
      records the outcome back onto the finding, CONFIRMED when live, ACCEPTED_RISK
      when the operator revoked it, a note when inconclusive, through the existing
      orchestrator so the audit chain covers it. The classifier is tight on
      purpose: a loose token match that mislabelled `high-entropy` as a GitHub
      token was fixed to require a real provider marker. 20 tests.
- [x] 10. **Rule-pack extensibility with signing.** The catalogue was fixed at the
      shipped packs; an operator with house rules had to fork. Now
      `THEMOB_KNOWLEDGE_EXTRA` points at extra pack directories, but a pack decides
      a finding's severity and its canonical key, so loading whatever is on disk is
      a real risk. The loader answers with signatures: in strict mode
      (`THEMOB_KNOWLEDGE_STRICT`) an extra pack loads only with an Ed25519 signature
      from a key listed in `THEMOB_KNOWLEDGE_PUBKEYS`; outside strict mode an
      unsigned pack still loads but the load records that it was unverified, which
      the preflight surfaces, so provenance is never hidden. A tampered pack, a pack
      signed by an untrusted key, and any attempt to redefine a built-in key are all
      refused: an extra pack can add weaknesses, never shadow one the engine already
      knows. `themob sign-pack <pack> --key <priv.pem>` writes the detached
      signature, and `--generate-key` makes the keypair. The Ed25519 primitives moved
      to `themob/_signing.py`, shared with the report-manifest signer so neither
      package imports the other, and verification degrades to "not verified" when
      cryptography is absent rather than silently passing. 13 tests.

## Full command-line interface

Done 2026-09-24. The console was one way in; now every capability the window
exposes is a subcommand of `themob`, driving the same engine, gate, storage and
audit trail with no PyQt6 imported at all. One entry point (`themob/cli.py`), a
single argparse dispatcher, no new dependency.

- **The extraction that made it Qt-free.** The only logic trapped behind a Qt
  import was the authorization gate's intake-plus-attestation-with-rollback,
  which lived in `app/auth_gate.py`. It moved to `themob/orchestrator/authorize.py`
  (`GateDecision`, `authorize_target`), and the window's `authorize()` is now a
  thin adapter over it, so the two share one implementation rather than the CLI
  reimplementing the gate. A test proves the headless import pulls in no PyQt6.
- **Every GUI capability has a command.** `doctor` (the preflight), `projects`,
  `authorize`, `analyze`, `report`, `overview`, `section`, `findings`, `finding`,
  `verdict`, `graph`, `entity`, `code`, `query` (list/run/save/delete), `audit`,
  `analyzers`, `dynamic` (devices/status/authorize/prepare/import-frida/
  import-capture), `handoff` (export/import), `validate` (authorize/plan/record),
  `build-workers`, `gui`, plus the pre-existing `scan`/`diff`/`verify`/`sign-pack`.
  `scan`/`diff`/`verify`/`sign-pack` keep their stable entry points and are routed
  to them by `__main__`; everything else, and `--help`, goes through `cli.run`.
- **The gates are not softened for being headless.** `authorize` asks for the
  attestation in the terminal and refuses without a `--yes` when there is no
  terminal to ask at; `analyze` still fails closed on an unauthorized project;
  `dynamic` and `validate` each keep their own second and third gate. All of it
  is the same audit trail.
- **Reads like a console, not a landing page.** A pure-ASCII banner that survives
  the Windows codepage; ANSI colour that turns itself off for a pipe, for
  `--no-color`, or for `NO_COLOR`, and switches VT on at the Windows console
  first; the severity ramp stays semantic. `--no-color` and `--home` work before
  or after the command. Exit codes are 0/1/2 for a pipeline to branch on.
- **Degrades, never crashes.** No Docker, no adb, an unbuilt image, a missing
  key: each is a message and a clean exit, and `doctor` is the command whose
  whole job is to say what is missing.
- Launchers `themob.sh` / `themob.cmd` find a working Python and run the package
  from a checkout; `pip install` gives the `themob` console script. 14 tests in
  `test_cli_console.py`, on top of the existing `test_cli.py`; a bounded live run
  exercised all 30-odd commands end to end.

## MCP tool server

An agent (REA, Claude, or themob's own assistant) drives the same contained
tools through the Model Context Protocol. `themob/mcp/tools.py` holds the
capabilities as plain functions that import neither the MCP SDK nor Qt;
`themob/mcp/server.py` wraps each as a FastMCP tool, and `themob mcp` /
`python -m themob.mcp` serve them over stdio. 18 tools: the read-only reads
(projects, overview, findings, finding, section, graph, entity, code, queries,
audit, analyzers, doctor) and the gated ones (authorize_target, analyze, scan,
record_verdict). The gate is not softened for an agent: the gated tools refuse
without `attested=true`, an operator and an engagement, and every one appends to
the hash-chained audit trail exactly as the CLI's `--yes` does; `analyze`
refuses an unauthorized project. The SDK is an optional extra (`themob[mcp]`),
and only `server.py` imports it, so the engine, the CLI and the window run
without it. 13 tests in `test_mcp.py` drive the tools directly with a stubbed
sandbox, and one confirms the server registers the catalog.

## REA reverse-engineering handoff

themob measures native libraries and decompiles Java, but does not reverse the
logic inside a native binary or an obfuscated class. REA
(github.com/morluto/rea) does, with LLM agents, which is non-deterministic and
reaches the network, so it sits beside the pipeline, not in it, like the
TOPRECON handoff. `themob/rea.py` has two gated, audited halves: `prepare`
resolves a chosen native library or decompiled class to its file in the
workspace, copies it into a handoff bundle with themob's context, and returns
the exact `rea` command; `import_summary` attaches what REA reported back as a
note on a finding, marked `[external: rea]`, changing no severity, confidence or
status. themob never imports `rea-agents` and never reaches the network itself.
Exposed as `themob rea prepare` / `themob rea import`, and as the `rea_prepare` /
`rea_import` MCP tools. Two new audit actions (`rea.prepared`, `rea.imported`).
8 tests in `test_rea.py`.

## AI assistant

The contest-facing product: an explain-and-fix surface on top of the
deterministic engine. `themob/assist/` is Qt-free and model-agnostic. `core.py`
reads the real findings through the MCP tool layer in-process
(`themob.mcp.tools`), builds a briefing of only what themob found, and asks a
model to explain each finding in plain language and give a step-by-step fix.
Honest data is enforced in two places, the briefing (only real findings) and the
system prompt (ground every statement, say when something was not found), so the
model cannot report a finding that is not real.

`llm.py` is provider-agnostic: an `LlmClient` protocol with an `AnthropicClient`
and an `OpenAICompatibleClient`, and a registry that auto-detects the provider
from whichever API key is in the environment (Claude, or a free OpenAI-compatible
endpoint: Groq, Gemini, OpenRouter, Mistral, Cerebras, or a local Ollama). It
sits behind the optional `themob[assist]` extra and degrades to a clear message
when no key or SDK is present.

`license.py` is a dormant gate, kept for a future paid tier: an Ed25519-signed
licence key (reusing themob's signing layer) verified against a trusted public
key. It is switched off by `ENFORCE_LICENSE = False` in `core.py`, so the app is
not licence-dependent today; flipping that one constant turns it back on with no
other change. The surface is the **Assistant** page in the console
(`app/panels/assistant.py`), which runs the call on a worker thread and renders
the no-model, no-project, ready and (when enforced) licence states on the violet
kit. `themob assist` is the licence tooling (status, generate-key, issue). 9
tests (`test_assist.py` plus a UI honesty test); the page was rendered and
checked against the kit.

## Phase 4: iOS support

iOS is read-only static analysis of an `.ipa`, mirroring the Android path:
intake detects the bundle, a sandboxed worker inventories it, an adapter founds
the graph, and the later stages (secrets, endpoints, REA handoff) read what it
produced. Five milestones, M1 first.

- [x] **M1  iOS intake and unpack.**
  - `workers/ios-unpack/` (Dockerfile + `analyze.py` + `requirements.txt`): a
    sandboxed worker that reads the `.ipa` from `/input`, parses the binary
    `Info.plist` with the standard-library `plistlib` (bundle id, name, version,
    build, minimum OS, executable, declared URL schemes, ATS policy, file
    sharing), inventories the embedded `Frameworks/` (`.framework` bundles and
    `.dylib` files), and reads the main Mach-O's hardening with `lief`
    (architectures, PIE, encryption/FairPlay, code signature, stack canary, ARC,
    NX), aggregating conservatively across fat slices. It never raises: a hostile
    bundle yields `{ok: false, error, traceback}`, never a crash.
  - `themob/adapters/ios_unpack.py` (`IosUnpackAnalyzer`): stage UNPACK,
    `platforms = (Platform.IOS,)`, `suffixes = (".ipa",)`, so it sits beside the
    Android unpackers and never competes with them. `normalize` founds the graph
    from the worker's JSON, treated as untrusted: the **App** node keyed on the
    validated bundle id (falling back to the sample hash), carrying the Info.plist
    facts the M3 auditor will judge; the embedded frameworks and dylibs as
    **LIBRARY** nodes the App `EMBEDS`; and the main Mach-O as a **NATIVE_LIB**
    node carrying the `hardening` flags M2 will turn into findings, exactly as
    `nativelib-scan` does for Android ELF `.so` files. It emits no findings
    itself: inventory and judgement stay in separate stages.
  - `lief` is imported **only inside the worker container**, never in the engine;
    the adapter uses only `plistlib` and the stdlib, so the arms-length rule holds
    and the engine still imports clean without `lief`.
  - `tests/fixtures/ipa.py` builds a real, structurally valid `.ipa` in code (a
    zip with `Payload/Demo.app/`, a binary Info.plist, a placeholder Mach-O, an
    embedded `.framework` and a `.dylib`), so the suite needs no third-party iOS
    app. 7 tests in `tests/test_ios_unpack.py` cover the fixture, intake
    detection, the worker's structural halves (plist + frameworks), and the
    adapter's `normalize`/`run`; the real `lief` Mach-O parse is exercised only
    under `-m docker`. Full hermetic suite: **1072 passed**.
- [x] **M2  Mach-O hardening.**
  - `knowledge/ios-weaknesses.json`: a new pack, auto-discovered by the loader's
    `*-weaknesses.json` glob (no loader change). Six Mach-O build-hardening
    weaknesses (`ios.macho.*`): no PIE/ASLR (medium), no NX (medium), no ARC
    (low), no stack canary (info), no code signature (low), not FairPlay
    encrypted (info). Severities are conservative, matching the Android native
    pack: a missing mitigation is a weakened defence, not a vulnerability. Each
    is MASVS-mapped (MASVS-CODE-4 or MASVS-RESILIENCE), CWE-693, M7. The
    not-encrypted entry says plainly that absence is expected off the App Store,
    so it never reads as alarm. M3's Info.plist keys will join this same pack.
  - [themob/adapters/ios_macho_audit.py](themob/adapters/ios_macho_audit.py)
    (`IosMachoAuditAnalyzer`): the iOS counterpart of `nativelib-scan`, and the
    judgement half of M1. No container: like the config auditor it carries no
    image and sets `wants_graph`, reading the `hardening` dict M1 put on the
    NATIVE_LIB node and turning each absent mitigation into a finding on that
    node. Stage REVERSE_ENGINEERING, so iOS binary-hardening findings land in the
    same report section as Android ones; iOS-only, so it never competes with
    jadx or nativelib. A flag that is `False` becomes a finding; a flag that is
    `True` or `None` (lief could not tell) does not, so themob never claims a
    weakness it did not measure. Findings carry the canonical weakness, cite the
    Mach-O node by id, and are fingerprinted `sha256(weakness_key+location)` so
    re-runs converge and cross-tool voting merges.
  - Registered in `adapters/__init__.py` beside nativelib. 12 tests in
    `tests/test_ios_macho_audit.py` (flags off, on, undetermined, no-hardening
    node, metadata/citation, info severity, fingerprint convergence, two
    Mach-Os). Full hermetic suite: **1084 passed**.
- [x] **M3  Info.plist and entitlements audit.**
  - The ios-unpack worker and adapter grew two things M3 judges: the
    code-signing entitlements, parsed out of `embedded.mobileprovision` (the
    CMS-wrapped plist is sliced out by its markers, no certificate chain trusted)
    carrying get-task-allow, provisioned-devices, team id and the entitlements
    dict; and per-domain ATS detail (`insecure_domains`). The unpack adapter also
    now founds a DEEP_LINK node per custom URL scheme (App DECLARES), mirroring
    androguard: the unpacker records the scheme, the auditor judges it.
  - [themob/adapters/ios_config_audit.py](themob/adapters/ios_config_audit.py)
    (`IosConfigAuditAnalyzer`): the iOS counterpart of config-audit. No
    container, iOS-only, `wants_graph`, stage CONFIG_AUDIT. It reads the App and
    DEEP_LINK nodes and emits findings: ATS off app-wide or for web content and
    each named cleartext exception domain (MASVS-NETWORK); each custom URL scheme
    as a hijackable deep link, cited on its DEEP_LINK node (MASVS-PLATFORM);
    iTunes/Finder file sharing (MASVS-STORAGE); get-task-allow, the debuggable
    signal (MASVS-RESILIENCE); and a bare wildcard in keychain-access-groups or
    associated-domains (over-broad entitlements). Eight new keys in the pack.
  - False-positive guards, each tested: every check fires only on an unambiguous
    signal (a flag that is exactly True, a real domain, a bare `*` or `prefix:*`
    wildcard), so an undetermined flag, a secure exception domain, a scoped
    keychain group and a named-domain subdomain wildcard all stay silent.
  - Registered in `adapters/__init__.py` beside config-audit. 20 tests in
    `tests/test_ios_config_audit.py`, plus the extended unpack and fixture tests.
- [x] **M4  secrets and endpoints on the bundle.**
  - The ios-unpack worker now decodes the bundle to the writable `/output` mount
    (zip-slip-safe and bounded), which the adapter points at `artifacts/ios`, so
    **gitleaks** and **syft/grype**, both already iOS-enabled and both scanning
    the artifacts tree, have a decoded bundle to walk. Secrets and dependencies
    on iOS need no adapter change; they only needed a tree, and now there is one.
  - apkleaks stays Android-only by design (it is an APK/jadx tool and cannot read
    an `.ipa`). Its role, pulling URLs out of the package, is filled on iOS by the
    ios-unpack worker, which scans the resources and the main Mach-O for absolute
    http(s) URLs (the iOS analog of apkleaks' LinkFinder pass) and emits them.
  - `endpoint-extract` is now platform-general: it reads apkleaks' hits on
    Android and the ios-unpack URL list on iOS, and runs both through the same
    classifier, so the identical ENDPOINT and CLOUD_ASSET nodes (and the cleartext
    finding, keyed `ios.network.cleartext-endpoint` on iOS) come out. Everything
    downstream, the graph, sections, scoring, report, MCP tools and the
    assistant, is platform-agnostic already and works on iOS unchanged.
  - Tested: worker URL scan (resources and binary), bounded zip-slip-safe
    decode, the adapter's output mount, and endpoint-extract on an iOS source
    (same node types, namespace host dropped, S3 bucket split out, iOS cleartext
    key). The live gitleaks/syft run over a decoded `.ipa` belongs to the
    `-m docker` suite; the hermetic tests cover the wiring with stubs.
- [x] **M5  REA for iOS.** Confirmed `themob rea prepare --native <Mach-O>`
  resolves and bundles an iOS Mach-O, the native-binary case REA exists for. It
  needed no change to `rea.py`: once M4 decodes the bundle to `artifacts/ios`,
  `_find_native_lib`'s path-suffix walk finds the Mach-O by its NATIVE_LIB key
  (`Payload/<app>.app/<exe>`), and the handoff bundle, context (bundle id, the
  Mach-O hardening attributes, and the M2 findings already on the node) and the
  returned `rea` command all come out as on Android. Resolves by key or by
  entity id. Two tests in `tests/test_rea.py`; the docstring now names the iOS
  case. **Phase 4 complete: 1117 hermetic tests.**

## Stability and UX pass (2026-10)

A round of field-use hardening after Phase 4, driven by real runs on large
packages. Everything here is covered by the hermetic suite (now 1160 tests).

### Three "not responding" freezes, three different causes

The PyQt UI froze on real scans, and it was not one bug. See the memory note
`project_themob_ui_freeze` for the full diagnosis. In short:

- [x] **Startup Docker sweep on the UI thread.** `load_project` probed every
  analyzer's Docker availability synchronously before the window was shown. Moved
  the whole sweep onto a background `_SandboxProbe` QThread, parented to the
  `QApplication` (not the window, so collecting a window never destroys a running
  thread, which aborts the process on Windows). The roster shows "checking" until
  the probe returns. `runner.prime_images` does one `docker images` to prime the
  cache instead of a cold inspect per analyzer.
- [x] **End-of-run ReDoS in `dataflow/trace.py`.** A nested-quantifier regex
  (`_DECLARATION`) backtracked catastrophically on a decompiled line that never
  reached `=`, so one `re.search` ran for minutes. It runs on the engine thread,
  but a C-level regex holds the GIL for the whole match, so the UI could not
  process a single event. Rewrote the pattern linear; added a one-time source
  walk and a wall-clock budget (`THEMOB_DATAFLOW_BUDGET_S`, default 20) in
  `dataflow/pass_.py` as a backstop, and lowered `MAX_FILES_SEARCHED` to 200.
- [x] **Spontaneous shutdown mid-run: a native access violation.** Not a freeze.
  `MainWindow.refresh()` rebuilt the whole NetworkX read model on the UI thread
  on every debounced `graph_changed` during a run, concurrent with the engine
  thread's own graph work. NumPy (via `spring_layout`) releases the GIL, so two
  threads in NetworkX and NumPy corrupted the heap. Fix: a `_run_active` flag;
  during a run `refresh()` short-circuits to `_refresh_live_counts()` (plain DB
  counts, no NetworkX), and the one full rebuild happens in `_on_run_finished`
  after the flag clears. `faulthandler.enable(file=...)` is how the faulting
  stack was caught.

### Adapter timeouts and path checks

- [x] **MobSF service lifetime.** Shortening the analyzer timeout also shortened
  the MobSF service container's own lifetime below its ~900s boot window, so the
  service died before it was ready. Split the two: the service gets
  `_MOBSF_READY_TIMEOUT_S` (900s) plus the analyzer timeout; the analyzer timeout
  is `THEMOB_MOBSF_TIMEOUT` (default 600).
- [x] **`jadx_decompile._contained`** rewritten to plain string checks (no
  `PurePosixPath`), rejecting absolute paths, drive letters and `..` segments.

### Secret reveal (toggle, no password)

- [x] A secret finding's evidence is masked in the UI by default, so a
  screen-share or a screenshot does not leak a credential. A **Reveal values /
  Hide values** toggle on the finding detail flips it. There is **no password**
  (removed 2026-10-16 at the operator's request): themob runs on the operator's
  own machine against an app they are authorized to assess, and the real access
  control is the app's own login, so a password here only stood between the
  operator and their own data. `app/widgets/secret_gate.py` is now just the
  reveal-state holder plus the mask/`is_secret_finding` helpers; nothing is
  persisted. `tests/test_secret_gate.py` updated.
- For gitleaks and apkleaks, the worker redacts every credential **inside the
  sandbox**: by default only a redacted preview plus a digest leave the
  container (`workers/*/analyze.py`, `redact()`; the full value is destroyed with
  the container's tmpfs). So for those findings, by default, the reveal has
  nothing fuller to show.
- [x] **Honest labeling.** `Evidence` carries a `redacted` flag. The gitleaks and
  apkleaks adapters set it on any evidence that is only a sandbox-redacted
  preview. The finding detail then shows those plainly with a one-line note that
  the full value never left the container, and offers the password reveal only
  for evidence whose full value themob actually holds, so it never fakes a reveal
  that returns the same stars. (Scans run before this flag existed read back as
  not-redacted, so a re-scan is needed for the note on old findings.)
- [x] **Opt-in full capture.** `THEMOB_CAPTURE_SECRET_VALUES` (off by default,
  set in the environment only) is forwarded by the adapter into the worker, which
  then lets the full value out so the password-gated reveal can show it. The
  decision is still made inside the container, the secret-entity node keeps only
  the redacted preview, and the full value lives only in the gated finding
  evidence. Trade-off, by design: it persists a live credential in the local
  store, it needs the gitleaks and apkleaks worker images rebuilt, and it applies
  only to new scans. See `adapters/base.py` `capture_secret_values`.

### Assistant answer quality

- [x] Answers used to shrink and vary run to run, worst in agent mode. Two
  causes: an open reasoning model (gpt-oss) spent its token budget thinking
  before it wrote, and the default temperature let the same question wander.
  `assist/llm.py` now sets `reasoning_effort="low"` on reasoning models and a low
  default temperature (`THEMOB_LLM_TEMPERATURE`, default 0.2), and the briefing
  in `assist/core.py` is compact so the answer gets the tokens.
- [x] **Full coverage (2026-10-16).** The briefing was a flat top-10 of findings,
  so a scan with 46 hardcoded-key findings had every one of them cut and the
  assistant never mentioned the secrets at all. `assist/core.py` now aggregates:
  `weakness_groups` lists every distinct weakness once with a count (the complete
  scope), and `findings` carries a bounded set in full detail (one exemplar per
  weakness). The system prompt tells the model to cover every group and use its
  count. So "46 hardcoded keys" is conveyed completely without 46 near-identical
  rows tripping a free provider's token cap.
- [x] **Secrets never go to the cloud model.** A secret finding's raw value is
  withheld from the briefing even in capture mode (`_is_secret_key` in
  `assist/core.py`): the model advises from the weakness and the count, and the
  credential stays on the machine. `tests/test_assist.py` asserts both the
  coverage and the withholding.
- [x] **Readable formatting in the narrow panel.** The answer rendered as
  garbled tables: Qt's `QTextEdit.setMarkdown` collapses a table when a cell
  holds a pipe, and every `... | grep ...` command does, merging the cells. Fixed
  both ends: the system prompt tells the model to use headings, lists and fenced
  code blocks and not tables, and `app/panels/assistant.py`
  `_flatten_markdown_tables` rewrites any table the model still emits into a list
  (splitting on column pipes only, never a pipe inside inline code), leaving
  fenced code untouched. Completeness of a 70-finding answer is a model-budget
  matter: the free Groq tier (8000 tokens/min) truncates, Gemini or Claude does
  not, so a full plan wants `GEMINI_API_KEY` (or `ANTHROPIC_API_KEY`) set.

### Navigation and window chrome

- [x] **Back control** on the finding detail is now a single button: a small
  chevron icon and the word "Back" as one click target, not a bare text link.
- [x] **Window centres itself** on first show. A frameless window is not placed
  by the OS, so it opened pinned to the top-left corner; `_center_on_screen`
  centres it in the work area once, clamped so the title bar can never go
  off-screen.

### Scan snapshots and switching

- [x] Every finished scan is already a persisted project (findings, entities and
  graph in the database under its id; artifacts in the workspace on disk), so
  there is no separate snapshot to take. An **Open scan** run-control button
  (Ctrl+Shift+O) lists the stored scans newest first (`app/widgets/scan_picker.py`)
  and reopens the chosen one restored to the exact state it finished in.
  `load_project` and the reopen path share one `_adopt(project, workspace,
  target)` helper so they cannot drift; a reopened scan whose sample is gone is
  still fully browsable (null target, only a re-run needs the sample).
- [x] **Switching away from a running scan prompts first.** `open_project`
  shows a `ConfirmDialog` (new in `app/widgets/dialog.py`) offering to stop the
  run; on yes the switch is deferred into `_pending_open` and performed by
  `_consume_pending_open` once the engine actually stops, so a live analyzer is
  never orphaned.

### Live updates during a run

- [x] **Nav badges** (findings, entities, and the per-section finding counts)
  keep moving during a scan. `_refresh_live_counts` reads the counts from the
  database and assigns findings to sections with
  `correlate.sections.counts_without_graph`, which reproduces exactly what
  `project()` computes but from entity types and the weakness key alone, with no
  NetworkX graph.
- [x] **The views themselves** (the graph, overview, sections, code) now also
  populate live, not only at the end. The badges updating while the Graph page
  sat empty was the complaint. The read model cannot be built on the UI thread
  during a run (that was the access-violation crash), so a background
  `_SnapshotWorker` builds the snapshot off-thread and the UI only draws it. All
  graph building and the one NumPy layout (`graph_view` `spring_layout`) are now
  serialised by `correlate.graph.GRAPH_LOCK`, which `build_snapshot` takes
  internally, so the engine thread's own graph builds and the console's live
  build can never run at the same moment. The live build is coalesced (one in
  flight, one more queued) and `_on_run_finished` still does the final
  authoritative rebuild once the run flag clears.

### A note on the jadx exit-125 / "unexpected EOF" failure

Seen on a large APK: `jadx ... failed: exited with code 125: ... "error waiting
for container: unexpected EOF"`. This is not a themob bug and not a jadx
out-of-memory (that would be exit 137). Exit 125 with "error waiting for
container" is the docker CLI losing its connection to the daemon mid-run, i.e.
Docker Desktop or its WSL2 backend dropped the connection or restarted under
load. The scan continues with the other analyzers; the Code page and the
decompiled-class part of the graph just will not fill for that run. Recovery is
to re-run only jadx (double-click its row in Activity) once Docker settles, or
restart Docker Desktop. See the `wsl_docker_desktop_gotchas` note.

### LLM provider

- [x] Gemini is wired as a free, OpenAI-compatible provider and is auto-detected
  ahead of Groq when `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) is set. Set the key in
  the environment, never in source: themob would flag a hardcoded key, and a
  committed key is a leak. On Windows, `setx GEMINI_API_KEY "<key>"` then open a
  NEW shell (setx does not touch the current one) and launch themob from it.
  Note Google's newer AI Studio keys use the `AQ.` prefix, not `AIza`.
- [x] **Model kept current (2026-10-18).** Google retired `gemini-2.0-flash`
  (404 "no longer available"); default is now `gemini-3.8-flash`, overridable
  with `THEMOB_LLM_MODEL`. `assist/core.py` also recognises a model-retired error
  and tells the operator to set `THEMOB_LLM_MODEL` to the replacement the
  provider names, so the next retirement is self-explanatory rather than cryptic.
- [x] **Answer budget per provider (2026-10-18).** A 70-finding report was cut
  off mid-sentence: the answer cap was a flat 4096, tuned for Groq's 8000/min
  cap. Now each provider carries its own budget (`max_tokens` in `_PROVIDERS`):
  Gemini and Claude default to 8192 (enough for the full report), Groq stays at
  4096, all overridable with `THEMOB_LLM_MAX_TOKENS`. The client exposes
  `max_output_tokens` so a caller can ask for "as much as this provider allows".
- [x] **Investigate (agent) made as complete as Ask (2026-10-18).** The agent
  gave thin answers covering one or two findings. Three causes, all fixed in
  `assist/agent.py`: it never saw the whole scan (now primed with the same
  `weakness_groups` aggregation as Ask, and the system prompt requires covering
  every group), its final answer was hard-capped at 2048 (now uses the
  provider's full budget), and an early FINAL on a non-last step got only 512
  tokens (every step now gets the full budget; an ACTION reply is short anyway).
  It also inherits the no-tables formatting rule.

### Disk-space handling

- [x] A full disk made a whole run fail analyzer by analyzer: one explicit
  `WinError 112` / ENOSPC, then the rest timing out (900s, 1500s, 1800s) because
  a full disk stalls the containers rather than failing fast. Two guards now:
  a **pre-run check** (`MainWindow._confirm_disk_space`) warns and lets the
  operator cancel when free space is below `THEMOB_MIN_FREE_DISK_GB` (default 2),
  and the pipeline **stops early** at the first out-of-space failure
  (`orchestrator/pipeline.py` `is_out_of_space`) instead of burning half an hour
  proving the disk is still full. `tests/test_pipeline.py`, `tests/test_ui.py`.

## Phase 5: not started

### Settled before Phase 2 starts

**The MobSF integration boundary: decided 2026-09-03, recorded as locked
decision 11.** Section 12 of the build plan says settle the GPL boundary before
writing integration code, not after. It is settled, and Phase 2's MobSF adapter
is held to it:

* MobSF runs as its own container, reached over its REST API. themob never
  imports MobSF code and never links against it.
* No MobSF source is vendored into this repository, and no MobSF output format
  is re-implemented here; the adapter reads its JSON and maps it onto themob's
  canonical weakness keys like any other tool, so cross-tool voting merges it
  with gitleaks, semgrep and the config auditor instead of double-counting.
* themob is GPL-3.0-or-later anyway (PyQt6), so the licences are compatible.
  The boundary protects the *option* in locked decision 6: if themob ever has
  to ship closed by moving to PySide6, an arms-length MobSF stays possible and
  a linked one does not.

The same rule already covers every other Phase 2 tool. It is the one line that
is both the containment boundary and the licensing boundary, and nothing in
Phase 2 gets to be the exception.
