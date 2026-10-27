# themob: working notes

An authorization-gated mobile attack-surface intelligence engine. See
[README.md](README.md) for what it is and [PROGRESS.md](PROGRESS.md) for where
the build is.

---

## UI design rules

These are not suggestions. The first version of this interface was a grid of
rounded bordered cards with letter-spaced neon capitals and a lot of empty
space: generic, and not what this project looks like.

**Banned, no exceptions:**

- Rounded or bordered **cards**. A section is a label, a 1px hairline, and its
  content. Nothing floats above the page.
- A bordered box **inside** another bordered box. Ever.
- Coloured **banner / callout boxes** with an icon in them (the ⓘ or ⚠ box).
  If something is important, say it in the right place with the right weight.
- **ALL-CAPS headings**, and letter-spacing on anything but the wordmark.
- The accent colour on **every** heading. The accent marks *one* thing per
  screen; spread everywhere it means nothing.
- Loose padding. Page margin 22px, 20px between sections, 8px within one.

**Required:**

- Build from `themob/app/widgets/common.py`: `Section`, `Rule`, `KeyValues`,
  `Metric`, `MetricRow`, `SeverityCounts`, `CountRow`, and the
  `heading` / `caption` / `mono` / `value` helpers. Do not hand-roll a layout
  that one of these already covers.
- **Sentence case** everywhere: "Top findings", not "TOP FINDINGS".
- One ground colour. Hierarchy comes from size and weight, not borders and
  fills.
- The **severity ramp stays semantic**, critical red, low green. Never restyle
  it to match the palette; a console that recolours risk for aesthetics
  misreports.
- No inline hex anywhere outside `themob/app/theme.py`.
- Data first, air second. This is a console, not a landing page.

**On the reference apps:** study HiveDefend and TOPRECON for *structure*,
signals and slots, `QThread` usage, the `QGraphicsView` graph, the authorization
gate and audit trail. Do not copy their visual style. themob looks like itself.

A `PreToolUse` hook (`.claude/hooks/ui_design_rules.py`) re-states these before
any edit under `themob/app/`.

---

## Engineering rules

- **Foundation first.** Finding fingerprints use the canonical weakness key
  (a MASWE id or an internal canonical rule id), never a tool's own rule name,
  otherwise cross-tool voting silently never merges, which is the whole point.
- **Untrusted input.** An uploaded APK/IPA is hostile. It is parsed only inside
  network-less, resource-limited Docker workers with read-only mounts. There is
  no host fallback: if Docker is unavailable, analyzers are skipped.
- **Arms-length tools.** Every third-party tool is a subprocess or REST call,
  never a library import: that boundary is both the containment boundary and
  the licensing boundary. MobSF is GPL: REST/subprocess only. Never bundle Burp;
  mitmproxy is the default proxy. Pin every tool by version *and* checksum, and
  verify it at image build time.
- **Inventory and judgement are separate stages.** androguard, apktool and jadx
  describe what is there. The config auditor and the SAST stages decide what is
  wrong. An adapter that does both makes findings that cannot cite an entity.
- **Every run** requires an authorization attestation and appends to the
  hash-chained audit log.
- **Never commit** an APK, a workspace, or a findings database. They contain
  real secrets. See `.gitignore`.

## Conventions

- Adapters subclass `Analyzer` and are registered in `themob/adapters/__init__.py`.
- Workers live in `workers/<tool>/` as a `Dockerfile` plus an `analyze.py` that
  emits one JSON document on stdout and never raises.
- `themob/orchestrator/` and everything below it stays free of Qt, so the engine
  is testable headless.
- Tests that need Docker are marked `@pytest.mark.docker` and skip without it.
