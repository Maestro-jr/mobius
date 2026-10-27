# themob: UI/UX extract

An exact reconstruction of themob's desktop UI, for merging into the desktop UI
kit (section 18). Reconstructed from the code, the project docs (CLAUDE.md,
README.md, PROGRESS.md) and the memory files, not from any one session's memory.
Every value is tagged CONFIRMED (read in the source or seen in a render) or
INFERRED. themob has no local git repository, so git history could not be
consulted; that is the one reconstruction source the task names that was
unavailable.

Stack: PyQt6, Windows. Package `themob/app/`. Entry point `themob/app/main.py`,
launched as `python -m themob` (routed through `themob/__main__.py`). Rendered
via `tools/render_ui.py` (eight screens).

Identity in one line: a violet, flat, dense operations console on a near-black
violet ground, with a Docker-style three-band tone system, a Qt-native
attack-surface graph, and a decompiled-code browser. No cards, no web view.

## UI modules (paths)

CONFIRMED, all under `themob/app/`:
- `main.py` launcher: Fusion style, Segoe UI 10, stylesheet, crash guard, gate then window.
- `main_window.py` the frameless shell: title bar, sidebar, stacked pages, footer.
- `auth_gate.py` the blocking authorization dialog (shown before the window).
- `engine_thread.py` the QThread that runs the pipeline off the UI thread.
- `signals.py` the engine-event to Qt-signal bridge (`EngineBridge`).
- `theme.py` colour tokens and the full stylesheet (no inline hex elsewhere).
- `widgets/common.py` the primitive vocabulary: `Section`, `Rule`, `KeyValues`,
  `Metric`, `MetricRow`, `SeverityCounts`, `CountRow`, `LinkLabel`, text helpers.
- `widgets/dialog.py` `FramelessDialog` and `MessageDialog`.
- `widgets/sidebar.py` the collapsible nav rail and its hover toggle.
- `widgets/titlebar.py` the drawn title bar.
- `widgets/window_buttons.py` painted minimise / maximise / close.
- `widgets/logo.py` the painted MOB mark, wordmark and full lockup.
- `widgets/graph_view.py` the `QGraphicsView` attack-surface graph.
- `widgets/java_highlighter.py` lexical Java syntax highlighting.
- `panels/overview.py`, `section_panel.py`, `finding_detail.py`, `graph_panel.py`,
  `code.py`, `queries_panel.py`, `dynamic_panel.py`, `activity.py` the pages.
- `app/assets/mob-logo.png` the installed artwork (present; drawn as-is).
- `tools/render_ui.py` the offscreen render harness.

---

## 1. Principles and bans

CONFIRMED (`CLAUDE.md` UI section, `widgets/common.py:1-16`, `theme.py:1-20`).
The look is an operations console: data first, air second.

Banned, no exceptions:
- Rounded or bordered cards. A section is a sentence-case label, a 1px hairline,
  and its content. There is no Card widget; the old bordered `Panel` was removed
  (`common.py:99-103`).
- A bordered box inside another bordered box.
- Coloured banner or callout boxes with an icon. A `MessageDialog` puts the
  message as the content, with no banner frame around it (`dialog.py:97-102`).
- All-caps headings; letter-spacing on anything except the wordmark.
- The accent on every heading. The accent marks one thing per screen: the
  primary action, the active nav item, and the single figure that matters.
- Emoji as iconography.
- Loose padding. Page margin 22, between sections 20, within a section 8.

Required:
- Sentence case in every visible string ("Top findings", "Export report").
- One ground colour. The title bar, nav rail and footer separate by a tone step,
  not a border (`theme.py:26-53`).
- Hierarchy from size and weight, not borders and fills.
- The severity ramp stays semantic (critical red, low green), never recoloured
  to the palette (`theme.py:82-88`, `CLAUDE.md`).
- No inline hex outside `theme.py` (one documented exception: the per-cell
  alternating table border `#150e22` in the stylesheet, which is inside
  `theme.py`, and transient compositing colours painted in `logo.py`).

## 2. Writing rules

CONFIRMED (global CLAUDE.md, enforced by a global hook per memory
`feedback_no_ai_typography`).
- Never an em dash, en dash, curly quote, ellipsis character or arrow glyph, in
  code, comments, docstrings, UI strings, logs or docs. Recast instead: comma,
  colon, two sentences, parentheses, "to" for a range, "..." and "->".
- Placeholders for no value are a plain hyphen "-" (seen throughout the renders:
  the Metric "Highest severity" shows "-" before findings exist, `overview.py:68`).
- UI ellipses are three ASCII periods: "filter classes...", "save this question
  as...", "Import Frida output..." (`code.py:61`, `queries_panel.py:87`,
  `dynamic_panel.py:169`).
- No machine-prose tells (no "it is not just X, it is Y", no "leverage",
  "seamless", "robust" filler, no triads, no closing restatement).

## 3. Colour tokens (`theme.py`)

CONFIRMED, exact hex from `theme.py`. themob is violet on near-black violet.

Ground and chrome (the three-band system, `theme.py:26-57`):
| Token | Hex | Use |
|---|---|---|
| `BG_BASE` | #100a1e | the single page ground |
| `BG_SIDEBAR` | #040209 | nav rail and footer (darker band) |
| `BG_TITLEBAR` | #231849 | title bar (the one lighter band) |
| `BG_TITLEBAR_HOVER` | #31226a | title bar control hover |
| `BG_RAISED` | #1a1230 | inputs, flat-item hover (never a card) |
| `BG_HOVER` | #221741 | stronger hover |
| `BG_SELECT` | #35225c | selected row, selection background |
| `WINDOW_RADIUS` | 10 (px) | window and footer corner radius |

Hairlines (two tones, `theme.py:60-61`): `RULE` #2b1f40 (divider),
`RULE_STRONG` #3c2a58 (frame edge, button border, scrollbar handle).
Legacy aliases (`theme.py:64-68`): `BG_CANVAS`=`BG_SIDEBAR`,
`BG_OVERLAY`/`BG_MUTED`=`BG_RAISED`, `BORDER`/`BORDER_STRONG`=`RULE`.

Accent, one family (`theme.py:70-75`): `ACCENT` #a855f7, `ACCENT_DIM` #7c3aed
(primary fill), `ACCENT_HOVER` #8b45f0, `ACCENT_BRIGHT` #c084fc, `ACCENT_SOFT`
#d8b4fe.

Text (`theme.py:77-80`): `TEXT_PRIMARY` #ebe3f7, `TEXT_BODY` #c3b4da,
`TEXT_SECONDARY` #8c7aa8, `TEXT_MUTED` #5f5080.

Semantic status ramp (`theme.py:82-98`), never restyled:
| Token | Hex |
|---|---|
| `SEVERITY_COLORS[CRITICAL]` / `ERROR` | #ff4d6d |
| `SEVERITY_COLORS[HIGH]` / `WARN` | #ff9d4d |
| `SEVERITY_COLORS[MEDIUM]` | #ffd166 |
| `SEVERITY_COLORS[LOW]` | #5ee6a8 |
| `SEVERITY_COLORS[INFO]` / `OK` | #a855f7 (violet; info carries no urgency) |
| `ERROR_SOFT` | #ff90a6 |
| `CLOSE_HOVER` | #a3123f |

Entity ramp for the graph and legend (`theme.py:103-115`): APP #d8b4fe,
COMPONENT #a855f7, NATIVE_LIB #7c3aed, PERMISSION #6366f1, LIBRARY #e879f9,
CLOUD_ASSET #f472b6, DEEP_LINK #22d3ee, ENDPOINT #38bdf8, SECRET #ff4d6d,
CRYPTO_USAGE #ffd166, STORAGE_SINK #fb923c.

Syntax ramp for the code browser (`theme.py:133-141`): keyword #c084fc,
literal #f0abfc, string #5ee6a8, number #ffd166, comment #5f5080 (italic),
annotation #818cf8, type #d8b4fe. Notable security APIs are drawn in the HIGH
severity colour, bold (`java_highlighter.py:73`).

`severity_color()`, `entity_color()`, `entity_label()` are the accessors
(`theme.py:147-171`); nothing reads the dicts directly.

## 4. Typography

CONFIRMED. Fonts (`theme.py:143-144`): UI `'Segoe UI','Inter','Helvetica
Neue',sans-serif`; mono `'JetBrains Mono','Cascadia Mono','Consolas',monospace`.
Launch sets `QFont("Segoe UI", 10)` (`main.py:67`). Base `QWidget` is 13px
(`theme.py:178-183`).

| Role | objectName / helper | Size / weight / colour |
|---|---|---|
| Window title name | `titleLabel` | 15 / 600 / TEXT_PRIMARY |
| Title sub-label (tagline) | `titleSubLabel` | 11 / 400 / TEXT_BODY |
| Section heading | `heading` (`common.heading`) | 13 / 600 / TEXT_PRIMARY |
| Caption | `caption` | 11 / 400 / TEXT_MUTED |
| Value | `value` | 13 / 400 / TEXT_BODY |
| Mono | `mono` | 12 / 400 / FONT_MONO / TEXT_BODY |
| Metric number | `metricValue` | 30 / 300 / TEXT_PRIMARY (or a semantic colour) |
| Severity number | `severityValue` | 21 / 500 / its severity colour, TEXT_MUTED when zero |
| Inline action | `link` (`LinkLabel`) | 11 / 600 / ACCENT_SOFT, hover ACCENT_BRIGHT |
| Danger text | `danger` | 12 / 400 / ERROR_SOFT |
| Empty state | `emptyState` | 12 / 400 / TEXT_MUTED |
| Nav item | `navItem` | 12.5 / 400, 600 when active |
| Table body | QTableWidget | 12.5 |
| Table header | QHeaderView::section | 11 / 500 / TEXT_MUTED |
| Code viewer | `source_font()` | JetBrains Mono / Cascadia / Consolas, 10pt (`java_highlighter.py:127`) |

No all-caps anywhere; the only letter-spacing is inside the painted wordmark
(`logo.py:388,397`). CONFIRMED in every render: headings are sentence case.

## 5. Spacing and sizing

CONFIRMED.
- Page margin 22; between sections 20; within a section 8 (`common.py:29-31`).
- `page_layout` margins (22, 18, 22, 16), section spacing 20 (`common.py:359-361`).
- Section head spacing 10; body top margin 2, spacing 8; scrollable body margins
  (0, 2, 6, 0), spacing 4 (`common.py:113-139`).
- `KeyValues` gutter 132, horizontal spacing 16, vertical spacing 5
  (`common.py:183-191`); graph detail pane overrides the gutter to 104
  (`graph_panel.py:57`).
- `MetricRow` divider: 26px space, a vertical `Rule`, 26px space (`common.py:291-293`).
- `SeverityCounts` spacing 22 between cells (`common.py:314`).
- `CountRow` chip 7x7, radius 3, row spacing 9 (`common.py:344-346`).
- Title bar height 64 (`theme.py:239`); title bar margins (14, 0, 0, 0), item
  spacing 10 (`titlebar.py:33-34`); logo mark 58px (`titlebar.py:44`).
- Nav rail 186 expanded, 52 collapsed (`sidebar.py:21-22`); root margins
  (0, 8, 0, 8), spacing 2 (`sidebar.py:103-104`); nav item min-height 30, padding
  7x12 (`sidebar.py:191`, `theme.py:258`).
- Sidebar hover toggle 24px, hot margin 26, top offset 78 (`sidebar.py:26-29`).
- Footer bar height 26 (`theme.py:376`); footer row margins (18, 0, 18, 0),
  spacing 18 (`main_window.py:266-267`).
- Window controls 46 x 32, glyph box 10px (`window_buttons.py:29-31`).
- Buttons: secondary padding 6x14, 12px; primary 600 weight, #ffffff on
  ACCENT_DIM (`theme.py:274-294`). Inputs padding 6x9 (`theme.py:297-303`).
- Checkbox indicator 15px (`theme.py:315-316`).
- Scrollbars 9px wide, handle radius 4, min length 30 (`theme.py:356-364`).
- Progress bar 2px tall, chunk ACCENT (`theme.py:378-382`).
- Window minimum 1180 x 760 (`main_window.py:96`). INFERRED: no explicit default
  size is set (`main.py` calls `window.show()` only), so it opens at the minimum
  or the last size; the render harness forces 1560 x 980.
- Dialogs: `FramelessDialog` default width 560, body margins (24, 20, 24, 20),
  spacing 12, frame radius 12 with a 1px BORDER (`dialog.py:22,62-63,35-37`);
  the authorization gate is width 620 with a 104px logo (`auth_gate.py:54,77`).

## 6. App shell

CONFIRMED (`main_window.py`, rendered). Frameless top-level
(`FramelessWindowHint`), translucent background so the 10px corners are cut
rather than painted over (`main_window.py:97-101`).

```
+--------------------------------------------------------------------------+
| [MOB] mobile attack surface   Example Shop  .  333d7123...   _  []  X     |  title bar (BG_TITLEBAR, 64)
+---------+----------------------------------------------------------------+
| Overview 8 |                                                             |
| Platform & IPC 6                                                         |
| Network & API 2                                                         |
| Secrets    |            current page (QStackedWidget)                    |
| Cryptography|                                                            |
| Storage    |                                                            |
| Dependencies & SDKs                                                     |
| Code       |                                                            |
| Graph 11   |                                                            |
| Questions  |                                                            |
| Dynamic    |                                                            |
| Activity   |                                                            |
|            |                                                            |
| Idle       |                                                            |
| [ Analyze ]|  (primary)                                                  |
| [  Stop   ]|                                                            |
| [Export report]                                                         |
+---------+----------------------------------------------------------------+
| workspace: C:\...\projects\<id>            11 entities . 10 edges . 8 findings |  footer (BG_SIDEBAR, 26)
+--------------------------------------------------------------------------+
  nav rail (BG_SIDEBAR, 186 / 52)
```

- Title bar: the painted `MobMark` (installed artwork), the tagline "mobile
  attack surface", the loaded project chip (name, then the SHA-256 prefix in
  mono), stretch, a mono status slot, then painted window controls. Drag to move,
  double-click to maximise, drag a maximised window to restore
  (`titlebar.py:44-106`).
- Nav rail: one `Overview` entry, then the six section pages generated from
  `correlate.sections` so the rail cannot disagree with the content
  (`main_window.py:62-86`), then Code / Graph / Questions / Dynamic / Activity.
  Each item carries a Unicode geometric glyph and an optional count badge. A
  footer slot holds the run state caption, `Analyze` (primary), `Stop`, and
  `Export report` (`main_window.py:208-246`).
- Active nav item: ACCENT 2px left border, TEXT_PRIMARY, 600 weight
  (`theme.py:262-266`). Inactive: TEXT_SECONDARY, transparent.
- The sidebar collapses to a 52px icons-only rail via a floating hover toggle on
  its right edge (section 13).
- A bottom footer bar shows the workspace path (left) and live entity / edge /
  finding counts (right) (`main_window.py:263-274,345-347`).
- A finding detail page exists in the stack but has no nav entry: a finding opens
  it, and "Back" returns to where you came from (`main_window.py:192-199`).

## 7. Page / workspace patterns

CONFIRMED. Every page is a `QScrollArea` or plain `QWidget` built with
`page_layout` and composed of `Section`s. There is no three-column control /
canvas / detail workspace template as in the kit; themob's pages are
list-and-detail and graph canvases. Patterns actually used:

- Overview (`overview.py`): a `MetricRow` of four `Metric`s (Graph entities,
  Attack surface, Findings, Highest severity in its severity colour), a `Rule`, a
  `SeverityCounts` line, then a three-column row (Application `KeyValues`;
  "Entities by type" `CountRow`s; an "Attack surface" mini `GraphView` with an
  "Open graph" link action), then a "Top findings" table.
- Section page (`section_panel.py`): one widget reused for all six sections (a
  section is a query, not a screen). Title + description caption, `SeverityCounts`,
  a Findings table with an "Exposed" column ("Yes" in WARN when an exported entry
  point reaches it), then an "In this section" entities table. Tables are sized to
  their rows so the page scrolls and the tables do not.
- Finding detail (`finding_detail.py`): a "Back" link, title, the severity word
  large in its colour plus confidence and status captions, a score rationale
  caption, the description, two `Section`s side by side (Standards `KeyValues`,
  Where `KeyValues` with an "Open in the code browser" link), Evidence, Remediation,
  then "Your verdict": a reason textarea and three buttons (Confirmed primary,
  False positive, Accepted risk), and a Notes list. The suppressing verdicts stay
  disabled until a reason is typed (`finding_detail.py:274-286`).
- Graph (`graph_panel.py`): a toolbar (type filter combo, "Isolate selection",
  "Show all relationships", a count caption, "Re-layout", "Fit"), a `QSplitter`
  with the `GraphView` on the left and an Entity `KeyValues` detail plus a Legend
  of `CountRow`s on the right.
- Code (`code.py`): a `QSplitter`, a "Classes" tree with a filter box on the left,
  a "Source" `QPlainTextEdit` with the fully-qualified name in the header on the
  right, a status caption at the foot.
- Questions (`queries_panel.py`): a "Questions" list (ten built-ins plus saved
  ones in ACCENT_SOFT), a save-as input, Save / Delete, and an "Answer" table.
- Dynamic (`dynamic_panel.py`): a status line, an "Execution authorization"
  Section (device input, interception-scope input, two checkboxes, a primary
  "Authorize dynamic analysis"), a Device section with "Refresh devices", and a
  "Prepare a run" section (a job combo, "Show command", import buttons).
- Activity (`activity.py`): an Analyzers table and a mono run-log console side by
  side, then an Audit trail table with a "Verify chain" action.

Tables everywhere: no grid lines, vertical header hidden, select rows, single
selection, no edit triggers, a hairline under the header only, first/title column
stretches and the rest resize to contents (`overview.py:104-117`,
`section_panel.py:104-121`, `theme.py:324-352`). Severity cells are a coloured
text label, never a pill.

## 8. Component library (`widgets/common.py`)

CONFIRMED.
| Primitive | What it is |
|---|---|
| `Section(title, meta, scrollable=False)` | sentence-case heading + meta caption + `Rule` + a `body` layout; `add_action`, `add_header_widget`, `show_empty` |
| `Rule(vertical=False)` | the 1px hairline, the only divider (objectName ruleH/ruleV) |
| `LinkLabel(text)` | inline text action (objectName link), not a button |
| `heading / caption / mono / value / label` | text helpers with token colours |
| `KeyValues` | right-aligned muted keys in a 132px gutter, values beside; `add(key, text, tone, monospace)`, `pairs()` read API |
| `Metric(name, text, note, emphasis)` | a 30px number over a caption; `emphasis` colours it, used for exactly one figure |
| `MetricRow` | metrics on one flush line, divided by vertical `Rule`s, not boxed |
| `SeverityCounts` | the five severity figures on one line; a zero recedes to TEXT_MUTED |
| `CountRow(color, text, count)` | a 7px colour chip, a label, a right-aligned mono count |
| `page_layout(widget)` | the standard page margins and rhythm |

To rebuild a dynamic panel: `takeAt`, then `setParent(None)` and `deleteLater()`
(set parent first, `common.py:161-167`, `finding_detail.py:300-306`).

## 9. Icons

CONFIRMED, and this is a deliberate divergence from the kit: themob has no
central `icons.py` drawn-stroke set. Instead:
- Nav items carry Unicode geometric glyphs passed to `Sidebar.add_item`
  (`main_window.py:62-86`): Overview a filled square, the sections a set of
  geometric marks (hexagon, lozenge, filled hex, and so on), Code an angle-bracket
  pair, Graph a hexagon outline, Questions a fisheye, Dynamic a half-circle,
  Activity a triple bar. The collapsed footer run controls become a play
  triangle, a stop square and a down triangle (`main_window.py:256-258`).
- The window controls, the sidebar toggle, the logo and the graph nodes are all
  painted with `QPainter` at fixed sizes with 1 to 1.8px strokes, so they stay
  crisp at any DPI (`window_buttons.py`, `sidebar.py:56-81`, `logo.py`,
  `graph_view.py`).
- Every icon-only control has a tooltip (`window_buttons.py:46-47`,
  `sidebar.py:48`, nav items `sidebar.py:192`).
- No emoji anywhere.

## 10. Buttons and interaction states

CONFIRMED (`theme.py:273-322`).
- Secondary (default QPushButton): transparent fill, 1px RULE_STRONG border,
  TEXT_BODY, padding 6x14; hover ACCENT_DIM border + TEXT_PRIMARY; disabled
  TEXT_MUTED + RULE border. A button never looks like bare text.
- Primary (`objectName("primary")`): ACCENT_DIM fill, 1px ACCENT_DIM border,
  #ffffff bold; hover ACCENT_HOVER; disabled transparent + RULE + TEXT_MUTED. At
  most one per area (Analyze, Authorize dynamic analysis, Confirmed, dialog OK).
- Window controls: transparent; hover BG_TITLEBAR_HOVER; close hover CLOSE_HOVER
  fill with a white X; the maximise glyph swaps to a restore glyph while
  maximized, kept in step in `changeEvent` (`window_buttons.py:68-74,128-141`,
  `main_window.py:623-626`).
- Inputs: BG_RAISED fill, 1px RULE border, ACCENT_DIM border on focus. Checkbox:
  15px box, ACCENT_DIM when checked. Combo popup BG_RAISED with BG_SELECT
  selection.
- Busy state: the run state caption changes (Running / Stopping), the progress
  bar shows, Analyze disables and Stop enables (`main_window.py:444-455`).

## 11. Data honesty and empty states

CONFIRMED (rendered). Every number comes from the real engine through the
database and the correlate layer; the render harness seeds a real project and
runs the real config auditor rather than hand-writing findings
(`render_ui.py:242-255`). Honest empty states seen in the renders: "Select a node
to inspect it and trace its path from the app." (graph), "No notes yet."
(finding), "Not authorized for dynamic analysis. Attest below..." and "Not
checked. Refresh to list connected devices." (dynamic), "No decompiled sources
yet. Run the jadx analyzer." (code, `code.py:127`). A level with a zero count
recedes to TEXT_MUTED rather than shouting (`common.py:329-331`). Missing Docker
raises an explicit modal rather than silently finding nothing
(`main_window.py:463-474`).

## 12. Platform integration

CONFIRMED, and the sharpest divergence from the kit. themob is frameless
(`FramelessWindowHint`) with `WA_TranslucentBackground` so the rounded corners
are genuinely cut (`main_window.py:97-101`). It does NOT ship a `winframe.py`
equivalent: there is no WM_NCCALCSIZE / WM_NCHITTEST native-frame restoration, so
Aero Snap, the Windows 11 snap-layouts menu and edge resizing are not available.
- Move: drag the title bar (`titlebar.py:82-97`).
- Maximise / restore: double-click the title bar, the maximise control, or drag a
  maximised window to restore (`titlebar.py:103-105`, `window_buttons.py`).
- A maximised window squares its corners and drops the 1px border so there are no
  transparent corner notches (`main_window.py:605-626`, `theme.py:192`).
- Taskbar and hover-preview icon from the installed artwork (`logo.app_icon`,
  `main_window.py:104-106`).
- INFERRED: no edge-resize handling is present, so a floating window is
  drag-move and maximise only, not edge-resizable. No tray icon and no global
  shortcuts were found. DPI is Qt's default (no per-monitor custom handling).

## 13. Motion

CONFIRMED. The only animation is the nav rail collapse / expand: a
`QPropertyAnimation` on both `minimumWidth` and `maximumWidth`, 140 ms,
`InOutQuad`, between 186 and 52; the item labels are swapped for glyphs before the
slide so they do not clip mid-flight (`sidebar.py:238-256`). The hover toggle
appears and hides with pointer proximity (no fade). No other decorative motion.
(Divergence from the kit, which animates 190 ms `InOutCubic`.)

## 14. Hard-won gotchas (the bug, and the fix that stuck)

CONFIRMED from source comments.
1. The offscreen Qt plugin exposes no fonts on Windows: every glyph renders as a
   box and text metrics come out about twice too wide, wrecking the layout. Render
   with the real "windows" plugin plus `WA_DontShowOnScreen`, not offscreen
   (`render_ui.py:18-22,259`).
2. `WA_TranslucentBackground` is required or the rounded corners are drawn over an
   opaque square and the outline looks soft (`main_window.py:98-101`).
3. A maximised frameless window keeps its radius unless you square it, leaving
   four transparent notches that read as a rendering fault; toggle a `maximized`
   property and restyle (`main_window.py:609-621`, `theme.py:192`).
4. Window controls drawn as text glyphs look wrong: a hyphen sits on the text
   baseline, not centred, and the font decides the weight so the three never
   match. Paint them at a fixed 10px box with 1px strokes (`window_buttons.py:1-13`).
5. The close button's square hover fill paints over the window radius; round only
   its top-right corner to match (`window_buttons.py:104-120`).
6. The sidebar toggle, if parented to the sidebar, is clipped by the rail it
   straddles; parent it to the body and track the pointer across the whole body
   (`sidebar.py:109-111,133-145`).
7. Grabbing the collapse animation mid-flight caught the rail at 186px with the
   buttons still stretched; drive the animation to its end value before the grab
   (`render_ui.py:313-315`).
8. "&" in button text is a Qt mnemonic, so "Network & API" renders as "Network
   _API"; escape it as "&&" (`sidebar.py:184-186`).
9. `fitInView` against a panel not yet shown (a degenerate viewport) locks in a
   wildly wrong scale that survives the later resize, so the graph becomes a cloud
   of dots; defer the fit and re-fit on show and resize until the user takes
   control of the view (`graph_view.py:440-483`).
10. `spring_layout` returns a roughly circular arrangement; scaling both axes by
    one constant wastes the width of a wide canvas and zooms everything
    unreadable, so stretch each axis to the viewport's own aspect
    (`graph_view.py:550-579`).
11. Eliding a node caption by a fixed character count centre-clips a long key and
    loses the half that identifies it; elide against the real font metrics
    (`graph_view.py:179-182`).
12. The logo is a title-bar icon at 58px and a 190px splash in the same session,
    so a raster would be soft at one of them; it is painted, and below about 50px
    the supplied lockup's wordmark is a smudge, so the title bar is sized to the
    artwork (58px) rather than the artwork squeezed into a smaller bar
    (`logo.py:9-16`, `titlebar.py:40-44`).

## 15. Verification workflow

CONFIRMED. `tools/render_ui.py` seeds a real project (a built APK fixture, a
graph, real config-audit findings, a small decompiled tree) and grabs eight full
`MainWindow` screens: overview, code, graph, collapsed rail, section, finding,
queries, dynamic. It monkeypatches `SandboxRunner.is_available/has_image` to True
so the no-Docker modal does not block the render (`render_ui.py:140-142`). Judge
colours from a full-window grab (an isolated `widget.grab()` renders transparent
areas light grey). Qt UI tests live in `tests/test_ui.py`; the logo in
`tests/test_logo.py`. The typography gate is `tools/check_typography.py`
(CI-enforced). The hermetic suite runs offscreen Qt (`QT_QPA_PLATFORM=offscreen`)
for logic, but pixel renders use the "windows" plugin per gotcha 1.

## 16. Packaging

CONFIRMED. themob is a Python package, not a PyInstaller bundle. `pyproject.toml`
declares `[project.scripts] themob = "themob.__main__:main"`, so `pip install`
gives a `themob` command; from a checkout `python -m themob` is the same thing,
and `themob.sh` / `themob.cmd` launchers find a working Python. Package data
(migrations, assets, agents) ships via `tool.setuptools.package-data`; the
knowledge packs install under `share/themob/`. The app is GPL-3.0-or-later because
PyQt6 is GPL. There is no frozen-exe spec or `--selftest` harness in this project
(that is an AdVerify kit pattern); the headless surface is the `themob` CLI.

## 17. Smell test

CONFIRMED against the renders: no card, no box-in-box, no callout tile; headings
sentence case with no caps or letter-spacing (except the painted wordmark); the
accent appears about twice per screen (the Analyze primary and the active nav
item, plus the one emphasised figure such as "High"); the severity ramp is the
semantic one; no hex outside `theme.py`; no emoji, and every icon-only control has
a tooltip; every button has a fill or border or the accent, nothing clickable is
bare text except the explicit `LinkLabel`; every number is real or an honest empty
state shows. Open points: the frameless window does not snap or edge-resize
(section 12), which the kit's smell test expects; treat that as a known gap, not a
pass.

---

## 18. What is distinctive here

Ranked by how much each makes the UI good.

1. **The Docker-style three-band tone system.** One ground (`BG_BASE` #100a1e),
   a darker rail and footer (`BG_SIDEBAR` #040209), and a lighter title bar
   (`BG_TITLEBAR` #231849), separated by tone alone, no borders. The code records
   that the first attempt put the rail only 4.7 luminance points below the page
   and it failed the eye, so the page was lifted instead to open a visible gap
   (`theme.py:26-57`). This is the single biggest reason the shell reads as
   structured without a line anywhere. The kit uses a darker band only; the
   lighter-title-bar third band is themob's.
2. **A Qt-native force-directed attack-surface graph** (`graph_view.py`). Octagon
   nodes coloured by entity type and overridden by the worst finding on them,
   sized by connectivity (a hub Provider is visibly a hub), typed edges (solid
   declared, dashed inferred, with arrowheads), click-a-node to trace and
   highlight its path from the App while dimming the rest, and level-of-detail
   captions that appear only past a zoom threshold. No `QWebEngineView`, no
   bundled JavaScript, which matters in a security tool. The kit has no graph.
3. **A decompiled-code browser with lexical Java highlighting**
   (`java_highlighter.py`, `code.py`): keywords, strings and types in the syntax
   ramp, and security-notable APIs (Cipher, TrustManager, WebView, rawQuery and
   the like) drawn in the HIGH severity colour so a reviewer's eye catches them
   without hunting. Lexical, not a parser, because decompiled output is often not
   valid Java.
4. **Sections generated from a data model.** The six section pages and the nav
   entries are projected from `correlate.sections`, so the rail cannot disagree
   with the queries that fill it (`main_window.py:62-86`). The same honesty shows
   in the finding detail as a full page with inline, reason-gated verdict controls
   rather than a dialog.
5. **The painted multi-part logo** (`logo.py`): a hexagon, a noir plate (a drawn
   fedora-and-trenchcoat silhouette when no photo is installed), and a violet ring
   for the "O". Real artwork wins and is drawn as-is with a silhouette halo only
   when the painted fallback is used. It is the app's whole identity and it scales
   from a 58px mark to a 190px splash without a raster.
6. **The Docker-style hover sidebar toggle** (`sidebar.py`): a painted circle that
   straddles the rail's right edge and appears only when the pointer is near,
   whose glyph is a panel outline with one side filled to say which way the panel
   will move.
7. **One severity ramp drives every surface** consistently: the KPI "Highest
   severity" figure, the `SeverityCounts` line, the table severity cells, the
   graph node borders, and the highlighter's notable-API colour all read from
   `SEVERITY_COLORS`.

What the kit has that themob does not, and would need if merged the other way: a
`winframe.py` to restore native Windows snapping and edge-resize (themob's single
real UI gap), and a central drawn `icons.py` (themob uses Unicode geometric glyphs
plus ad-hoc QPainter). If this extract and the kit's sections 1, 2 or 17 ever
conflict, the kit's house rules win.
