# ui_extract: themob UI source

Verbatim copies of themob's reusable UI source, shipped with `UI_UX_EXTRACT.md`
for the desktop UI kit. These are unchanged copies of the files under
`themob/app/`; they are reference material, not a standalone package, so the
relative imports (`from .. import theme`) resolve only inside the original tree.

| File | Role | Original path |
|---|---|---|
| theme.py | colour tokens and the full stylesheet | themob/app/theme.py |
| common.py | the primitive vocabulary (Section, Rule, KeyValues, Metric, SeverityCounts, CountRow, text helpers) | themob/app/widgets/common.py |
| sidebar.py | collapsible nav rail and the hover toggle | themob/app/widgets/sidebar.py |
| titlebar.py | the drawn title bar | themob/app/widgets/titlebar.py |
| window_buttons.py | painted minimise / maximise / close | themob/app/widgets/window_buttons.py |
| dialog.py | FramelessDialog and MessageDialog | themob/app/widgets/dialog.py |
| logo.py | the painted MOB mark, wordmark and lockup | themob/app/widgets/logo.py |
| graph_view.py | the QGraphicsView attack-surface graph | themob/app/widgets/graph_view.py |
| java_highlighter.py | lexical Java syntax highlighting | themob/app/widgets/java_highlighter.py |
| main_window.py | the frameless shell (title bar, rail, stacked pages, footer) | themob/app/main_window.py |
| overview.py | one example page | themob/app/panels/overview.py |

themob has no central icons file: nav items use Unicode geometric glyphs and the
chrome (window controls, sidebar toggle, logo, graph) is painted with QPainter.
There is no native-frame module: the window is frameless with manual move and
maximise, so Aero Snap and edge resize are not restored. See sections 9 and 12 of
UI_UX_EXTRACT.md.
