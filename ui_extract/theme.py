"""themob's theme: violet, flat, dense.

One ground colour, hairline rules, and typographic hierarchy. Deliberately
**not** a grid of bordered cards: structure comes from rules and weight, so the
eye reads the data rather than the containers around it, and nothing is ever a
bordered box inside another bordered box.

The accent is spent sparingly: the primary action, the active nav item, and
the single figure that matters on a screen. Everything violet is not a design,
it is a wash.

**The severity ramp stays semantic.** Critical is red, low is green. A console
that recolours its risk ramp to match a palette misreports, which is worse than
being off-brand. ``INFO`` is the one level that turns violet, since it carries
no urgency.

Constants rather than a ``.qss`` file because the custom-painted widgets, the
attack-surface graph, the logo, the code highlighter, need the same colours
the stylesheet uses, and duplicating them is how a theme drifts.
"""
from __future__ import annotations

from ..model.enums import EntityType, Severity

# --- ground ----------------------------------------------------------------
BG_BASE = "#100a1e"          # the page. Everything sits on this
# The window's edge chrome, and deliberately *darker* than the page. Docker
# Desktop separates its sidebar from the content this way and it reads well:
# the rail recedes, the content comes forward, and no border is needed to say
# where one ends.
#
# Three bands, and no more than three: light chrome at the top, content in the
# middle, dark chrome down the left and along the bottom. The footer shares
# BG_SIDEBAR, so the dark band runs along the left edge and the bottom as one.
#
# The step took two attempts. The first put the rail 4.7 luminance points below
# the page, which passes a threshold and fails an eye: at this end of the scale
# both colours are already near black, so there was nowhere darker to go. The
# fix was to lift the *page* instead, which opened a 9.8 point gap, comparable
# to the 17 the title bar sits above it. The lesson is in the test: a tone step
# has to be checked against what a person can see, not against a number that
# happens to be greater than zero.
BG_SIDEBAR = "#040209"
BG_RAISED = "#1a1230"        # inputs and hover states only, never a "card"
BG_HOVER = "#221741"
BG_SELECT = "#35225c"        # selected row

# The title bar is the one band that sits *lighter* than the page, the way
# Docker Desktop's header does. It reads as the window's own chrome rather than
# part of the document, which is what makes the rounded top corners look
# deliberate instead of clipped.
BG_TITLEBAR = "#231849"
BG_TITLEBAR_HOVER = "#31226a"

# Window corner radius. Small on purpose: enough to soften the outline, not
# enough to look like a phone widget.
WINDOW_RADIUS = 10

# Hairlines. There are two: a divider, and a slightly stronger frame edge.
RULE = "#2b1f40"
RULE_STRONG = "#3c2a58"

# Legacy aliases; a few call sites still reach for the old token names.
BG_CANVAS = BG_SIDEBAR       # legacy alias
BG_OVERLAY = BG_RAISED
BG_MUTED = BG_RAISED
BORDER = RULE
BORDER_STRONG = RULE

ACCENT = "#a855f7"           # the violet in the mark
ACCENT_DIM = "#7c3aed"
ACCENT_HOVER = "#8b45f0"
ACCENT_BRIGHT = "#c084fc"
ACCENT_SOFT = "#d8b4fe"
ACCENT_TEAL = ACCENT_SOFT    # legacy alias

TEXT_PRIMARY = "#ebe3f7"
TEXT_BODY = "#c3b4da"
TEXT_SECONDARY = "#8c7aa8"
TEXT_MUTED = "#5f5080"

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff4d6d",
    Severity.HIGH: "#ff9d4d",
    Severity.MEDIUM: "#ffd166",
    Severity.LOW: "#5ee6a8",
    Severity.INFO: "#a855f7",
}

# --- semantic status tokens -------------------------------------------------
OK = ACCENT
WARN = SEVERITY_COLORS[Severity.HIGH]
ERROR = SEVERITY_COLORS[Severity.CRITICAL]
ERROR_SOFT = "#ff90a6"
SELECTION_BG = BG_SELECT
CLOSE_HOVER = "#a3123f"
DANGER_BG = "#1a0a12"
DANGER_BORDER = "#40142a"

# The graph legend needs eleven colours that are actually distinguishable.
# Violet by lightness for the app's own structure; indigo and fuchsia for its
# dependencies; cyan and sky for anything reachable from outside; warm for risk.
ENTITY_COLORS: dict[EntityType, str] = {
    EntityType.APP: "#d8b4fe",
    EntityType.COMPONENT: "#a855f7",
    EntityType.NATIVE_LIB: "#7c3aed",
    EntityType.PERMISSION: "#6366f1",
    EntityType.LIBRARY: "#e879f9",
    EntityType.CLOUD_ASSET: "#f472b6",
    EntityType.DEEP_LINK: "#22d3ee",
    EntityType.ENDPOINT: "#38bdf8",
    EntityType.SECRET: "#ff4d6d",
    EntityType.CRYPTO_USAGE: "#ffd166",
    EntityType.STORAGE_SINK: "#fb923c",
}

ENTITY_LABELS: dict[EntityType, str] = {
    EntityType.APP: "App",
    EntityType.COMPONENT: "Components",
    EntityType.PERMISSION: "Permissions",
    EntityType.DEEP_LINK: "Deep links",
    EntityType.ENDPOINT: "Endpoints",
    EntityType.CLOUD_ASSET: "Cloud assets",
    EntityType.SECRET: "Secrets",
    EntityType.LIBRARY: "Libraries",
    EntityType.NATIVE_LIB: "Native libraries",
    EntityType.CRYPTO_USAGE: "Crypto usage",
    EntityType.STORAGE_SINK: "Storage sinks",
}

# Syntax colours for the decompiled-code browser. Here, not in the highlighter,
# so every colour in the app still comes from one file.
SYNTAX = {
    "keyword": ACCENT_BRIGHT,
    "literal": "#f0abfc",
    "string": "#5ee6a8",
    "number": "#ffd166",
    "comment": TEXT_MUTED,
    "annotation": "#818cf8",
    "type": ACCENT_SOFT,
}

FONT_UI = "'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif"
FONT_MONO = "'JetBrains Mono', 'Cascadia Mono', 'Consolas', monospace"


def severity_color(severity: Severity | str) -> str:
    if isinstance(severity, str):
        try:
            severity = Severity(severity)
        except ValueError:
            return TEXT_SECONDARY
    return SEVERITY_COLORS.get(severity, TEXT_SECONDARY)


def entity_color(etype: EntityType | str) -> str:
    if isinstance(etype, str):
        try:
            etype = EntityType(etype)
        except ValueError:
            return TEXT_SECONDARY
    return ENTITY_COLORS.get(etype, TEXT_SECONDARY)


def entity_label(etype: EntityType | str) -> str:
    if isinstance(etype, str):
        try:
            etype = EntityType(etype)
        except ValueError:
            return str(etype).replace("_", " ").capitalize()
    return ENTITY_LABELS.get(etype, etype.value.replace("_", " ").capitalize())


def stylesheet() -> str:
    return f"""
    * {{ outline: 0; }}

    QWidget {{
        color: {TEXT_BODY};
        font-family: {FONT_UI};
        font-size: 13px;
        background-color: transparent;
    }}
    QMainWindow, QDialog {{ background-color: transparent; }}
    /* The rounded outline lives on #root, and the window itself is translucent
       so the corners are actually cut rather than painted over. */
    QWidget#root {{
        background-color: {BG_BASE};
        border-radius: {WINDOW_RADIUS}px;
        border: 1px solid {RULE_STRONG};
    }}
    QWidget#root[maximized="true"] {{ border-radius: 0px; border: none; }}

    QToolTip {{
        background-color: {BG_RAISED};
        color: {TEXT_PRIMARY};
        border: 1px solid {RULE};
        padding: 5px 9px;
        font-size: 12px;
    }}

    /* --- typography ------------------------------------------------------ */
    QLabel#heading {{
        color: {TEXT_PRIMARY};
        font-size: 13px;
        font-weight: 600;
    }}
    QLabel#caption {{ color: {TEXT_MUTED}; font-size: 11px; }}
    QLabel#value   {{ color: {TEXT_BODY}; font-size: 13px; }}
    QLabel#mono {{
        color: {TEXT_BODY};
        font-family: {FONT_MONO};
        font-size: 12px;
    }}
    QLabel#metricValue {{
        color: {TEXT_PRIMARY};
        font-size: 30px;
        font-weight: 300;
    }}
    QLabel#severityValue {{ font-size: 21px; font-weight: 500; }}
    QLabel#link {{
        color: {ACCENT_SOFT};
        font-size: 11px;
        font-weight: 600;
    }}
    QLabel#link:hover {{ color: {ACCENT_BRIGHT}; }}
    QLabel#danger {{ color: {ERROR_SOFT}; font-size: 12px; }}
    QLabel#emptyState {{ color: {TEXT_MUTED}; font-size: 12px; }}

    /* --- rules: the only dividers ---------------------------------------- */
    QFrame#ruleH, QFrame#ruleV {{ background-color: {RULE}; border: none; }}

    /* --- title bar -------------------------------------------------------- */
    QFrame#titleBar {{
        background-color: {BG_TITLEBAR};
        border: none;
        border-top-left-radius: {WINDOW_RADIUS}px;
        border-top-right-radius: {WINDOW_RADIUS}px;
        min-height: 64px; max-height: 64px;
    }}
    QLabel#titleSubLabel {{ color: {TEXT_BODY}; font-size: 11px; }}
    QLabel#titleLabel {{ color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 600; }}

    /* --- sidebar ---------------------------------------------------------- */
    QWidget#sidebar {{
        background-color: {BG_SIDEBAR};
        /* No border. The tone step is what separates the rail from the page,
           which is one less line on screen for the same amount of structure. */
        border: none;
    }}
    QFrame#sidebarNav {{ background: transparent; border: none; }}
    QPushButton#navItem {{
        background: transparent;
        border: none;
        border-left: 2px solid transparent;
        color: {TEXT_SECONDARY};
        text-align: left;
        padding: 7px 12px;
        font-size: 12.5px;
    }}
    QPushButton#navItem:hover {{ color: {TEXT_PRIMARY}; }}
    QPushButton#navItem:checked {{
        border-left: 2px solid {ACCENT};
        color: {TEXT_PRIMARY};
        font-weight: 600;
    }}
    QPushButton#sidebarToggle {{
        background: transparent; border: none; color: {TEXT_MUTED};
        font-size: 13px;
    }}
    QPushButton#sidebarToggle:hover {{ color: {TEXT_PRIMARY}; }}

    /* --- buttons ---------------------------------------------------------- */
    QPushButton {{
        background-color: transparent;
        border: 1px solid {RULE_STRONG};
        color: {TEXT_BODY};
        padding: 6px 14px;
        font-size: 12px;
    }}
    QPushButton:hover {{ border-color: {ACCENT_DIM}; color: {TEXT_PRIMARY}; }}
    QPushButton:disabled {{ color: {TEXT_MUTED}; border-color: {RULE}; }}
    QPushButton#primary {{
        background-color: {ACCENT_DIM};
        border: 1px solid {ACCENT_DIM};
        color: #ffffff;
        font-weight: 600;
    }}
    QPushButton#primary:hover {{
        background-color: {ACCENT_HOVER}; border-color: {ACCENT_HOVER};
    }}
    QPushButton#primary:disabled {{
        background-color: transparent; border-color: {RULE}; color: {TEXT_MUTED};
    }}

    /* --- inputs ----------------------------------------------------------- */
    QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
        background-color: {BG_RAISED};
        border: 1px solid {RULE};
        padding: 6px 9px;
        color: {TEXT_PRIMARY};
        selection-background-color: {BG_SELECT};
    }}
    QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{
        border: 1px solid {ACCENT_DIM};
    }}
    QComboBox::drop-down {{ border: none; width: 16px; }}
    QComboBox QAbstractItemView {{
        background-color: {BG_RAISED};
        border: 1px solid {RULE};
        selection-background-color: {BG_SELECT};
        color: {TEXT_PRIMARY};
    }}
    QCheckBox {{ color: {TEXT_BODY}; font-size: 13px; spacing: 9px; }}
    QCheckBox::indicator {{
        width: 15px; height: 15px;
        border: 1px solid {RULE_STRONG};
        background: {BG_RAISED};
    }}
    QCheckBox::indicator:checked {{
        background: {ACCENT_DIM}; border-color: {ACCENT_DIM};
    }}

    /* --- tables: flush, hairline-separated -------------------------------- */
    QTableWidget, QTableView, QTreeWidget {{
        background-color: transparent;
        alternate-background-color: transparent;
        gridline-color: transparent;
        border: none;
        selection-background-color: {BG_SELECT};
        selection-color: {TEXT_PRIMARY};
        font-size: 12.5px;
    }}
    QTableWidget::item {{
        padding: 6px 8px;
        border-bottom: 1px solid #150e22;
    }}
    QTableWidget::item:hover:!selected, QTreeWidget::item:hover:!selected {{
        background-color: {BG_RAISED};
    }}
    QTreeWidget::item {{ padding: 3px 4px; }}
    QHeaderView {{ background: transparent; border: none; }}
    QHeaderView::section {{
        background: transparent;
        color: {TEXT_MUTED};
        padding: 4px 8px;
        border: none;
        border-bottom: 1px solid {RULE};
        font-weight: 500;
        font-size: 11px;
    }}
    QTableCornerButton::section {{ background: transparent; border: none; }}

    /* --- scrollbars ------------------------------------------------------- */
    QScrollArea {{ border: none; background: transparent; }}
    QScrollBar:vertical {{ background: transparent; width: 9px; margin: 0; }}
    QScrollBar::handle:vertical {{
        background: {RULE_STRONG}; border-radius: 4px; min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {ACCENT_DIM}; }}
    QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 0; }}
    QScrollBar::handle:horizontal {{
        background: {RULE_STRONG}; border-radius: 4px; min-width: 30px;
    }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    /* --- chrome ----------------------------------------------------------- */
    QFrame#footer {{
        background-color: {BG_SIDEBAR};
        border-top: none;
        /* Matches the window, or the footer paints square over the radius and
           the two bottom corners look like the rounding failed. */
        border-bottom-left-radius: {WINDOW_RADIUS}px;
        border-bottom-right-radius: {WINDOW_RADIUS}px;
        min-height: 26px; max-height: 26px;
    }}
    QProgressBar {{
        background: {RULE}; border: none; height: 2px;
        text-align: center; color: transparent;
    }}
    QProgressBar::chunk {{ background: {ACCENT}; }}
    QSplitter::handle {{ background: {RULE}; }}
    QSplitter::handle:horizontal {{ width: 1px; }}
    QSplitter::handle:vertical {{ height: 1px; }}
    """
