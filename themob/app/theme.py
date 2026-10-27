"""themob's theme: violet, flat, dense, on the desktop UI kit.

One ground colour, hairline rules, and typographic hierarchy. Structure comes
from rules and weight, never from bordered cards, and nothing is a bordered box
inside another bordered box. The accent marks one thing per screen.

Built on the kit (reference/theme.py): the kit's token names live in ``COLORS``
with themob's violet values (the themob token map), so new code reads
``COLORS["accent"]`` while the long-standing module constants below stay as
aliases for the panels that already use them. Two kit rules are honoured here and
override themob's earlier choices:

* selection is quiet. A selected nav item or list row brightens to the primary
  text and goes semibold on a neutral ``raised`` step. No accent bar, no tint, no
  accent-coloured text.
* the window controls are flush. The title bar has no right margin and the close
  button runs to the window's corner, on the main window and every dialog. The
  native frame (``winframe``) draws the border, shadow and rounded corners, so
  the shell no longer paints its own radius.

The severity ramp stays semantic: critical red, low green. ``INFO`` is the one
level that turns violet, since it carries no urgency.
"""
from __future__ import annotations

from ..model.enums import EntityType, Severity

# --- ground ----------------------------------------------------------------
BG_BASE = "#100a1e"          # the page. Everything sits on this
# The rail and footer, darker than the page, so they recede without a border.
BG_SIDEBAR = "#040209"
BG_RAISED = "#1a1230"        # inputs and hover states only, never a "card"
BG_HOVER = "#221741"         # stronger hover, and the quiet selected step
BG_SELECT = "#35225c"        # legacy brighter selection (kept as a token)

# The title bar sits lighter than the page, the third of three tone bands.
BG_TITLEBAR = "#231849"
BG_TITLEBAR_HOVER = "#31226a"

# The assistant's answer surface. Deliberately off the violet ground: the model
# speaks in a different voice from the deterministic engine, so its output reads
# on a distinct, cooler slate rather than one more purple panel. A hue change,
# not a louder purple.
BG_ASSISTANT = "#111a2b"

# Window corner radius. Kept as a token for callers; the native frame rounds the
# window now, so the shell does not paint this.
WINDOW_RADIUS = 10

# Hairlines. A divider, and a slightly stronger frame edge.
RULE = "#2b1f40"
RULE_STRONG = "#3c2a58"

# Legacy aliases; a few call sites still reach for the old token names.
BG_CANVAS = BG_SIDEBAR
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
SELECTION_BG = BG_HOVER       # the quiet selected step (was BG_SELECT)
# A bright flush red for the close button's hover fill, so it reads at the
# window corner. The X is drawn dark against it.
CLOSE_HOVER = SEVERITY_COLORS[Severity.CRITICAL]
ON_ACCENT = "#ffffff"
DANGER_BG = "#1a0a12"
DANGER_BORDER = "#40142a"

# The graph legend needs eleven colours that are actually distinguishable.
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

# Syntax colours for the decompiled-code browser.
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


# --- kit token names --------------------------------------------------------
# The desktop UI kit addresses colours by these names. themob's violet values
# are mapped onto them (the themob token map), so kit-shaped code and the
# painted widgets share one source of truth with the panels above.
COLORS = {
    "ground": BG_BASE,
    "band": BG_SIDEBAR,
    "band_hi": BG_TITLEBAR,
    "band_hi_hover": BG_TITLEBAR_HOVER,
    "raised": BG_RAISED,
    "raised_hi": BG_HOVER,
    "selection": BG_SELECT,
    "rule": RULE,
    "edge": RULE_STRONG,
    "text": TEXT_PRIMARY,
    "text_body": TEXT_BODY,
    "text_dim": TEXT_SECONDARY,
    "text_faint": TEXT_MUTED,
    "accent": ACCENT,
    "accent_dim": ACCENT_DIM,
    "accent_hover": ACCENT_HOVER,
    "accent_bright": ACCENT_BRIGHT,
    "accent_soft": ACCENT_SOFT,
    "on_accent": ON_ACCENT,
    # The semantic ramp, under the kit's names.
    "ok": SEVERITY_COLORS[Severity.LOW],
    "warn": SEVERITY_COLORS[Severity.HIGH],
    "partial": SEVERITY_COLORS[Severity.MEDIUM],
    "frag": SEVERITY_COLORS[Severity.INFO],
    "danger": SEVERITY_COLORS[Severity.CRITICAL],
    "close_hover": CLOSE_HOVER,
}

_STATUS_COLORS = {
    "critical": SEVERITY_COLORS[Severity.CRITICAL],
    "high": SEVERITY_COLORS[Severity.HIGH],
    "medium": SEVERITY_COLORS[Severity.MEDIUM],
    "low": SEVERITY_COLORS[Severity.LOW],
    "info": SEVERITY_COLORS[Severity.INFO],
}


def status_color(status_value: str) -> str:
    """The kit's status accessor, mapped onto themob's severity ramp."""
    return _STATUS_COLORS.get(status_value, TEXT_SECONDARY)


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
    QMainWindow, QDialog {{ background-color: {BG_BASE}; }}
    /* The native frame draws the border, shadow and rounded corners, so #root
       is a plain filled ground with no radius and no border of its own. */
    QWidget#root {{ background-color: {BG_BASE}; }}

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
    QLabel[role="sectionLabel"] {{
        color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;
    }}

    /* --- rules: the only dividers ---------------------------------------- */
    QFrame#ruleH, QFrame#ruleV {{ background-color: {RULE}; border: none; }}

    /* --- title bar: the lighter third band ------------------------------- */
    QFrame#titleBar {{
        background-color: {BG_TITLEBAR};
        border: none;
        min-height: 64px; max-height: 64px;
    }}
    QLabel#titleSubLabel {{ color: {TEXT_BODY}; font-size: 11px; }}
    QLabel#titleLabel {{ color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 600; }}

    /* --- dialog title bar: the kit's 46px bar, so the close button is flush -- */
    QFrame#dialogBar {{
        background-color: {BG_TITLEBAR};
        border: none;
        min-height: 46px; max-height: 46px;
    }}

    /* --- window controls: flush to the top-right corner, no right margin.
       The close hover fill is a bright red that runs to the window edge. ---- */
    QPushButton#winBtn, QPushButton#winClose {{
        background: transparent; border: none; padding: 0;
    }}
    QPushButton#winBtn:hover {{ background-color: {BG_TITLEBAR_HOVER}; }}
    QPushButton#winBtn[hot="true"] {{ background-color: {BG_TITLEBAR_HOVER}; }}
    QPushButton#winClose:hover {{ background-color: {CLOSE_HOVER}; }}

    /* --- sidebar: a dark band, quiet selection --------------------------- */
    QWidget#sidebar {{
        background-color: {BG_SIDEBAR};
        border: none;
    }}
    QFrame#sidebarNav {{ background: transparent; border: none; }}
    /* Selection is quiet: brighter, semibold text on a neutral raised step.
       No accent bar, no tint, no accent-coloured text. */
    QPushButton#navItem {{
        background: transparent;
        border: none;
        color: {TEXT_SECONDARY};
        text-align: left;
        padding: 7px 12px;
        font-size: 12.5px;
    }}
    QPushButton#navItem:hover {{
        background-color: {BG_RAISED};
        color: {TEXT_PRIMARY};
    }}
    QPushButton#navItem:checked {{
        background-color: {BG_RAISED};
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
        background-color: {BG_RAISED};
        border: 1px solid {RULE_STRONG};
        color: {TEXT_BODY};
        padding: 6px 14px;
        font-size: 12px;
    }}
    QPushButton:hover {{ background-color: {BG_HOVER}; border-color: {ACCENT_DIM}; color: {TEXT_PRIMARY}; }}
    QPushButton:pressed {{ background-color: {RULE}; }}
    QPushButton:disabled {{ color: {TEXT_MUTED}; border-color: {RULE}; background-color: {BG_SIDEBAR}; }}
    QPushButton#primary {{
        background-color: {ACCENT_DIM};
        border: 1px solid {ACCENT_DIM};
        color: {ON_ACCENT};
        font-weight: 600;
    }}
    QPushButton#primary:hover {{
        background-color: {ACCENT_HOVER}; border-color: {ACCENT_HOVER};
    }}
    QPushButton#primary:disabled {{
        background-color: {RULE}; border-color: {RULE}; color: {TEXT_MUTED};
    }}

    /* --- inputs ----------------------------------------------------------- */
    QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
        background-color: {BG_RAISED};
        border: 1px solid {RULE};
        padding: 6px 9px;
        color: {TEXT_PRIMARY};
        selection-background-color: {BG_HOVER};
    }}
    QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{
        border: 1px solid {ACCENT_DIM};
    }}
    QComboBox::drop-down {{ border: none; width: 16px; }}
    QComboBox QAbstractItemView {{
        background-color: {BG_RAISED};
        border: 1px solid {RULE};
        selection-background-color: {BG_HOVER};
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

    /* --- lists: flush rows, quiet neutral selection ---------------------- */
    QListWidget {{ background: transparent; border: none; }}
    QListWidget::item {{ padding: 6px 8px; color: {TEXT_BODY}; }}
    QListWidget::item:hover {{ background-color: {BG_RAISED}; }}
    QListWidget::item:selected {{ background-color: {BG_HOVER}; color: {TEXT_PRIMARY}; }}

    /* --- tables: flush, hairline-separated, quiet selection -------------- */
    QTableWidget, QTableView, QTreeWidget {{
        background-color: transparent;
        alternate-background-color: transparent;
        gridline-color: transparent;
        border: none;
        selection-background-color: {BG_HOVER};
        selection-color: {TEXT_PRIMARY};
        font-size: 12.5px;
    }}
    QTableWidget::item {{
        padding: 6px 8px;
        border-bottom: 1px solid #150e22;
    }}
    QTableWidget::item:selected {{ background-color: {BG_HOVER}; color: {TEXT_PRIMARY}; }}
    QTableWidget::item:hover:!selected, QTreeWidget::item:hover:!selected {{
        background-color: {BG_RAISED};
    }}
    QTreeWidget::item {{ padding: 3px 4px; }}
    QTreeWidget::item:selected {{ background-color: {BG_HOVER}; color: {TEXT_PRIMARY}; }}
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
