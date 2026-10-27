"""Inject themob's UI design rules before any edit to the app layer.

Wired as a ``PreToolUse`` hook on ``Write|Edit`` (see .claude/settings.json).
Claude Code passes the tool call as JSON on stdin; when the target is under
``themob/app/`` this prints the rules, and Claude reads that output as context
before writing the file.

The rules exist because the first version of this UI was a grid of rounded
bordered cards with letter-spaced neon capitals and a lot of air, generic,
and not what this project looks like.
"""
from __future__ import annotations

import json
import sys

RULES = """\
themob UI rules: this edit touches themob/app/. Follow these:

BANNED, no exceptions:
  * Rounded/bordered "cards". Sections are a label + a 1px hairline + content.
  * A bordered box inside another bordered box. Ever.
  * Coloured "banner" or callout boxes with an icon (the ⓘ/⚠ box pattern).
  * ALL-CAPS headings, and letter-spacing on anything except the wordmark.
  * Accent colour on every heading. The accent marks ONE thing per screen.
  * Loose padding. Page margin 22px, 20px between sections, 8px inside one.

REQUIRED:
  * Build from themob/app/widgets/common.py: Section, Rule, KeyValues, Metric,
    MetricRow, SeverityCounts, CountRow, caption/heading/mono/value.
  * Sentence case everywhere: "Top findings", not "TOP FINDINGS".
  * One ground colour. Nothing floats above the page.
  * Hierarchy comes from size and weight, not from borders and fills.
  * The severity ramp stays semantic: critical red, low green. Never restyle
    it to match the palette.
  * No inline hex. Every colour comes from themob/app/theme.py.

Study HiveDefend and TOPRECON for structure, signals/slots, threading,
QGraphicsView: not for their visual style. themob looks like itself.\
"""


def main() -> int:
    # Windows consoles default to cp1252, which cannot encode the glyphs named
    # in the rules. A hook that raises is worse than no hook at all, so force
    # UTF-8 and fall back to replacement rather than dying.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):        # already wrapped, or a pipe
            pass

    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    path = str(tool_input.get("file_path") or "").replace("\\", "/")
    if "/themob/app/" in path and path.endswith(".py"):
        print(RULES)
    return 0


if __name__ == "__main__":
    sys.exit(main())
