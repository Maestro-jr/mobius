"""Assistant: explain this app's findings and coach the fix, in plain language.

The product surface inside the console. It asks themob's assistant core
(themob.assist), which reads the real findings and asks a model to put them in
plain language with a step-by-step fix. Honest data is enforced in the core, not
here; this page only collects the question, runs the call off the UI thread, and
renders the state the core returns: a model connected or not, nothing to explain
yet, or the answer.

The layout is the house style: a labelled section, a hairline, and content. The
one accent on the page is the Ask button; everything else is text and a rule.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QFrame, QHBoxLayout, QLineEdit,
                             QPushButton, QScrollArea, QTextEdit, QVBoxLayout,
                             QWidget)

from .. import theme
from ..widgets.common import Rule, Section, caption, page_layout, value


def _flatten_markdown_tables(md: str) -> str:
    """Rewrite GitHub-style tables as bulleted lists before rendering.

    Qt's Markdown renderer collapses a table when a cell contains a pipe, and
    every shell command with a pipe does, which merges the cells into one
    unreadable run. The assistant is told not to emit tables, but not every
    model obeys, so this is the backstop: a list is lenient where the table
    parser is strict, and it reads far better than a mangled table in a narrow
    panel. Content inside fenced code blocks is left untouched.
    """
    lines = md.split("\n")
    out: list[str] = []
    index, total = 0, len(lines)
    in_fence = False

    def is_separator(text: str) -> bool:
        stripped = text.strip()
        return (stripped.startswith("|") and "-" in stripped
                and set(stripped) <= set("-:| "))

    def split_cells(row: str) -> list[str]:
        # Split on the column pipes only, never a pipe inside an inline-code span,
        # so a cell like `readelf ... | grep RELRO` survives as one piece.
        body = row.strip().strip("|")
        cells, buf, in_code = [], [], False
        for char in body:
            if char == "`":
                in_code = not in_code
                buf.append(char)
            elif char == "|" and not in_code:
                cells.append("".join(buf).strip())
                buf = []
            else:
                buf.append(char)
        cells.append("".join(buf).strip())
        return cells

    while index < total:
        line = lines[index]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            index += 1
            continue
        if (not in_fence and line.strip().startswith("|")
                and index + 1 < total and is_separator(lines[index + 1])):
            header = split_cells(line)
            index += 2                                   # skip header + separator
            while (index < total and lines[index].strip().startswith("|")
                   and not lines[index].lstrip().startswith("```")):
                cells = split_cells(lines[index])
                parts = []
                for position, cell in enumerate(cells):
                    if not cell:
                        continue
                    label = header[position] if position < len(header) else ""
                    parts.append(f"**{label}:** {cell}" if label else cell)
                out.append(("- " + "  ".join(parts)) if parts else "")
                index += 1
            out.append("")
        else:
            out.append(line)
            index += 1
    return "\n".join(out)


class _AskWorker(QThread):
    """Runs the assistant or the agent off the UI thread; it is a network round trip."""

    done = pyqtSignal(dict)

    def __init__(self, home, project: str, question: str, mode: str = "ask",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._home, self._project, self._question = home, project, question
        self._mode = mode

    def run(self) -> None:                                     # noqa: D401
        try:
            if self._mode == "agent":
                from ...assist import agent
                result = agent.run(self._home, self._project, self._question)
            else:
                from ...assist import core
                result = core.ask(self._home, self._project, self._question)
        except Exception as exc:                               # noqa: BLE001
            result = {"error": f"the assistant failed: {exc}"}
        self.done.emit(result)


def _describe(proposal: dict) -> str:
    action = proposal.get("action")
    reason = proposal.get("reason", "")
    if action == "record_verdict":
        verdict = proposal.get("status", "").replace("_", "-")
        return f"Mark {proposal.get('fingerprint', '')[:12]} as {verdict}: {reason}"
    if action == "rea_prepare":
        return f"Hand {proposal.get('target', '')} to REA: {reason}"
    if action == "rescan":
        return f"Re-run analysis: {reason}"
    return str(action)


class AssistantPanel(QScrollArea):
    """Ask about the findings; get an explanation and a fix, grounded in them."""

    rescan_requested = pyqtSignal()        # an approved 'rescan' proposal

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        host = QWidget()
        self.setWidget(host)
        self._root = page_layout(host)

        self._home = None
        self._project: str = ""
        self._worker: _AskWorker | None = None
        self._build()

    # ------------------------------------------------------------------ build

    def _build(self) -> None:
        panel = Section("Assistant")

        self._status = caption("")
        self._status.setWordWrap(True)
        panel.body.addWidget(self._status)

        self._question = QLineEdit()
        self._question.setPlaceholderText(
            "ask about this app's findings, e.g. what are my worst issues and "
            "how do I fix them?")
        self._question.returnPressed.connect(self._on_ask)
        panel.body.addWidget(self._question)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self._ask = QPushButton("Ask")
        self._ask.setObjectName("primary")
        self._ask.clicked.connect(self._on_ask)
        row.addWidget(self._ask)
        self._agent_mode = QCheckBox("Investigate (agent)")
        self._agent_mode.setToolTip(
            "The agent calls themob's tools across a few steps to dig in, "
            "instead of a single pass. It uses more of the model's budget.")
        row.addWidget(self._agent_mode)
        row.addStretch()
        panel.body.addLayout(row)

        panel.body.addWidget(Rule())

        # The answer sits on its own surface, off the violet ground, and the
        # model's markdown (tables, headings, code) is rendered rather than
        # shown raw. It is read-only output, not a card for the sake of a card.
        self._answer = QTextEdit()
        self._answer.setReadOnly(True)
        self._answer.setMinimumHeight(240)
        self._answer.setPlaceholderText(
            "The explanation and fix plan appear here. Every statement is grounded "
            "in what themob found; nothing is invented.")
        self._answer.setStyleSheet(
            f"QTextEdit {{ background:{theme.BG_ASSISTANT}; border:none;"
            f" color:{theme.TEXT_PRIMARY}; font-family:{theme.FONT_UI};"
            f" font-size:13px; padding:12px; }}")
        panel.body.addWidget(self._answer, 1)

        # Gated actions the agent recommends. Each gets an Approve button; the
        # action runs only on the click, and the gated tool enforces its own
        # gate on top. Empty and invisible until there is something to approve.
        self._proposals = QWidget()
        self._proposals_layout = QVBoxLayout(self._proposals)
        self._proposals_layout.setContentsMargins(0, 8, 0, 0)
        self._proposals_layout.setSpacing(6)
        panel.body.addWidget(self._proposals)

        self._panel = panel
        self._root.addWidget(panel, 1)
        self._refresh_status()

    # ------------------------------------------------------------------- data

    def bind(self, home) -> None:
        """Give the panel the project store to work against."""
        self._home = home
        self._refresh_status()

    def load(self, project_id: str) -> None:
        self._project = project_id or ""
        self._refresh_status()

    def clear(self) -> None:
        self._project = ""
        self._answer.clear()
        self._clear_proposals()
        self._refresh_status()

    def _refresh_status(self) -> None:
        """Decide what the page can do, and say why when it cannot."""
        from ...assist import core

        state = core.status(self._home)
        ready = state["licensed"] and state["llm_ready"]
        self._ask.setEnabled(ready and bool(self._project))

        if state["enforced"] and not state["licensed"]:
            self._status.setText(
                f"This is a licensed feature: {state['license_reason']}")
        elif not state["llm_ready"]:
            self._status.setText(f"No model connected yet. {state['llm_reason']}.")
        elif not self._project:
            self._status.setText(
                "Authorize and analyze an app, then I can explain what themob "
                "found and how to fix it.")
        else:
            provider = state["provider"] or "the model"
            self._status.setText(f"Ready, using {provider}.")

    # ---------------------------------------------------------------- actions

    def _on_ask(self) -> None:
        if not self._ask.isEnabled():
            return
        question = self._question.text().strip()
        mode = "agent" if self._agent_mode.isChecked() else "ask"
        self._clear_proposals()
        self._ask.setEnabled(False)
        self._ask.setText("Investigating" if mode == "agent" else "Thinking")
        self._answer.setPlainText(
            "Investigating across a few steps..." if mode == "agent"
            else "Working on it...")

        self._worker = _AskWorker(self._home, self._project, question, mode, self)
        self._worker.done.connect(self._on_answer)
        self._worker.start()

    def _on_answer(self, result: dict) -> None:
        self._ask.setText("Ask")
        self._refresh_status()
        if "error" in result:
            self._answer.setPlainText(result["error"])
            return
        answer = result.get("answer", "")
        steps = result.get("steps")
        if steps:
            used = ", ".join(dict.fromkeys(s["tool"] for s in steps))
            answer = f"*Investigated via: {used}.*\n\n{answer}"
        # The model answers in markdown; render it so headings, lists and code
        # read as a report, not raw hashes. Tables are flattened to lists first:
        # Qt's table parser breaks on a pipe inside a cell (every grep command).
        self._answer.setMarkdown(_flatten_markdown_tables(answer))
        self._show_proposals(result.get("proposals") or [])

    # -------------------------------------------------------------- proposals

    def _clear_proposals(self) -> None:
        while self._proposals_layout.count():
            item = self._proposals_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)

    def _show_proposals(self, proposals: list) -> None:
        self._clear_proposals()
        if not proposals:
            return
        self._proposals_layout.addWidget(
            caption("Recommended actions. Each runs only when you approve it."))
        for proposal in proposals:
            row = QWidget()
            inner = QHBoxLayout(row)
            inner.setContentsMargins(0, 0, 0, 0)
            label = value(_describe(proposal))
            label.setWordWrap(True)
            inner.addWidget(label, 1)
            button = QPushButton("Approve")
            button.clicked.connect(
                lambda _checked=False, p=proposal, b=button: self._approve(p, b))
            inner.addWidget(button)
            self._proposals_layout.addWidget(row)

    def _approve(self, proposal: dict, button: QPushButton) -> None:
        """Run one approved gated action. The tool enforces its own gate too."""
        button.setEnabled(False)
        button.setText("...")
        action = proposal.get("action")
        try:
            if action == "record_verdict":
                from ...mcp import tools
                result = tools.record_verdict(
                    self._home, self._project, proposal["fingerprint"],
                    proposal["status"], proposal.get("reason", ""))
                self._settle(button, result, "Recorded")
            elif action == "rea_prepare":
                from ... import rea
                result = rea.prepare(self._home, self._project, "native",
                                     proposal["target"])
                self._settle(button, result, "Prepared")
                if "error" not in result:
                    button.setToolTip(f"run: {result.get('command', '')}")
            elif action == "rescan":
                self.rescan_requested.emit()
                button.setText("Started")
            else:
                button.setText("Unknown")
        except Exception as exc:                               # noqa: BLE001
            button.setText("Failed")
            button.setToolTip(str(exc))

    @staticmethod
    def _settle(button: QPushButton, result: dict, done: str) -> None:
        if isinstance(result, dict) and "error" in result:
            button.setText("Failed")
            button.setToolTip(str(result["error"]))
        else:
            button.setText(done)
