"""themob: application entry point.

Boots Qt, opens (and migrates) the database, runs the mandatory authorization
gate, and only then shows the main window. If the gate is declined, themob exits
without ingesting anything.

Same order as TOPRECON's ``gui/app.py``: crash guard, theme, gate, window.
"""
from __future__ import annotations

import logging
import os
import sys
import traceback
from pathlib import Path

logger = logging.getLogger("themob")


def _install_crash_guard(log_path: Path) -> None:
    """Keep a stray exception in a Qt slot or paint handler from killing the app.

    PyQt6 calls ``qFatal`` for an exception escaping a virtual method, which
    terminates the process with no visible error. Log the traceback and keep the
    app alive instead: a security tool that vanishes mid-assessment is worse
    than one that reports a bug.
    """
    def hook(exc_type, value, tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            return
        text = "".join(traceback.format_exception(exc_type, value, tb))
        logger.error("Unhandled exception (app kept alive):\n%s", text)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError:
            pass

    sys.excepthook = hook


def main(argv: list[str] | None = None) -> int:
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import QApplication

    from ..storage.db import open_database
    from ..storage.repositories import Repositories
    from ..storage.workspace import default_root
    from ..audit.attestation import AuditTrail
    from ..orchestrator.intake import IntakeError
    from . import theme
    from .auth_gate import AuthorizationGate, authorize
    from .main_window import MainWindow
    from .widgets.dialog import MessageDialog

    logging.basicConfig(
        level=os.environ.get("THEMOB_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    root = default_root()
    _install_crash_guard(root / "crash.log")

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("themob")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(theme.stylesheet())

    database = open_database(root / "themob.db")
    repos = Repositories(database)
    audit = AuditTrail(repos.audit)

    # --- the gate, before anything is ingested -------------------------------
    gate = AuthorizationGate()
    if gate.exec() != AuthorizationGate.DialogCode.Accepted:
        logger.info("Authorization declined. Exiting.")
        database.close_all()
        return 0

    decision = gate.result()
    if decision is None:                                   # pragma: no cover
        database.close_all()
        return 0

    try:
        intake_result = authorize(decision, repos, audit, root=root)
    except (IntakeError, PermissionError) as exc:
        MessageDialog.show_error(None, "The target could not be accepted.", str(exc))
        database.close_all()
        return 1

    window = MainWindow(database, root)
    window.load_project(intake_result)
    window.show()
    return app.exec()


if __name__ == "__main__":
    # Running this file directly is the obvious thing to try, and it cannot
    # work: main() imports its siblings relatively, which needs the package
    # context that `python main.py` does not provide. Python's own message for
    # that is "attempted relative import with no known parent package", which
    # says nothing about what to do instead. Say it here.
    if not __package__:
        print(
            "Run themob as a module from the repository root, not as a script:\n"
            "\n"
            "    cd " + str(Path(__file__).resolve().parents[2]) + "\n"
            "    python -m themob\n"
            "\n"
            "themob/app/main.py imports its siblings relatively, so it needs to "
            "be loaded as part of the themob package.",
            file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
