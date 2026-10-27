"""``python -m themob`` (and the ``themob`` console script): window or command.

With no arguments the desktop console opens. With a subcommand, themob runs
headless, and every capability the window has is one of them: ``themob --help``
lists them all, and each has its own ``--help``.

The machine-facing commands a pipeline scripts against, ``scan``, ``diff``,
``verify`` and ``sign-pack``, are routed straight to their entry points so those
stay stable; ``--check`` is the preflight; everything else, and ``--help``, goes
through the one dispatcher in :mod:`themob.cli`.
"""
from __future__ import annotations

import sys

# Routed directly so their entry points stay stable for pipelines and tests.
_DIRECT = {
    "scan": "main",
    "diff": "diff_main",
    "verify": "verify_main",
    "sign-pack": "sign_pack_main",
}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        from .app.main import main as launch
        return launch()

    first = argv[0]

    if first in ("--check", "-c", "check"):
        from .preflight import report
        return report()

    if first in _DIRECT:
        from . import cli
        return getattr(cli, _DIRECT[first])(argv[1:])

    # Every other subcommand, plus --help and -h, through the one dispatcher.
    from .cli import run
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
