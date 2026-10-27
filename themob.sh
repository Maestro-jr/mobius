#!/bin/sh
# themob launcher (POSIX): run the console from a checkout without installing.
#
# `pip install .` gives you a `themob` command directly; this is for running
# straight from a clone. It finds a working Python 3 and puts this directory on
# PYTHONPATH so `python -m themob` resolves the package beside it.
#
# Rename or symlink this to `themob` on your PATH, or call it as `./themob.sh`.
# Set THEMOB_PYTHON to force a specific interpreter.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1

for py in "${THEMOB_PYTHON:-}" python3 python; do
    [ -n "$py" ] || continue
    if command -v "$py" >/dev/null 2>&1; then
        PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}"
        export PYTHONPATH
        exec "$py" -m themob "$@"
    fi
done

echo "themob: no Python 3 found on PATH. Set THEMOB_PYTHON to your interpreter." >&2
exit 127
