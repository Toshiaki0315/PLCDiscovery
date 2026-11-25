#!/usr/bin/env bash
# Run the CI checks (lint, unit and integration tests) on this machine.
# Uses .venv when the development tools are installed there (requirements-dev.txt;
# the launchers create it with the runtime packages only), otherwise python3.
# Options: --lint, --no-integration
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
PY=python3
if [ -x .venv/bin/python ] && .venv/bin/python -c "import black, pytest" 2>/dev/null; then
    PY=.venv/bin/python
fi
exec "$PY" scripts/check.py "$@"
