#!/bin/sh
set -eu

if command -v focuswall >/dev/null 2>&1; then
  sudo focuswall uninstall "$@"
else
  cd "$(dirname "$0")"
  PYTHON_BIN="$(command -v python3)"
  sudo "$PYTHON_BIN" ./focuswall.py uninstall "$@"
fi
