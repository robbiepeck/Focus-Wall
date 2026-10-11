#!/bin/sh
set -eu

cd "$(dirname "$0")"
PYTHON_BIN="$(command -v python3)"
sudo "$PYTHON_BIN" ./focuswall.py install "$@"
