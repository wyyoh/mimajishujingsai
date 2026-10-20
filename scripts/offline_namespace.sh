#!/usr/bin/env bash
set -euo pipefail
ip link set lo up
cd "$1"
export GRID_RUNTIME="$2"
export PYTHONPATH="$PWD"
.venv/bin/python scripts/offline_run.py
.venv/bin/python scripts/v41_offline_run.py
exec .venv/bin/python scripts/v42_offline_run.py
