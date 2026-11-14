#!/usr/bin/env bash
# Start the threat-intel HUD on 127.0.0.1:8102 (creates the venv on first run).
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8102}"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv --system-site-packages .venv
fi
.venv/bin/pip install -q -r requirements.txt
if [ ! -f data/threatintel.db ]; then
    echo "No database yet: loading the offline demo fixtures"
    .venv/bin/python -m threatintel seed
fi
exec .venv/bin/python -m uvicorn threatintel.server:app --host 127.0.0.1 --port "$PORT"
