#!/bin/bash
# Kill the nist_seeds_cracker.py python process and any john it spawned.
# Systemd will auto-restart both in 2 hours (RestartSec=7200).

set -e

CRACKER_SCRIPT="nist_seeds_cracker.py"

# Find the cracker's PID
CRACKER_PID=$(pgrep -f "$CRACKER_SCRIPT" 2>/dev/null || true)

if [ -z "$CRACKER_PID" ]; then
    echo "nist_seeds_cracker.py is not running."
else
    # Kill john children of the cracker first (graceful, then force)
    JOHN_PIDS=$(pgrep -P "$CRACKER_PID" -x john 2>/dev/null || true)
    if [ -n "$JOHN_PIDS" ]; then
        echo "Killing john (PID $JOHN_PIDS)..."
        kill $JOHN_PIDS 2>/dev/null || true
    fi

    # Now kill the python cracker
    echo "Killing nist_seeds_cracker.py (PID $CRACKER_PID)..."
    kill "$CRACKER_PID"

    echo "Done. Systemd will restart in 2 hours."
fi
