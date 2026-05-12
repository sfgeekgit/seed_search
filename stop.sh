#!/bin/bash
# Stop the NIST cracker and schedule an automatic restart via systemd.

HOURS=${1:-6}

if [ "$HOURS" = "--help" ] || [ "$HOURS" = "-h" ]; then
    cat <<EOF
Usage: stop.sh [HOURS]
       stop.sh --help

Stops the NIST cracker and schedules an automatic restart via systemd.

  HOURS    Number of hours to stay stopped (default: 6)

Examples:
  stop.sh        Stop for 6 hours (default)
  stop.sh 8      Stop for 8 hours

The restart is managed by systemd and is fire-and-forget: you can
close your shell and log out -- the service will restart automatically
after the specified time. Note: a server reboot during the stop period
will cause the service to restart immediately.
EOF
    exit 0
fi

if ! [[ "$HOURS" =~ ^[0-9]+$ ]]; then
    echo "Error: HOURS must be a positive integer (got: $HOURS)"
    exit 1
fi

DELAY="${HOURS}h"

echo "Stopping nist-cracker for ${HOURS} hour(s)..."
sudo systemctl stop nist-cracker

echo "Scheduling restart in ${HOURS} hour(s)..."
sudo systemd-run --on-active="$DELAY" systemctl start nist-cracker

echo "Done. The cracker will restart automatically in ${HOURS} hour(s)."
echo "You can close your shell -- systemd owns the timer."
