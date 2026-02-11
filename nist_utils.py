"""
nist_utils.py - Shared utilities for the NIST Seeds Cracker project
====================================================================

This file is imported by both:
  - nist_seeds_cracker.py  (the main cracker daemon)
  - nist_watcher.py        (the status/alert watcher daemon, not yet written)

It contains shared constants (file paths), the email sending function,
and the state log parser.

FILE LAYOUT ON DISK:
    /home/seeds/
        nist_seeds_cracker.py    # Main cracker daemon (Phase 1/2/3)
        nist_watcher.py          # Watcher daemon (status emails, alerts)
        nist_utils.py            # THIS FILE - shared utilities
        nist-seeds-john.txt      # Target hashes in John format
        nist_cracker_state.log   # Append-only state/checkpoint log
        nist_seeds_FOUND.txt     # Created only if a match is found
        tmp/                     # Temp wordlist files (auto-cleaned)

EMAIL:
    System mail is configured separately on this box. The send_email()
    function just calls the `mail` command and trusts the system config.
    Both the cracker and the watcher call send_email() — the cracker
    calls it immediately if a match is found, the watcher calls it on
    a timer for status reports (and also if it sees the FOUND file).
    Getting duplicate "FOUND" emails from both is fine and expected.

STATE LOG FORMAT:
    The state log at STATE_LOG is an append-only text file. Each line is:
        ISO_TIMESTAMP: MESSAGE
    
    The cracker writes these specific marker lines that have meaning:
    
    "PHASE1_COMPLETE"
        Written once when Phase 1 finishes. Means all base phrases have
        been checked with John Jumbo rules. Phase 1 is skipped on restart
        if this marker exists.
    
    "PHASE2_BASE_DONE:INDEX:PHRASE"
        Written each time a base phrase completes in Phase 2. INDEX is the
        0-based index into the sorted base phrase list. PHRASE is the actual
        phrase text (for human readability). Phase 2 skips any phrase whose
        index appears in a PHASE2_BASE_DONE line.
        Example: "2025-02-10T12:00:00+00:00: PHASE2_BASE_DONE:42:Jerry deserves a raise"
    
    "PHASE2_COMPLETE"
        Written once when all base phrases are done in Phase 2.
    
    "PHASE3_STATUS: batches=N, generated=N, elapsed=Nh, sample='...'"
        Written every PHASE3_LOG_INTERVAL seconds (default 4 hours) during
        Phase 3. This is just informational — not a checkpoint. Useful for
        the watcher to report progress and confirm the cracker is alive.
    
    "FOUND: POT_ENTRY"
        Written if John the Ripper cracks a hash. POT_ENTRY is the raw
        line from John's pot file. THIS IS THE BIG ONE.
    
    Other lines are general status messages (phase start/stop, errors,
    candidate counts, timing info). They're useful for human reading
    and for the watcher's daily summary.

FOUND FILE:
    FOUND_FILE is only created/written to if a match is found. If this
    file exists and is non-empty, we won the bounty. The watcher should
    check for this file on every cycle.
"""

import os
import sys
from datetime import datetime, timezone

# Add venv to path for SendGrid
sys.path.insert(0, '/home/seed_search2/venv/lib/python3.11/site-packages')

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content


# =============================================================================
# SHARED PATH CONSTANTS
# All paths are absolute so both scripts work regardless of cwd.
# =============================================================================

# Project directory — everything lives here
PROJECT_DIR = "/home/seed_search2"

# John the Ripper binary (compiled from source, lives in /tmp)
JOHN_BINARY = "/tmp/john-jumbo/run/john"

# Hash file with NIST seed targets in John format (username:hash)
HASH_FILE = os.path.join(PROJECT_DIR, "nist-seeds-john.txt")

# Append-only state/checkpoint log. Written by the cracker, read by both.
# See STATE LOG FORMAT in module docstring above for line format details.
STATE_LOG = os.path.join(PROJECT_DIR, "nist_cracker_state.log")

# Only created if a match is found. If non-empty, check it immediately.
FOUND_FILE = os.path.join(PROJECT_DIR, "nist_seeds_FOUND.txt")

# Temp directory for wordlist batches (cracker writes, auto-deletes)
TEMP_DIR = os.path.join(PROJECT_DIR, "tmp")

# John rules — always Jumbo for maximum coverage
JOHN_RULES = "Jumbo"

# Email recipient
EMAIL_TO = "sfgeek@gmail.com"

# SendGrid API key location
SENDGRID_KEY_FILE = os.path.expanduser("~/.sendgrid_key")


# =============================================================================
# EMAIL
# =============================================================================

def send_email(subject, body):
    """
    Send an email via SendGrid API.

    Both the cracker and watcher call this function:
    - Cracker: calls immediately when a match is found
    - Watcher: calls on its timer interval for status reports,
      and also if it detects the FOUND file

    If email fails, we print a warning but don't crash — the log files
    still have the information.
    """
    # Read API key from secure file
    try:
        with open(SENDGRID_KEY_FILE, 'r') as f:
            api_key = f.read().strip()
    except FileNotFoundError:
        print(f"WARNING: SendGrid API key file not found at {SENDGRID_KEY_FILE}", flush=True)
        return False
    except Exception as e:
        print(f"WARNING: Could not read SendGrid API key: {e}", flush=True)
        return False

    # Create the email message
    message = Mail(
        from_email=Email(EMAIL_TO, "NIST Seeds Cracker"),
        to_emails=To(EMAIL_TO),
        subject=subject,
        plain_text_content=Content("text/plain", body)
    )

    try:
        print(f"Sending email via SendGrid: {subject}", flush=True)
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)

        if response.status_code == 202:
            print(f"✓ Email sent successfully: {subject}", flush=True)
            return True
        else:
            print(f"WARNING: SendGrid unexpected response: {response.status_code}", flush=True)
            return False

    except Exception as e:
        print(f"WARNING: Failed to send email via SendGrid: {e}", flush=True)
        return False


# =============================================================================
# STATE LOG PARSING
# =============================================================================

def parse_state_log():
    """
    Parse the state log and return a structured summary.
    
    Returns a dict with:
        phase1_complete: bool
        phase2_done_indices: set of ints
        phase2_complete: bool
        phase3_running: bool (True if we've seen any Phase 3 status lines)
        phase3_last_status: str or None (most recent Phase 3 status line)
        found: list of str (any FOUND lines — hopefully not empty someday!)
        all_lines: list of (timestamp_str, message) tuples
        recent_lines: list of (timestamp_str, message) tuples from last 24h
    
    Used by:
    - The cracker: reads phase1_complete and phase2_done_indices to know
      what to skip on restart
    - The watcher: reads everything to build status reports
    """
    state = {
        "phase1_complete": False,
        "phase2_done_indices": set(),
        "phase2_complete": False,
        "phase3_running": False,
        "phase3_last_status": None,
        "found": [],
        "all_lines": [],
        "recent_lines": [],  # populated below
    }

    if not os.path.isfile(STATE_LOG):
        return state

    now = datetime.now(timezone.utc)

    try:
        with open(STATE_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Parse timestamp and message
                # Format: "2025-02-10T12:00:00+00:00: MESSAGE"
                timestamp_str = None
                message = line
                if ": " in line and line[0] == "2":  # starts with year
                    parts = line.split(": ", 1)
                    if len(parts) == 2:
                        timestamp_str = parts[0]
                        message = parts[1]

                state["all_lines"].append((timestamp_str, message))

                # Check if this line is from the last 24 hours
                if timestamp_str:
                    try:
                        ts = datetime.fromisoformat(timestamp_str)
                        if (now - ts).total_seconds() < 86400:
                            state["recent_lines"].append((timestamp_str, message))
                    except (ValueError, TypeError):
                        pass

                # Parse known markers
                if "PHASE1_COMPLETE" in message:
                    state["phase1_complete"] = True
                elif "PHASE2_BASE_DONE:" in message:
                    try:
                        marker = message.split("PHASE2_BASE_DONE:")[1]
                        idx = int(marker.split(":")[0])
                        state["phase2_done_indices"].add(idx)
                    except (ValueError, IndexError):
                        pass
                elif "PHASE2_COMPLETE" in message:
                    state["phase2_complete"] = True
                elif "PHASE3_STATUS:" in message:
                    state["phase3_running"] = True
                    state["phase3_last_status"] = message
                elif "FOUND:" in message:
                    state["found"].append(message)

    except Exception as e:
        print(f"WARNING: Error reading state log: {e}", flush=True)

    return state


def check_for_found():
    """
    Quick check: does the FOUND file exist and have content?
    
    Returns the file contents if found, None otherwise.
    Used by the watcher to trigger immediate alert emails.
    """
    if os.path.isfile(FOUND_FILE):
        try:
            with open(FOUND_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return None
