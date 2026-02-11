#!/home/seed_search2/venv/bin/python3
"""
NIST Watcher - Status Reporter
================================

Runs periodically (via systemd timer) to monitor the cracker's progress
and send status report emails.

This script:
1. Reads the state log (last 50 hours)
2. Parses progress information
3. Checks for found matches
4. Formats a status report
5. Sends email via SendGrid
6. Exits (timer will run it again later)
"""

import os
import sys
from datetime import datetime, timezone, timedelta

# Import shared utilities
from nist_utils import (
    STATE_LOG, FOUND_FILE, PROJECT_DIR,
    send_email, parse_state_log, check_for_found
)


def get_recent_activity(hours=50):
    """
    Parse the state log and extract activity from the last N hours.
    
    Returns a dict with:
        - current_phase: str ("Phase 1", "Phase 2", "Phase 3", or "Unknown")
        - phase1_complete: bool
        - phase2_progress: str ("X/Y base phrases")
        - phase3_status: str (last PHASE3_STATUS line)
        - found_count: int
        - found_matches: list of str
        - recent_lines: list of important log lines
        - last_activity: datetime or None
        - errors: list of warning/error lines
    """
    state = parse_state_log()
    
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    
    # Filter lines from last N hours
    recent = []
    errors = []
    last_activity = None
    
    for timestamp_str, message in state["all_lines"]:
        if not timestamp_str:
            continue
            
        try:
            ts = datetime.fromisoformat(timestamp_str)
            if ts >= cutoff:
                recent.append((ts, message))
                last_activity = ts
                
                # Collect errors/warnings
                if "ERROR" in message or "WARNING" in message:
                    errors.append(message)
        except (ValueError, TypeError):
            pass
    
    # Determine current phase
    current_phase = "Unknown"
    if state["phase3_running"]:
        current_phase = "Phase 3 (Deep Noise)"
    elif state["phase2_complete"]:
        current_phase = "Phase 3 (Deep Noise)"
    elif len(state["phase2_done_indices"]) > 0:
        current_phase = "Phase 2 (Single Char Insertion)"
    elif state["phase1_complete"]:
        current_phase = "Phase 2 (Single Char Insertion)"
    else:
        current_phase = "Phase 1 (Base Phrases)"
    
    # Phase 2 progress
    phase2_progress = "Not started"
    if len(state["phase2_done_indices"]) > 0:
        # We don't know total without generating phrases, so estimate ~1350
        total_estimate = 1350
        done = len(state["phase2_done_indices"])
        percent = (done / total_estimate) * 100
        phase2_progress = f"{done}/{total_estimate} base phrases (~{percent:.1f}%)"
    
    return {
        "current_phase": current_phase,
        "phase1_complete": state["phase1_complete"],
        "phase2_complete": state["phase2_complete"],
        "phase2_progress": phase2_progress,
        "phase3_status": state["phase3_last_status"],
        "found_count": len(state["found"]),
        "found_matches": state["found"],
        "recent_lines": recent,
        "last_activity": last_activity,
        "errors": errors,
    }


def format_status_email():
    """Generate the status report email body."""
    
    activity = get_recent_activity(hours=50)
    now = datetime.now(timezone.utc)
    
    # Check if cracker is running
    cracker_status = "Running" if activity["last_activity"] and \
                     (now - activity["last_activity"]).total_seconds() < 3600 \
                     else "⚠️ POSSIBLY STOPPED"
    
    # Format last activity time
    if activity["last_activity"]:
        time_since = now - activity["last_activity"]
        hours = int(time_since.total_seconds() / 3600)
        minutes = int((time_since.total_seconds() % 3600) / 60)
        last_activity_str = f"{hours}h {minutes}m ago"
    else:
        last_activity_str = "Unknown"
    
    # Build email body
    body = f"""NIST Seeds Cracker Status Report
{'=' * 50}

CURRENT STATUS: {cracker_status}
Phase: {activity['current_phase']}
Last Activity: {last_activity_str}

PROGRESS:
"""
    
    # Phase 1
    if activity["phase1_complete"]:
        body += "  ✓ Phase 1: Complete\n"
    else:
        body += "  ⧗ Phase 1: In progress...\n"
    
    # Phase 2
    if activity["phase2_complete"]:
        body += "  ✓ Phase 2: Complete\n"
    elif len(activity.get("phase2_progress", "")) > 0:
        body += f"  ⧗ Phase 2: {activity['phase2_progress']}\n"
    else:
        body += "  ⧖ Phase 2: Not started\n"
    
    # Phase 3
    if activity["phase3_status"]:
        body += f"  ⧗ Phase 3: Running\n"
        body += f"     {activity['phase3_status']}\n"
    elif activity["phase2_complete"]:
        body += "  ⧗ Phase 3: Running (no status yet)\n"
    else:
        body += "  ⧖ Phase 3: Not started\n"
    
    # Found matches
    body += f"\nMATCHES FOUND: {activity['found_count']}\n"
    if activity["found_count"] > 0:
        body += "⚠️ CHECK THE FOUND FILE IMMEDIATELY!\n\n"
        for found in activity["found_matches"]:
            body += f"  • {found}\n"
    else:
        body += "  (None yet - still searching)\n"
    
    # Errors
    if activity["errors"]:
        body += f"\nERRORS/WARNINGS: {len(activity['errors'])}\n"
        for err in activity["errors"][-5:]:  # Last 5 errors
            body += f"  • {err}\n"
    
    # Recent activity summary
    body += f"\nRECENT ACTIVITY (last 50 hours):\n"
    
    important_lines = [
        msg for ts, msg in activity["recent_lines"]
        if any(keyword in msg for keyword in [
            "PHASE", "COMPLETE", "Starting phrase", "Completed in",
            "FOUND", "ERROR", "WARNING"
        ])
    ]
    
    if important_lines:
        for line in important_lines[-10:]:  # Last 10 important lines
            body += f"  • {line[:100]}\n"
    else:
        body += "  (No significant activity)\n"
    
    # Footer
    body += f"\n{'=' * 50}\n"
    body += f"Report generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    body += f"Next report scheduled in 24 hours\n"
    body += f"\nLogs: {STATE_LOG}\n"
    body += f"Found file: {FOUND_FILE}\n"
    
    return body


def main():
    """Main entry point for the watcher."""
    
    print("=" * 60)
    print("NIST Watcher - Generating Status Report")
    print("=" * 60)
    
    # Check if state log exists
    if not os.path.isfile(STATE_LOG):
        print(f"WARNING: State log not found at {STATE_LOG}")
        print("The cracker may not have started yet.")
        
        # Send a notification
        send_email(
            "NIST Watcher: Cracker Not Started",
            f"The watcher ran but found no state log.\n\n"
            f"This means the cracker hasn't started yet or the state log "
            f"was deleted.\n\n"
            f"Expected location: {STATE_LOG}"
        )
        return
    
    # Check for found matches (high priority)
    found_content = check_for_found()
    if found_content:
        print("⚠️ FOUND FILE EXISTS - Including in report")
    
    # Generate and send report
    print("Parsing logs and generating report...")
    email_body = format_status_email()
    
    print("Sending status report email...")
    success = send_email(
        "NIST Cracker Status Report",
        email_body
    )
    
    if success:
        print("✓ Status report sent successfully")
    else:
        print("✗ Failed to send status report")
        return 1
    
    print("=" * 60)
    print("Watcher complete. Exiting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
