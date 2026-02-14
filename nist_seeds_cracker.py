#!/usr/bin/env python3
"""
NIST Elliptic Curve Seeds Cracker - Daemon Edition
====================================================

PURPOSE:
    Attempts to find the original English phrases that were SHA-1 hashed to
    produce the seed values for the NIST elliptic curves (P-192 through P-521).

    There is a $12,288 bounty (tripled if donated to charity) offered by
    Filippo Valsorda for cracking these hashes.

BACKGROUND:
    Jerry Solinas at the NSA generated these seeds in ~1997 by hashing
    "humorous" English phrases with SHA-1. He forgot the exact phrases
    before he passed away in 2023. Clues from multiple sources suggest:

    - The phrases mention TWO people (likely Jerry Solinas and Bob Reiter,
      who actually wrote the code, or possibly Laurie Law, Jerry's
      long-time co-author)
    - Something like "Give Bob and Jerry a raise" or "Bob and Jerry rule"
    - Probably includes a counter appended (because only ~1 in 200-500
      hashes produces a valid elliptic curve, so you need to try many)
    - Counter likely < 2400 for the largest curve
    - Jerry himself tried to remember the phrase and failed, which suggests
      it was human-readable (not noise-injected), but he just couldn't
      recall the exact wording

    Source: Steve Weis's research at saweis.net, Filippo Valsorda's bounty
    page, Jerry Solinas's own emails to Dan Bernstein (2015), and the
    Security Cryptography Whatever podcast episode with Steve Weis.

ARCHITECTURE:
    This script runs as a systemd daemon on a Debian server. It generates
    candidate phrases in Python, writes them to temp wordlist files, and
    feeds them to John the Ripper (Jumbo edition) which applies mangling
    rules and does the actual SHA-1 checking at ~10M H/s.

    Division of labor:
      1. Python (smart, clue-driven): name variations, counter formats,
         and in later phases, character insertion
      2. John the Ripper --rules=Jumbo (mechanical, broad): case variations,
         punctuation, digit appends, l33tspeak, character swaps, and
         thousands of other transformations

    We use John's Jumbo rules to handle case/punctuation variations and
    to cast a wider net with unexpected transformations. This eliminates
    redundancy while still covering edge cases we might not think of.

THREE PHASES:
    Phase 1: "The obvious check" (~1-6 hours)
        Generate all base phrase combinations with case/punctuation/counter
        variations. Feed to John with Jumbo rules. This covers the most
        likely candidates — the ones where we basically guessed the phrase
        right. If someone was going to crack this the easy way, this is it.
        Logged as complete when done; skipped on restart.

    Phase 2: "Single character insertion" (~weeks to months)
        For each base phrase, generate all variants, then systematically
        insert every printable ASCII character at every position. This
        covers the scenario where Jerry added one bit of noise — even a
        single extra character makes a phrase uncrackable by naive methods.
        We iterate deterministically (char by char, position by position)
        so we can checkpoint per base phrase. Each phrase takes hours with
        John's Jumbo rules on top. Logged per completed base phrase;
        skips completed phrases on restart.

    Phase 3: "Deep noise" (runs forever)
        Insert 2+ random characters at random positions into random base
        phrases. This is the true long shot — betting that Jerry added
        moderate noise AND that we guessed a phrase close enough. No
        checkpointing (the search space is too large to track). Just
        generates endless batches and feeds them to John. Logs a status
        line every few hours so you can verify it's still running and
        doing the right thing.

CHECKPOINTING:
    See nist_utils.py for state log format details.

USAGE:
    # Direct run (for testing):
    python3 nist_seeds_cracker.py

    # Install as systemd service (see nist-cracker.service file):
    sudo cp nist-cracker.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now nist-cracker

    # Check status:
    sudo systemctl status nist-cracker
    journalctl -u nist-cracker -f
    cat /home/seed_search2/nist_cracker_state.log

    # Check for found results:
    cat /home/seed_search2/nist_seeds_FOUND.txt

REQUIREMENTS:
    - John the Ripper Jumbo at /tmp/john-jumbo/run/john
    - Hash file at /home/seed_search2/nist-seeds-john.txt
    - Python 3.6+
    - nist_utils.py in same directory
"""

import os
import random
import string
import subprocess
import sys
import time
from datetime import datetime

# Import shared utilities and constants
from nist_utils import (
    JOHN_BINARY, HASH_FILE, STATE_LOG, FOUND_FILE, TEMP_DIR, JOHN_RULES,
    send_email
)

# Maximum counter value to append to phrases. The counter is needed because
# only ~1 in 192-521 hashes produces a valid curve. Filippo's analysis says
# 99% chance the counter is < 2400 for the largest curve (P-521) and < 1175
# for P-256. We use 2500 to have some margin.
MAX_COUNTER = 2500

# Counter batch size for Phase 1. Smaller batches = more frequent checkpoints
# and smaller temp files, but more overhead from launching John.
PHASE_1_BATCH_SIZE = 10

# Counter batch size for Phase 2. Larger batches reduce John launch overhead,
# which matters more in Phase 2 since each batch takes hours anyway.
PHASE_2_BATCH_SIZE = 500

# How often to log a status line in Phase 3 (seconds).
# Every 4 hours = 14400 seconds. This is just so you can check the log
# and confirm the daemon is still alive and making progress.
PHASE3_LOG_INTERVAL = 14400

# How many candidates to generate per batch in Phase 3 before feeding
# to John. Too small = overhead from launching John repeatedly. Too large =
# huge temp files. 5M candidates ~ 150MB wordlist file, which is manageable.
PHASE3_BATCH_SIZE = 20_000


# =============================================================================
# NAME COMPONENTS
#
# These are the people most likely to appear in the seed phrases, based on
# all available clues from Steve Weis's research:
#
# - Jerry Solinas: The NSA mathematician who chose the seeds. Everyone agrees
#   his name is almost certainly in the phrase.
# - Bob Reiter: Jerry's email to Dan Bernstein explicitly says "It was Bob
#   Reiter who actually wrote the code." Jerry's example phrases were
#   "Give Bob and Jerry a raise" and "Bob and Jerry rule."
# - Laurie Law: Jerry's longtime co-author at NSA (papers from 1996-2011).
#   A fourth source told Steve Weis the phrase had "two names" in it.
#   Laurie is the other most likely candidate besides Bob.
#
# We try multiple forms of each name because we don't know if Jerry used
# first names only, full names, last names only, or abbreviations.
# =============================================================================

SINGLE_NAMES = [
    "Jerry", "Bob", "Laurie",
    "Jerry Solinas", "Bob Reiter", "Laurie Law",
    "Solinas", "Reiter", "Law",
    "Jerome", "Robert",
    "Jerome Solinas", "Robert Reiter",
    "J. Solinas", "B. Reiter", "L. Law",
    "Jerome A. Solinas",
]

# Pairs of names. The phrase likely contains TWO names based on:
# 1. Jerry's own email: "Give Bob and Jerry a raise"
# 2. A source telling Steve Weis the phrase had "two names like Alice and Bob"
# We try all orderings because we don't know who came first.
NAME_PAIRS = [
    # Most likely: Jerry + Bob (since Bob wrote the code)
    ("Jerry", "Bob"), ("Bob", "Jerry"),
    ("Jerry Solinas", "Bob Reiter"), ("Bob Reiter", "Jerry Solinas"),
    ("Solinas", "Reiter"), ("Reiter", "Solinas"),
    # Jerry + Laurie (the other likely second person)
    ("Jerry", "Laurie"), ("Laurie", "Jerry"),
    ("Jerry Solinas", "Laurie Law"), ("Laurie Law", "Jerry Solinas"),
    ("Solinas", "Law"), ("Law", "Solinas"),
    # Bob + Laurie (less likely but possible)
    ("Bob", "Laurie"), ("Laurie", "Bob"),
    ("Bob Reiter", "Laurie Law"),
    # Formal first names
    ("Jerome", "Bob"), ("Jerome", "Robert"),
    ("Bob", "Jerome"), ("Robert", "Jerry"), ("Jerry", "Robert"),
    ("Jerome Solinas", "Bob Reiter"), ("Jerome Solinas", "Robert Reiter"),
]


# =============================================================================
# PHRASE TEMPLATES
#
# Structured around the specific clues we have:
#
# Jerry's email to Bernstein: "The message was along the lines of 'Give Bob
# and Jerry a raise' or 'Bob and Jerry rule' or something like that."
#
# An anonymous source (~2013): Jerry said SEED = SHA1("Jerry deserves a raise.")
#
# Another source: The phrase had TWO names, like "Give Alice and Bob a raise."
#
# We cast a wide net: raises, pay, humor, workplace, promotion, authorship.
# Templates should NOT include case-only duplicates because Jumbo rules
# handle case variation well.
# =============================================================================

TWO_NAME_TEMPLATES = [
    # === "Give X and Y a raise" family (Jerry's primary example) ===
    # NOTE: Jumbo rules will add most case/punctuation variants
    "Give {name1} and {name2} a raise",
    "Give {name1} and {name2} raises",
    "Give {name1} & {name2} a raise",

    # === "deserve/need a raise" family ===
    "{name1} and {name2} deserve a raise",
    "{name1} and {name2} deserve raises",
    "{name1} and {name2} need a raise",
    "{name1} and {name2} need raises",
    "{name1} and {name2} should get a raise",
    "{name1} & {name2} deserve a raise",
    "{name1} & {name2} need a raise",

    # === "rule" family (Jerry's other example) ===
    "{name1} and {name2} rule",
    "{name1} & {name2} rule",
    "{name1} and {name2} rock",

    # === Pay/money ===
    "Pay {name1} and {name2} more",
    "{name1} and {name2} need more money",
    "{name1} and {name2} need better pay",
    "{name1} and {name2} are underpaid",

    # === Workplace humor ===
    "{name1} and {name2} were here",
    "{name1} and {name2} wuz here",
    "{name1} and {name2} made this",
    "{name1} and {name2} did this",
    "{name1} and {name2} built this",

    # === Credit/authorship ===
    "{name1} and {name2}'s excellent curve",
    "{name1} and {name2}'s excellent adventure",
    "{name1} and {name2}'s gift to cryptography",
    "{name1} and {name2}'s contribution",
    "A gift from {name1} and {name2}",
    "From {name1} and {name2}",
    "Made by {name1} and {name2}",

    # === Promotion ===
    "Promote {name1} and {name2}",
    "{name1} and {name2} for promotion",
    "{name1} and {name2} deserve a promotion",
]

SINGLE_NAME_TEMPLATES = [
    # === "deserves a raise" (the most-cited example phrase) ===
    # NOTE: Jumbo rules will add most case/punctuation variants
    "{name} deserves a raise",
    "{name} needs a raise",
    "Give {name} a raise",

    # === Rule/rock ===
    "{name} rules",
    "{name} rocks",

    # === Workplace ===
    "{name} was here", "{name} wuz here",
    "{name} made this", "{name} did this", "{name} built this",

    # === Pay ===
    "Pay {name} more",
    "{name} is underpaid",
    "{name} needs more money", "{name} needs better pay",
    "{name} should get a raise",

    # === Promotion (NSA uses GS pay grades) ===
    "Promote {name}",
    "{name} for promotion",
    "{name} for GS-15", "{name} for GS-14", "{name} for GS-13",
    "{name} deserves a promotion",

    # === Credit ===
    "A gift from {name}",
    "{name}'s gift to cryptography", "{name}'s contribution",
    "{name}'s curve", "{name}'s excellent curve",
    "From {name}",
    "Made by {name}",
    "Generated by {name}",

    # === Misc humor ===
    "{name} is the best", "{name} is the man",
    "Thank {name}",
    "Thanks {name}",
    "{name} saves the day", "{name} to the rescue",
]

# "We" phrasing — Jerry consistently said "we" in his emails ("we built
# all the seeds", "we can remember neither"). The phrase might use "we"
# instead of names.
WE_TEMPLATES = [
    # NOTE: Jumbo rules will add most case/punctuation variants
    "We deserve a raise", "We deserve raises",
    "We need a raise", "We need raises",
    "Give us a raise",
    "We rule",
    "We were here", "We built this", "We made this",
    "Our gift to cryptography",
    "NSA rules", "NSA was here",
]


# =============================================================================
# VARIATION GENERATORS
#
# These functions take a base phrase and produce variants that cover
# different formatting possibilities. Jerry was typing on a late-90s
# workstation, probably a Unix terminal. We don't know if he used a period,
# an exclamation mark, a newline at the end, etc.
# =============================================================================

def counter_formats(n):
    """
    Generate various string representations of a counter number.
    
    We don't know how the counter was formatted. Was it just appended
    directly? With a space? An underscore? Parentheses? Zero-padded?
    We try all reasonable formats.
    
    The counter exists because only ~1 in 200-500 hashes produces a valid
    elliptic curve. Jerry would have needed to try many counter values
    for each base phrase until one worked.
    """
    s = str(n)
    formats = [
        s,              # "1", "42", "123"  — directly appended
        f" {s}",        # " 1", " 42"       — space separated
        f"_{s}",        # "_1", "_42"       — underscore separated
        f"-{s}",        # "-1", "-42"       — dash separated
        f"({s})",       # "(1)", "(42)"     — parenthesized
        f" ({s})",      # " (1)", " (42)"   — space + parens
        f"#{s}",        # "#1", "#42"       — hash prefix
        f" #{s}",       # " #1"             — space + hash
        f".{s}",        # ".1"              — dot prefix
    ]
    # Zero-padded variants (programmers often zero-pad counters)
    if n < 10:
        formats.extend([f"0{s}", f" 0{s}", f"00{s}", f" 00{s}"])
    elif n < 100:
        formats.extend([f"0{s}", f" 0{s}"])

    return formats


def generate_counter_batches(batch_size):
    """
    Generate counter batch ranges from 0 to MAX_COUNTER.

    Returns a list of (min, max) tuples like [(0, 49), (50, 99), ...].
    This is used in both Phase 1 and Phase 2 to create uniform batch sizes.
    """
    batches = []
    current = 0
    while current <= MAX_COUNTER:
        end = min(current + batch_size - 1, MAX_COUNTER)
        batches.append((current, end))
        current = end + 1
    return batches


# REMOVED: punctuation_variants() and case_variants()
# Let Jumbo rules handle case and punctuation variations to eliminate redundancy


# =============================================================================
# BASE PHRASE GENERATION
# =============================================================================

def generate_base_phrases():
    """
    Generate all base phrases (before counter/case/punctuation expansion).
    
    Returns a sorted list (not set) so the order is deterministic and
    reproducible across runs. This matters for Phase 2 checkpointing —
    we need base phrase #N to always be the same phrase on every run.
    If you add new phrases later, they'll get new indices at the end
    (since we sort alphabetically) and the old checkpoints stay valid
    as long as you don't remove phrases.
    """
    phrases = set()

    for name1, name2 in NAME_PAIRS:
        for template in TWO_NAME_TEMPLATES:
            phrases.add(template.format(name1=name1, name2=name2))

    for name in SINGLE_NAMES:
        for template in SINGLE_NAME_TEMPLATES:
            phrases.add(template.format(name=name))

    for template in WE_TEMPLATES:
        phrases.add(template)

    return sorted(phrases)


def expand_phrase_with_counters(phrase, min_counter=0, max_counter=MAX_COUNTER):
    """
    Take a single base phrase and yield all expanded variants with counters.

    Jumbo handles most case and punctuation transformations. We only emit
    the base phrase and counter-format variants here.

    This is used in both Phase 1 (all phrases at once) and Phase 2
    (per phrase, before inserting characters).

    The min_counter and max_counter params allow batching the counter range
    to reduce temp file sizes (e.g., 0-500, 501-1000, etc.).
    """
    # Only yield the no-counter variant if min_counter is 0
    if min_counter == 0:
        yield phrase

    # Yield counters in the specified range.
    for n in range(min_counter, max_counter + 1):
        for fmt in counter_formats(n):
            yield phrase + fmt


# =============================================================================
# JOHN THE RIPPER INTERFACE
# =============================================================================

def check_john_available():
    """
    Verify John the Ripper is installed where we expect it.
    If /tmp was wiped by a reboot, John needs to be recompiled.
    """
    if not os.path.isfile(JOHN_BINARY):
        print(f"ERROR: John the Ripper not found at {JOHN_BINARY}")
        print("If the server was rebooted, /tmp may have been cleared.")
        print("You'll need to recompile John the Ripper Jumbo.")
        print("See JOHN_VS_PYTHON_COMPARISON.md for setup notes.")
        sys.exit(1)

    if not os.path.isfile(HASH_FILE):
        print(f"ERROR: Hash file not found at {HASH_FILE}")
        print("This file should contain the NIST seed hashes in John format.")
        sys.exit(1)


def run_john_on_wordlist(wordlist_path):
    """
    Run John the Ripper with Jumbo rules on a wordlist file.
    
    Returns True if John found any new cracks, False otherwise.
    
    We use --rules=Jumbo for maximum mangling coverage. This means John
    takes each word in our wordlist and applies thousands of transformations
    (l33tspeak, case toggling, appending numbers, character swaps, etc.)
    before checking against the target hashes.
    
    John automatically stores found passwords in its "pot" file
    (~/.john/john.pot). We check the pot file after each run to see
    if anything new was found.
    """
    # Snapshot the pot file before this run so we can detect new finds
    pot_before = get_john_pot_contents()

    cmd = [
        JOHN_BINARY,
        "--format=Raw-SHA1",        # We're cracking raw SHA-1 hashes
        f"--wordlist={wordlist_path}",
        f"--rules={JOHN_RULES}",    # Always Jumbo for maximum coverage
        HASH_FILE,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=86400,  # 24 hour safety timeout per batch
        )

        # Log John's output for debugging
        if result.stdout.strip():
            print(f"  John stdout: {result.stdout.strip()[:200]}", flush=True)

        # Non-zero exit means the batch did not run cleanly.
        # Treat this as an operational error, not a normal "no match" result.
        if result.returncode != 0:
            stderr_preview = result.stderr.strip()[:400] if result.stderr else ""
            stdout_preview = result.stdout.strip()[:200] if result.stdout else ""
            log_message(
                f"ERROR: John exited with code {result.returncode}. "
                f"stderr={repr(stderr_preview)} stdout={repr(stdout_preview)}"
            )
            return False

        # Check for new cracks
        pot_after = get_john_pot_contents()
        new_cracks = pot_after - pot_before

        if new_cracks:
            handle_found_cracks(new_cracks)
            return True

    except subprocess.TimeoutExpired:
        log_message("WARNING: John timed out after 24 hours on this batch")
    except Exception as e:
        log_message(f"ERROR running John: {e}")

    return False


def get_john_pot_contents():
    """
    Read John's pot file to get the set of already-cracked hashes.
    
    John stores cracked passwords in a pot file so it doesn't recheck them.
    We read this before and after each run to detect new cracks.
    The pot file location varies, so we check several common paths.
    """
    pot_paths = [
        os.path.expanduser("~/.john/john.pot"),
        "/home/seeds/.john/john.pot",
        "/root/.john/john.pot",
        os.path.join(os.path.dirname(JOHN_BINARY), "john.pot"),
    ]

    entries = set()
    for pot_path in pot_paths:
        if os.path.isfile(pot_path):
            try:
                with open(pot_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.add(line)
            except Exception:
                pass
    return entries


def handle_found_cracks(new_cracks):
    """
    Called when John finds a new crack. This is the exciting part!

    Writes to FOUND_FILE, logs the finding, sends email alert, and prints
    a giant banner so it's impossible to miss in journalctl output.
    """
    timestamp = datetime.now().astimezone().isoformat()

    for crack in new_cracks:
        msg = (
            f"\n{'!' * 70}\n"
            f"{'!' * 70}\n"
            f"  FOUND A MATCH!\n"
            f"  Time: {timestamp}\n"
            f"  Pot entry: {crack}\n"
            f"  GO COLLECT THE BOUNTY!\n"
            f"{'!' * 70}\n"
            f"{'!' * 70}\n"
        )
        print(msg, flush=True)
        log_message(f"FOUND: {crack}")

        with open(FOUND_FILE, 'a') as f:
            f.write(f"{timestamp}: {crack}\n")

        # Send immediate email alert
        email_subject = "🎉 NIST SEEDS CRACKED! BOUNTY WON!"
        email_body = f"""FOUND A MATCH!

Time: {timestamp}
Pot entry: {crack}

GO COLLECT THE $12,288 BOUNTY!

Check the FOUND file at: {FOUND_FILE}

---
NOTE: Test dummy hashes are inserted for testing:
- "Jerry deserves a raise 123"
- "Jaerry deserves a raise 123"
If this is one of those, it's just a test. Check the pot entry above.
"""
        send_email(email_subject, email_body)


# =============================================================================
# LOGGING AND STATE MANAGEMENT
# =============================================================================

def log_message(msg):
    """
    Append a timestamped message to the state log and print to stdout.
    
    Stdout goes to systemd's journal (viewable with journalctl -u nist-cracker).
    The state log file is our persistent checkpoint — it survives reboots
    and is how we know what work to skip on restart.
    """
    timestamp = datetime.now().astimezone().isoformat()
    line = f"{timestamp}: {msg}"
    print(line, flush=True)

    try:
        with open(STATE_LOG, 'a') as f:
            f.write(line + "\n")
            f.flush()  # Force write to disk immediately (important for checkpoints)
    except Exception as e:
        print(f"WARNING: Could not write to state log: {e}", flush=True)


def read_state():
    """
    Read the state log to determine what work has already been completed.

    Returns a dict with:
        phase1_complete: bool
        phase1_done_batches: set of tuples (min_counter, max_counter)
        phase2_done_batches: dict mapping base phrase index to set of (min, max) tuples
        phase2_done_indices: set of ints (base phrase indices fully complete)

    We parse the log line by line looking for specific markers. This is
    robust to partial writes and corruption — if a line doesn't match
    a known pattern, we just skip it.
    """
    state = {
        "phase1_complete": False,
        "phase1_done_batches": set(),
        "phase2_done_batches": {},  # idx -> set of (min, max) tuples
        "phase2_done_indices": set(),
    }

    if not os.path.isfile(STATE_LOG):
        return state

    try:
        with open(STATE_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if "PHASE1_COMPLETE" in line:
                    state["phase1_complete"] = True
                elif "PHASE1_BATCH_DONE:" in line:
                    # Format: "timestamp: PHASE1_BATCH_DONE:0-500" or "PHASE1_BATCH_DONE:501-1000"
                    try:
                        marker = line.split("PHASE1_BATCH_DONE:")[1].split()[0]
                        min_c, max_c = map(int, marker.split("-"))
                        state["phase1_done_batches"].add((min_c, max_c))
                    except (ValueError, IndexError):
                        pass  # Corrupted line, skip it
                elif "PHASE2_BATCH_DONE:" in line:
                    # Format: "timestamp: PHASE2_BATCH_DONE:idx:0-500:phrase"
                    try:
                        marker = line.split("PHASE2_BATCH_DONE:")[1]
                        parts = marker.split(":")
                        idx = int(parts[0])
                        min_c, max_c = map(int, parts[1].split("-"))
                        if idx not in state["phase2_done_batches"]:
                            state["phase2_done_batches"][idx] = set()
                        state["phase2_done_batches"][idx].add((min_c, max_c))
                    except (ValueError, IndexError):
                        pass  # Corrupted line, skip it
                elif "PHASE2_BASE_DONE:" in line:
                    # Format: "timestamp: PHASE2_BASE_DONE:index:phrase"
                    # This is the old-style completion marker (all batches done)
                    try:
                        marker = line.split("PHASE2_BASE_DONE:")[1]
                        idx = int(marker.split(":")[0])
                        state["phase2_done_indices"].add(idx)
                    except (ValueError, IndexError):
                        pass  # Corrupted line, skip it
    except Exception as e:
        print(f"WARNING: Error reading state log: {e}", flush=True)

    return state


def ensure_dirs():
    """Create required directories if they don't exist."""
    os.makedirs(TEMP_DIR, exist_ok=True)
    # Ensure log directory exists
    os.makedirs(os.path.dirname(STATE_LOG), exist_ok=True)


# =============================================================================
# PHASE 1: Base phrases + John Jumbo
#
# This is the "maybe we just guessed right" phase. We generate all
# reasonable phrase variants and let John's Jumbo rules expand them further.
# Takes ~1-6 hours depending on how aggressive John's rules are.
# =============================================================================

def run_phase1():
    """
    Generate all base phrase variants and feed to John with Jumbo rules.

    We split the counter range (0-MAX_COUNTER) into batches of BATCH_SIZE
    to reduce temp file sizes and allow more frequent checkpoints. Each batch
    is checkpointed so we can resume after crashes.
    """
    log_message("PHASE 1 START: Base phrases with John Jumbo rules (batched counters)")

    base_phrases = generate_base_phrases()
    log_message(f"Phase 1: {len(base_phrases)} base phrases to expand")

    # Generate counter batches based on PHASE_1_BATCH_SIZE parameter
    counter_batches = generate_counter_batches(PHASE_1_BATCH_SIZE)

    # Check which batches are already done
    state = read_state()
    done_batches = state["phase1_done_batches"]

    for min_c, max_c in counter_batches:
        # Skip batches completed in a previous run
        if (min_c, max_c) in done_batches:
            log_message(f"Phase 1: Batch {min_c}-{max_c} already complete (skipping)")
            continue

        log_message(f"Phase 1: Starting counter batch {min_c}-{max_c}")
        start_time = time.time()

        wordlist_path = os.path.join(TEMP_DIR, f"phase1_batch_{min_c}_{max_c}.txt")
        log_message(f"Phase 1: Generating wordlist at {wordlist_path}...")

        count = 0
        with open(wordlist_path, 'w') as f:
            for phrase in base_phrases:
                for candidate in expand_phrase_with_counters(phrase, min_c, max_c):
                    f.write(candidate + "\n")
                    count += 1
                    if count % 5_000_000 == 0:
                        print(f"  Phase 1 [{min_c}-{max_c}]: {count:,} candidates "
                              f"generated...", flush=True)

        file_mb = os.path.getsize(wordlist_path) / (1024 * 1024)
        log_message(f"Phase 1 [{min_c}-{max_c}]: Generated {count:,} candidates "
                    f"({file_mb:.0f} MB)")
        log_message(f"Phase 1 [{min_c}-{max_c}]: Feeding to John with Jumbo rules...")

        found = run_john_on_wordlist(wordlist_path)

        # Clean up the wordlist file
        try:
            os.remove(wordlist_path)
        except Exception:
            pass

        elapsed = time.time() - start_time
        log_message(f"Phase 1 [{min_c}-{max_c}]: Completed in {elapsed/60:.1f} minutes")

        # Checkpoint: log this batch as done
        log_message(f"PHASE1_BATCH_DONE:{min_c}-{max_c}")

        if found:
            log_message(f"Phase 1: !!! FOUND SOMETHING in batch {min_c}-{max_c}! "
                        f"Check FOUND file !!!")

    # Mark Phase 1 as complete — all 5 batches done
    log_message("PHASE1_COMPLETE")
    log_message("Phase 1: All counter batches complete. Moving to Phase 2.")


# =============================================================================
# PHASE 2: Single character insertion + John Jumbo
#
# For each base phrase, we insert every printable ASCII character at every
# position, THEN feed the result to John with Jumbo rules on top.
#
# We iterate DETERMINISTICALLY (not randomly) so we can checkpoint:
# - Outer loop: each base phrase (1,352 of them)
# - Inner: expand with counters/case/punctuation, then insert chars
#
# When a base phrase is fully processed, we log it as done. On restart,
# we skip completed phrases. If we crash mid-phrase, we lose at most a
# few hours of work for that one phrase — acceptable.
#
# Why deterministic order matters: if we used random insertion, we couldn't
# know what we'd already tried. By going in order (char 'a' at position 0,
# char 'a' at position 1, ..., char '~' at last position), we guarantee
# full coverage of the single-insertion search space for each base phrase.
# =============================================================================

# All characters we'll try inserting. Every printable ASCII character
# from space (0x20) through tilde (0x7E), plus tab and newline.
INSERTABLE_CHARS = (
    string.ascii_letters +      # a-zA-Z
    string.digits +             # 0-9
    string.punctuation +        # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    ' ' +                       # space
    '\t'                        # tab (less likely but cheap to try)
)


def generate_phase2_candidates_for_phrase(phrase, min_counter=0, max_counter=MAX_COUNTER):
    """
    Generator: for a single base phrase, yield all candidates with one
    inserted character at every position.

    For each expanded variant (case x punctuation x counters), we insert
    each character from INSERTABLE_CHARS at each position in the string.
    Position 0 = before first char, position len = after last char.

    The min_counter and max_counter params allow batching to reduce file sizes.

    This produces a LOT of candidates per phrase, which is why each
    phrase takes hours when John's Jumbo rules are applied on top.
    """
    for variant in expand_phrase_with_counters(phrase, min_counter, max_counter):
        for pos in range(len(variant) + 1):
            for char in INSERTABLE_CHARS:
                yield variant[:pos] + char + variant[pos:]


def run_phase2():
    """
    Run Phase 2: single character insertion for each base phrase.

    Iterates through base phrases in deterministic order. For each one,
    we process in counter batches of BATCH_SIZE to reduce temp file sizes
    and allow more frequent checkpoints.

    Skips any phrases/batches already logged as done from a previous run.
    """
    log_message("PHASE 2 START: Single character insertion with John Jumbo (batched counters)")

    base_phrases = generate_base_phrases()
    state = read_state()
    done_indices = state["phase2_done_indices"]
    done_batches = state["phase2_done_batches"]

    # Generate counter batches based on PHASE_2_BATCH_SIZE parameter
    counter_batches = generate_counter_batches(PHASE_2_BATCH_SIZE)

    remaining = len(base_phrases) - len(done_indices)
    log_message(f"Phase 2: {len(base_phrases)} total base phrases, "
                f"{len(done_indices)} already done, {remaining} remaining")

    for idx, phrase in enumerate(base_phrases):
        # Skip phrases completed in a previous run
        if idx in done_indices:
            continue

        log_message(f"Phase 2: Starting phrase {idx}/{len(base_phrases)-1}: "
                    f"{repr(phrase)}")
        phrase_start_time = time.time()

        # Get the set of batches already done for this phrase
        completed_batches = done_batches.get(idx, set())

        # Process each counter batch for this phrase
        for min_c, max_c in counter_batches:
            # Skip batches completed in a previous run
            if (min_c, max_c) in completed_batches:
                log_message(f"Phase 2 [{idx}]: Batch {min_c}-{max_c} already "
                            f"complete (skipping)")
                continue

            log_message(f"Phase 2 [{idx}]: Starting counter batch {min_c}-{max_c}")
            batch_start_time = time.time()

            # Generate all single-char-insertion candidates for this counter batch.
            # We write to disk rather than piping to John because:
            # 1. John can report progress on a file (not on stdin)
            # 2. If John crashes, we can re-feed the same file
            # 3. We can inspect the file for debugging
            wordlist_path = os.path.join(TEMP_DIR,
                                         f"phase2_phrase_{idx}_batch_{min_c}_{max_c}.txt")

            count = 0
            with open(wordlist_path, 'w') as f:
                for candidate in generate_phase2_candidates_for_phrase(phrase, min_c, max_c):
                    f.write(candidate + "\n")
                    count += 1
                    if count % 10_000_000 == 0:
                        print(f"  Phase 2 [{idx}:{min_c}-{max_c}]: {count:,} "
                              f"candidates generated...", flush=True)

            gen_time = time.time() - batch_start_time
            file_mb = os.path.getsize(wordlist_path) / (1024 * 1024)
            log_message(f"Phase 2 [{idx}:{min_c}-{max_c}]: Generated {count:,} "
                        f"candidates ({file_mb:.0f} MB) in {gen_time:.0f}s. "
                        f"Feeding to John...")

            # Feed to John — this is the slow part (hours per batch)
            found = run_john_on_wordlist(wordlist_path)

            batch_elapsed = time.time() - batch_start_time
            log_message(f"Phase 2 [{idx}:{min_c}-{max_c}]: Completed in "
                        f"{batch_elapsed/3600:.1f} hours")

            # Clean up temp wordlist (can be huge)
            try:
                os.remove(wordlist_path)
            except Exception:
                pass

            # Checkpoint: log this batch as done
            log_message(f"PHASE2_BATCH_DONE:{idx}:{min_c}-{max_c}:{phrase}")

            if found:
                log_message(f"Phase 2: !!! FOUND SOMETHING on phrase {idx} "
                            f"batch {min_c}-{max_c}! Check FOUND file !!!")

        # All batches done for this phrase
        phrase_elapsed = time.time() - phrase_start_time
        log_message(f"Phase 2 [{idx}]: All batches complete for this phrase "
                    f"(total {phrase_elapsed/3600:.1f} hours)")

        # Checkpoint: log the entire phrase as done (for backward compatibility
        # and as a summary marker)
        log_message(f"PHASE2_BASE_DONE:{idx}:{phrase}")

    log_message("PHASE2_COMPLETE: All base phrases processed with "
                "single-char insertion")


# =============================================================================
# PHASE 3: Deep random noise + John Jumbo (runs forever)
#
# This is the long-shot phase. We insert 2+ random printable ASCII
# characters at random positions in random base phrases, then feed
# batches to John with Jumbo rules.
#
# Why random instead of deterministic like Phase 2?
# Because with 2+ insertions, the search space is so enormous that
# systematic coverage is impossible. With 2 chars at ~25 positions each
# from 95 printable chars, that's ~56 million variants PER expanded
# candidate (and we have millions of expanded candidates per phrase).
# It would take years per base phrase. Random sampling gives us a better
# chance of getting lucky across the whole phrase space.
#
# No checkpointing — the probability of generating the same random
# candidate twice is negligible, and tracking billions of attempts
# would be more overhead than it's worth.
#
# We DO log a status line every 4 hours so you can:
# 1. Confirm the daemon is still alive
# 2. See the rate of candidates being processed
# 3. Sanity-check a sample candidate to make sure it looks right
# =============================================================================

def generate_phase3_batch(base_phrases, batch_size):
    """
    Generate a batch of randomly-noised candidates for Phase 3.

    For each candidate in the batch:
    1. Pick a random base phrase
    2. Insert 2-4 random printable ASCII characters at random positions

    We skip counters here because John's Jumbo rules already append
    numbers aggressively. Adding our counters on top of 2-4 random
    insertions would make batches enormous without much benefit —
    John will handle that layer of variation.

    Case and most punctuation variations are handled by Jumbo rules.
    """
    candidates = []
    for _ in range(batch_size):
        phrase = random.choice(base_phrases)

        # Insert 2-4 random characters at random positions.
        # We use 2-4 because:
        # - Phase 2 already covers exactly 1 insertion
        # - 2 is the next step up (and still plausible for a cryptographer
        #   adding light noise)
        # - 3-4 is a longer shot but we include it for breadth
        # - 5+ is almost certainly hopeless on our hardware
        num_insertions = random.randint(2, 4)
        chars = list(phrase)
        for _ in range(num_insertions):
            pos = random.randint(0, len(chars))
            char = random.choice(INSERTABLE_CHARS)
            chars.insert(pos, char)

        candidates.append(''.join(chars))

    return candidates


def run_phase3():
    """
    Run Phase 3 forever: deep random noise injection.
    
    Generates batches of randomly-noised candidates, feeds them to John
    with Jumbo rules, and repeats indefinitely. Logs status every
    PHASE3_LOG_INTERVAL seconds.
    
    This only stops when:
    - We find a match (!!!)
    - The process is killed
    - The server shuts down (systemd will restart us)
    """
    log_message("PHASE 3 START: Deep random noise injection (runs forever)")
    log_message(f"Phase 3: batch_size={PHASE3_BATCH_SIZE:,}, "
                f"status_interval={PHASE3_LOG_INTERVAL}s")

    base_phrases = generate_base_phrases()
    total_generated = 0
    batches_run = 0
    last_log_time = time.time()
    phase3_start = time.time()

    while True:
        candidates = generate_phase3_batch(base_phrases, PHASE3_BATCH_SIZE)

        wordlist_path = os.path.join(TEMP_DIR, "phase3_batch.txt")
        with open(wordlist_path, 'w') as f:
            for c in candidates:
                f.write(c + "\n")

        found = run_john_on_wordlist(wordlist_path)

        try:
            os.remove(wordlist_path)
        except Exception:
            pass

        total_generated += len(candidates)
        batches_run += 1

        if found:
            log_message(f"Phase 3: !!! FOUND SOMETHING on batch {batches_run}! "
                        f"Check FOUND file !!!")

        # Periodic status log — not a checkpoint, just proof of life
        # and a sanity check that candidates look reasonable
        now = time.time()
        if now - last_log_time >= PHASE3_LOG_INTERVAL:
            elapsed = now - phase3_start
            # Show a sample candidate so we can eyeball it in the log
            # and verify it looks like a noisy phrase, not garbage
            sample = candidates[0] if candidates else "N/A"
            log_message(
                f"PHASE3_STATUS: batches={batches_run}, "
                f"generated={total_generated:,}, "
                f"elapsed={elapsed/3600:.1f}h, "
                f"sample={repr(sample[:80])}"
            )
            last_log_time = now


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    print("=" * 70, flush=True)
    print("NIST Elliptic Curve Seeds Cracker - Daemon Edition", flush=True)
    print("=" * 70, flush=True)
    print(f"Working dir:  {os.getcwd()}", flush=True)
    print(f"John binary:  {JOHN_BINARY}", flush=True)
    print(f"Hash file:    {HASH_FILE}", flush=True)
    print(f"State log:    {STATE_LOG}", flush=True)
    print(f"Found file:   {FOUND_FILE}", flush=True)
    print(f"Temp dir:     {TEMP_DIR}", flush=True)
    print(f"John rules:   {JOHN_RULES}", flush=True)
    print("=" * 70, flush=True)

    # Preflight checks — fail fast if John or hash file is missing
    check_john_available()
    ensure_dirs()

    # Read existing state to determine where to resume
    state = read_state()
    total_counter_batches = len(generate_counter_batches(PHASE_1_BATCH_SIZE))

    log_message("Daemon starting. Reading state...")
    if state["phase1_complete"]:
        log_message(f"Phase 1: already complete")
    else:
        log_message(f"Phase 1: {len(state['phase1_done_batches'])} counter batches "
                    f"already done (out of {total_counter_batches})")
    log_message(f"Phase 2: {len(state['phase2_done_indices'])} base phrases "
                f"already done")

    # Phase 1: Base phrases with John Jumbo
    # Only runs once. After completion, PHASE1_COMPLETE is logged
    # and all future runs skip straight to Phase 2.
    if state["phase1_complete"]:
        log_message("Phase 1: Already complete (skipping)")
    else:
        run_phase1()

    # Phase 2: Single character insertion
    # Handles its own per-phrase checkpointing internally.
    # Skips phrases that were completed in previous runs.
    run_phase2()

    # Phase 3: Deep random noise (runs forever)
    # Never returns unless the process is killed.
    run_phase3()


if __name__ == "__main__":
    main()
