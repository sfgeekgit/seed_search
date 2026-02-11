#!/usr/bin/env python3
"""
NIST Elliptic Curve Seeds Cracker - Daemon Edition
====================================================

PURPOSE:
    Attempts to find the original English phrases that were SHA-1 hashed to
    produce the seed values for the NIST elliptic curves (P-192 through P-521).
    

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
    feeds them to John the Ripper (Jumbo edition) which applies its own
    mangling rules on top and does the actual SHA-1 checking at ~10M H/s.
    
    Two layers of mangling:
      1. Python (smart, clue-driven): name variations, case, punctuation,
         counters, and in later phases, character insertion
      2. John the Ripper --rules=Jumbo (mechanical, broad): thousands of
         additional transformations like l33tspeak, appending numbers,
         character swaps, etc.
    
    We ALWAYS use John's Jumbo rules because the whole point is to cast
    the widest possible net. Even if our Python-generated phrase is close
    but not exact, John's mangling might bridge the gap.

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
    We log to /home/seeds/nist_cracker_state.log. The format is simple
    text lines that the script reads on startup to determine what to skip:
    
        PHASE1_COMPLETE                          # Phase 1 done, skip it
        PHASE2_BASE_DONE:0:Jerry deserves a raise  # This phrase done
        PHASE2_BASE_DONE:1:Bob deserves a raise     # etc.
        PHASE3_STATUS:checked=5000000000           # just FYI
    
    Why text and not JSON? Because we only ever append to this file, and
    we want it to survive partial writes (e.g., if the process is killed
    mid-write). Each line is self-contained. On restart, we read all lines
    and reconstruct state.
    
    Why per-base-phrase checkpointing in Phase 2 instead of finer-grained?
    Because each base phrase takes a few hours at most. If we crash halfway
    through a phrase, we lose a few hours of work — acceptable. Finer
    checkpointing would add complexity and I/O overhead for minimal benefit.

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
    cat /home/seeds/nist_cracker_state.log
    
    # Check for found results:
    cat /home/seeds/nist_seeds_FOUND.txt

REQUIREMENTS:
    - John the Ripper Jumbo at /tmp/john-jumbo/run/john
    - Hash file at /home/seeds/nist-seeds-john.txt
    - Python 3.6+
"""

import os
import random
import string
import subprocess
import sys
import time
from datetime import datetime, timezone


# =============================================================================
# CONFIGURATION
# =============================================================================

# Path to John the Ripper Jumbo binary.
# This was compiled from source on this server and lives in /tmp.
# If the server was rebooted and /tmp was cleared, John needs to be
# recompiled. The script will check and exit with a helpful message.
JOHN_BINARY = "/tmp/john-jumbo/run/john"

# Path to the hash file formatted for John (username:hash format).
# Contains all the NIST seed hashes we're trying to crack.
HASH_FILE = "/home/seeds/nist-seeds-john.txt"

# Where we log progress and checkpoint state.
# This file is append-only. We read it on startup to determine what to skip.
# Lives in /home/seeds/ (the project directory) so it won't be cleaned up
# by system log rotation or /tmp wipes.
STATE_LOG = "/home/seeds/nist_cracker_state.log"

# Where we write any successful cracks. This is the exciting file.
# If this file has content, we probably won the bounty.
FOUND_FILE = "/home/seeds/nist_seeds_FOUND.txt"

# Temporary wordlist directory. We write batches here, feed them to John,
# then delete them. Using /home/seeds/tmp/ instead of /tmp/ so it survives
# reboots and we can inspect wordlists for debugging if needed.
TEMP_DIR = "/home/seeds/tmp"

# John the Ripper rules to use. "Jumbo" is the most aggressive built-in
# ruleset — thousands of transformations including l33tspeak, case toggling,
# character insertion, appending numbers/symbols, etc. We ALWAYS use this
# because the whole point is maximum coverage. The cost is time, but we
# have time (this runs 24/7 for weeks).
JOHN_RULES = "Jumbo"

# Maximum counter value to append to phrases. The counter is needed because
# only ~1 in 192-521 hashes produces a valid curve. Filippo's analysis says
# 99% chance the counter is < 2400 for the largest curve (P-521) and < 1175
# for P-256. We use 2500 to have some margin.
MAX_COUNTER = 2500

# How often to log a status line in Phase 3 (seconds).
# Every 4 hours = 14400 seconds. This is just so you can check the log
# and confirm the daemon is still alive and making progress.
PHASE3_LOG_INTERVAL = 14400

# How many candidates to generate per batch in Phase 3 before feeding
# to John. Too small = overhead from launching John repeatedly. Too large =
# huge temp files. 5M candidates ~ 150MB wordlist file, which is manageable.
PHASE3_BATCH_SIZE = 5_000_000


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
# Some templates include trailing punctuation and some don't — the
# punctuation_variants() function adds/removes punctuation too, so we get
# coverage both ways. Some duplication is fine; it's cheap.
# =============================================================================

TWO_NAME_TEMPLATES = [
    # === "Give X and Y a raise" family (Jerry's primary example) ===
    "Give {name1} and {name2} a raise",
    "give {name1} and {name2} a raise",
    "Give {name1} and {name2} raises",
    "give {name1} and {name2} raises",
    "Give {name1} and {name2} a raise!",
    "Give {name1} and {name2} a raise.",
    "Give {name1} & {name2} a raise",
    "give {name1} & {name2} a raise",

    # === "deserve/need a raise" family ===
    "{name1} and {name2} deserve a raise",
    "{name1} and {name2} deserve raises",
    "{name1} and {name2} need a raise",
    "{name1} and {name2} need raises",
    "{name1} and {name2} deserve a raise!",
    "{name1} and {name2} deserve a raise.",
    "{name1} and {name2} need a raise!",
    "{name1} and {name2} need a raise.",
    "{name1} and {name2} should get a raise",
    "{name1} & {name2} deserve a raise",
    "{name1} & {name2} need a raise",

    # === "rule" family (Jerry's other example) ===
    "{name1} and {name2} rule",
    "{name1} and {name2} rule!",
    "{name1} and {name2} rule.",
    "{name1} & {name2} rule",
    "{name1} & {name2} rule!",
    "{name1} and {name2} rock",
    "{name1} and {name2} rock!",

    # === Pay/money ===
    "Pay {name1} and {name2} more",
    "Pay {name1} and {name2} more!",
    "pay {name1} and {name2} more",
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
    "a gift from {name1} and {name2}",
    "From {name1} and {name2}",
    "from {name1} and {name2}",
    "Made by {name1} and {name2}",
    "made by {name1} and {name2}",

    # === Promotion ===
    "Promote {name1} and {name2}",
    "promote {name1} and {name2}",
    "{name1} and {name2} for promotion",
    "{name1} and {name2} deserve a promotion",
]

SINGLE_NAME_TEMPLATES = [
    # === "deserves a raise" (the most-cited example phrase) ===
    "{name} deserves a raise",
    "{name} deserves a raise.",
    "{name} deserves a raise!",
    "{name} needs a raise",
    "{name} needs a raise.",
    "{name} needs a raise!",
    "Give {name} a raise",
    "Give {name} a raise.",
    "Give {name} a raise!",
    "give {name} a raise",

    # === Rule/rock ===
    "{name} rules", "{name} rules!", "{name} rules.",
    "{name} rocks", "{name} rocks!",

    # === Workplace ===
    "{name} was here", "{name} wuz here",
    "{name} made this", "{name} did this", "{name} built this",

    # === Pay ===
    "Pay {name} more", "pay {name} more",
    "{name} is underpaid",
    "{name} needs more money", "{name} needs better pay",
    "{name} should get a raise",

    # === Promotion (NSA uses GS pay grades) ===
    "Promote {name}", "promote {name}",
    "{name} for promotion",
    "{name} for GS-15", "{name} for GS-14", "{name} for GS-13",
    "{name} deserves a promotion",

    # === Credit ===
    "A gift from {name}", "a gift from {name}",
    "{name}'s gift to cryptography", "{name}'s contribution",
    "{name}'s curve", "{name}'s excellent curve",
    "From {name}", "from {name}",
    "Made by {name}", "made by {name}",
    "Generated by {name}", "generated by {name}",

    # === Misc humor ===
    "{name} is the best", "{name} is the man",
    "Thank {name}", "thank {name}",
    "Thanks {name}", "thanks {name}",
    "{name} saves the day", "{name} to the rescue",
]

# "We" phrasing — Jerry consistently said "we" in his emails ("we built
# all the seeds", "we can remember neither"). The phrase might use "we"
# instead of names.
WE_TEMPLATES = [
    "We deserve a raise", "We deserve raises",
    "We need a raise", "We need raises",
    "we deserve a raise", "we need a raise",
    "Give us a raise", "give us a raise",
    "We rule", "We rule!",
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


def punctuation_variants(phrase):
    """
    Generate trailing punctuation and whitespace variants.
    
    We don't know if Jerry ended his phrase with a period, exclamation mark,
    nothing, or a newline (which would be common if he typed it into a
    terminal and hit Enter, since the newline might be included in the hash
    input depending on how his code read the input).
    """
    variants = set()
    variants.add(phrase)

    # Strip existing trailing punctuation to create a clean base
    stripped = phrase.rstrip('.!? ')
    variants.add(stripped)

    # Add trailing punctuation options
    variants.add(stripped + ".")
    variants.add(stripped + "!")

    # Newline variants — very plausible if Jerry piped input from a file
    # or if his code included the trailing newline from stdin
    variants.add(phrase + "\n")
    variants.add(phrase + "\r\n")
    variants.add(stripped + "\n")
    variants.add(stripped + "\r\n")

    return list(variants)


def case_variants(phrase):
    """
    Generate case variants of a phrase.
    
    We don't know if Jerry typed "Give Bob and Jerry a raise" or
    "give bob and jerry a raise" or "GIVE BOB AND JERRY A RAISE".
    Names were probably capitalized, but we can't be sure.
    """
    variants = set()
    variants.add(phrase)                    # Original as-is
    variants.add(phrase.lower())            # all lowercase
    variants.add(phrase.upper())            # ALL UPPERCASE
    variants.add(phrase.title())            # Title Case Every Word
    # First letter cap only (like a sentence)
    if len(phrase) > 1:
        variants.add(phrase[0].upper() + phrase[1:].lower())
    return list(variants)


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


def expand_phrase_with_counters(phrase, max_counter=MAX_COUNTER):
    """
    Take a single base phrase and yield all expanded variants:
    case x punctuation x (no counter + counters 0..max_counter in all formats).
    
    This is used in both Phase 1 (all phrases at once) and Phase 2
    (per phrase, before inserting characters).
    """
    for cased in case_variants(phrase):
        for punc in punctuation_variants(cased):
            yield punc
            for n in range(0, max_counter + 1):
                for fmt in counter_formats(n):
                    yield punc + fmt


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
        if result.returncode != 0 and result.stderr.strip():
            print(f"  John stderr: {result.stderr.strip()[:200]}", flush=True)

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
    
    Writes to FOUND_FILE, logs the finding, and prints a giant banner
    so it's impossible to miss in journalctl output.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

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
    timestamp = datetime.now(timezone.utc).isoformat()
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
        phase2_done_indices: set of ints (base phrase indices that are done)
    
    We parse the log line by line looking for specific markers. This is
    robust to partial writes and corruption — if a line doesn't match
    a known pattern, we just skip it.
    """
    state = {
        "phase1_complete": False,
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
                elif "PHASE2_BASE_DONE:" in line:
                    # Format: "timestamp: PHASE2_BASE_DONE:index:phrase"
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
    
    We write all candidates to a single large wordlist file, then let
    John process it in one shot. This is more efficient than batching
    because John can optimize its rule application across the whole file.
    """
    log_message("PHASE 1 START: Base phrases with John Jumbo rules")

    base_phrases = generate_base_phrases()
    log_message(f"Phase 1: {len(base_phrases)} base phrases to expand")

    wordlist_path = os.path.join(TEMP_DIR, "phase1_wordlist.txt")
    log_message(f"Phase 1: Generating wordlist at {wordlist_path}...")

    count = 0
    with open(wordlist_path, 'w') as f:
        for phrase in base_phrases:
            for candidate in expand_phrase_with_counters(phrase):
                f.write(candidate + "\n")
                count += 1
                if count % 5_000_000 == 0:
                    print(f"  Phase 1: {count:,} candidates generated...",
                          flush=True)

    file_mb = os.path.getsize(wordlist_path) / (1024 * 1024)
    log_message(f"Phase 1: Generated {count:,} candidates ({file_mb:.0f} MB)")
    log_message("Phase 1: Feeding to John with Jumbo rules. This will take hours.")
    log_message("Phase 1: Monitor with: journalctl -u nist-cracker -f")

    found = run_john_on_wordlist(wordlist_path)

    # Clean up the large wordlist file
    try:
        os.remove(wordlist_path)
    except Exception:
        pass

    # Mark Phase 1 as complete — this is the checkpoint that lets us skip
    # Phase 1 on all future restarts
    log_message("PHASE1_COMPLETE")

    if found:
        log_message("Phase 1: !!! FOUND SOMETHING! Check FOUND file !!!")
    else:
        log_message("Phase 1: No matches found. Moving to Phase 2.")


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


def generate_phase2_candidates_for_phrase(phrase):
    """
    Generator: for a single base phrase, yield all candidates with one
    inserted character at every position.
    
    For each expanded variant (case x punctuation x counters), we insert
    each character from INSERTABLE_CHARS at each position in the string.
    Position 0 = before first char, position len = after last char.
    
    This produces a LOT of candidates per phrase, which is why each
    phrase takes hours when John's Jumbo rules are applied on top.
    """
    for variant in expand_phrase_with_counters(phrase):
        for pos in range(len(variant) + 1):
            for char in INSERTABLE_CHARS:
                yield variant[:pos] + char + variant[pos:]


def run_phase2():
    """
    Run Phase 2: single character insertion for each base phrase.
    
    Iterates through base phrases in deterministic order. For each one,
    generates ALL single-char-insertion variants, writes to a temp wordlist,
    feeds to John with Jumbo rules, then logs the phrase as done.
    
    Skips any phrases already logged as done from a previous run.
    """
    log_message("PHASE 2 START: Single character insertion with John Jumbo")

    base_phrases = generate_base_phrases()
    state = read_state()
    done_indices = state["phase2_done_indices"]

    remaining = len(base_phrases) - len(done_indices)
    log_message(f"Phase 2: {len(base_phrases)} total base phrases, "
                f"{len(done_indices)} already done, {remaining} remaining")

    for idx, phrase in enumerate(base_phrases):
        # Skip phrases completed in a previous run
        if idx in done_indices:
            continue

        log_message(f"Phase 2: Starting phrase {idx}/{len(base_phrases)-1}: "
                    f"{repr(phrase)}")
        start_time = time.time()

        # Generate all single-char-insertion candidates and write to file.
        # We write to disk rather than piping to John because:
        # 1. John can report progress on a file (not on stdin)
        # 2. If John crashes, we can re-feed the same file
        # 3. We can inspect the file for debugging
        wordlist_path = os.path.join(TEMP_DIR, f"phase2_batch_{idx}.txt")

        count = 0
        with open(wordlist_path, 'w') as f:
            for candidate in generate_phase2_candidates_for_phrase(phrase):
                f.write(candidate + "\n")
                count += 1
                if count % 10_000_000 == 0:
                    print(f"  Phase 2 [{idx}]: {count:,} candidates "
                          f"generated...", flush=True)

        gen_time = time.time() - start_time
        file_mb = os.path.getsize(wordlist_path) / (1024 * 1024)
        log_message(f"Phase 2 [{idx}]: Generated {count:,} candidates "
                    f"({file_mb:.0f} MB) in {gen_time:.0f}s. "
                    f"Feeding to John...")

        # Feed to John — this is the slow part (hours per phrase)
        found = run_john_on_wordlist(wordlist_path)

        elapsed = time.time() - start_time
        log_message(f"Phase 2 [{idx}]: Completed in {elapsed/3600:.1f} hours")

        # Clean up temp wordlist (can be huge)
        try:
            os.remove(wordlist_path)
        except Exception:
            pass

        # Checkpoint: log this phrase as done so we skip it on restart.
        # This is the key line that makes Phase 2 resumable.
        log_message(f"PHASE2_BASE_DONE:{idx}:{phrase}")

        if found:
            log_message(f"Phase 2: !!! FOUND SOMETHING on phrase {idx}! "
                        f"Check FOUND file !!!")

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
    2. Apply a random case variant
    3. Apply a random punctuation variant
    4. Insert 2-4 random printable ASCII characters at random positions
    
    We skip counters here because John's Jumbo rules already append
    numbers aggressively. Adding our counters on top of 2-4 random
    insertions would make batches enormous without much benefit —
    John will handle that layer of variation.
    """
    candidates = []
    for _ in range(batch_size):
        phrase = random.choice(base_phrases)
        phrase = random.choice(case_variants(phrase))
        phrase = random.choice(punctuation_variants(phrase))

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

    log_message("Daemon starting. Reading state...")
    if state["phase1_complete"]:
        log_message(f"Phase 1: already complete")
    log_message(f"Phase 2: {len(state['phase2_done_indices'])} "
                f"base phrases already done")

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
