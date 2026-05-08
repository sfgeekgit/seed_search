"""
nist_phrases.py - Phrase templates and name lists for the NIST Seeds Cracker
=============================================================================

This file contains all the candidate names and phrase templates used to
generate search candidates. Edit this file to add/remove names or phrases.

Because Phase 2 checkpointing is by phrase TEXT (not index), you can freely
add or remove entries here without invalidating existing checkpoint history —
already-completed phrases are recognized by their text, so they'll be skipped
regardless of their position in the sorted list.
"""

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
