#!/usr/bin/env python3
"""Draw Tarot cards using os.urandom() for cryptographic randomness.

Shuffles a full 78-card deck via Fisher-Yates and draws 4 from the top.
Each card has an independent 50/50 chance of being reversed.
"""
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import json
import os
import sys

MAJOR_ARCANA = [
    ("major", "00-the-fool"),
    ("major", "01-the-magician"),
    ("major", "02-the-high-priestess"),
    ("major", "03-the-empress"),
    ("major", "04-the-emperor"),
    ("major", "05-the-hierophant"),
    ("major", "06-the-lovers"),
    ("major", "07-the-chariot"),
    ("major", "08-strength"),
    ("major", "09-the-hermit"),
    ("major", "10-wheel-of-fortune"),
    ("major", "11-justice"),
    ("major", "12-the-hanged-man"),
    ("major", "13-death"),
    ("major", "14-temperance"),
    ("major", "15-the-devil"),
    ("major", "16-the-tower"),
    ("major", "17-the-star"),
    ("major", "18-the-moon"),
    ("major", "19-the-sun"),
    ("major", "20-judgement"),
    ("major", "21-the-world"),
]

RANKS = [
    "ace",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "page",
    "knight",
    "queen",
    "king",
]

SUITS = ["wands", "cups", "swords", "pentacles"]


def build_deck():
    """Build the full 78-card Tarot deck."""
    deck = list(MAJOR_ARCANA)
    for suit in SUITS:
        for rank in RANKS:
            deck.append((suit, f"{rank}-of-{suit}"))
    return deck


def secure_randbelow(n):
    """Return a cryptographically random integer in [0, n).

    Uses os.urandom() with rejection sampling to avoid modulo bias.
    """
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 0
    # Number of bytes needed to cover range
    k = (n - 1).bit_length()
    num_bytes = (k + 7) // 8
    # Rejection sampling: discard values >= n to avoid bias
    while True:
        raw = int.from_bytes(os.urandom(num_bytes), "big")
        # Mask to k bits to reduce rejection rate
        raw = raw & ((1 << k) - 1)
        if raw < n:
            return raw


def fisher_yates_shuffle(deck):
    """Shuffle deck in-place using Fisher-Yates with os.urandom()."""
    for i in range(len(deck) - 1, 0, -1):
        j = secure_randbelow(i + 1)
        deck[i], deck[j] = deck[j], deck[i]
    return deck


def is_reversed():
    """Return True with 50% probability using os.urandom()."""
    return os.urandom(1)[0] & 1 == 1


def draw(n=4):
    """Shuffle deck and draw n cards, each possibly reversed."""
    deck = build_deck()
    fisher_yates_shuffle(deck)
    hand = []
    for i in range(min(n, len(deck))):
        suit, card_id = deck[i]
        reversed_flag = is_reversed()
        hand.append(
            {
                "suit": suit,
                "card_id": card_id,
                "reversed": reversed_flag,
                "position": i + 1,
                "file": f"cards/{suit}/{card_id}.md",
            }
        )
    return hand


def main():
    n = 4
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            print(
                f"Error: '{sys.argv[1]}' is not a valid integer. "
                f"Usage: draw_cards.py [count]  (1-78, default 4)",
                file=sys.stderr,
            )
            sys.exit(1)
        if n < 1 or n > 78:
            print(
                f"Error: card count must be 1-78, got {n}",
                file=sys.stderr,
            )
            sys.exit(1)
    try:
        hand = draw(n)
    except OSError as e:
        print(
            f"Error: failed to read system entropy source: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(json.dumps(hand, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: draw_cards.py failed: {e}", file=sys.stderr)
        sys.exit(1)
