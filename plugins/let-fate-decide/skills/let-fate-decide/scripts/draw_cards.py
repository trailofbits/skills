#!/usr/bin/env python3
"""Draw Tarot cards using the secrets module for cryptographic randomness.

Shuffles a full 78-card deck via Fisher-Yates and draws 4 from the top.
Each card has an independent 50/50 chance of being reversed.
"""
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import json
import os
import secrets
import sys

MAJOR_ARCANA = (
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
)

RANKS = (
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
)

SUITS = ("wands", "cups", "swords", "pentacles")


def build_deck():
    """Build the full 78-card Tarot deck."""
    deck = list(MAJOR_ARCANA)
    for suit in SUITS:
        for rank in RANKS:
            deck.append((suit, f"{rank}-of-{suit}"))
    return deck


def fisher_yates_shuffle(deck):
    """Shuffle deck in-place using Fisher-Yates with secrets.randbelow()."""
    for i in range(len(deck) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        deck[i], deck[j] = deck[j], deck[i]
    return deck


def is_reversed():
    """Return True with 50% probability using secrets.randbits()."""
    return secrets.randbits(1) == 1


def draw(n=4, include_content=False):
    """Shuffle deck and draw n cards, each possibly reversed."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError(f"n must be int, got {type(n).__name__}")
    deck = build_deck()
    fisher_yates_shuffle(deck)
    # Resolve cards directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cards_dir = os.path.join(os.path.dirname(script_dir), "cards")
    hand = []
    for i in range(min(n, len(deck))):
        suit, card_id = deck[i]
        reversed_flag = is_reversed()
        card = {
            "suit": suit,
            "card_id": card_id,
            "reversed": reversed_flag,
            "position": i + 1,
            "file": f"cards/{suit}/{card_id}.md",
        }
        if include_content:
            path = os.path.join(cards_dir, suit, f"{card_id}.md")
            try:
                with open(path) as f:
                    card["content"] = f.read()
            except FileNotFoundError:
                card["content"] = f"(card file not found: {path})"
        hand.append(card)
    return hand


def main():
    n = 4
    include_content = False
    args = sys.argv[1:]
    if "--content" in args:
        include_content = True
        args.remove("--content")
    if args:
        try:
            n = int(args[0])
        except ValueError:
            print(
                f"Error: '{args[0]}' is not a valid integer. "
                f"Usage: draw_cards.py [--content] [count]",
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
        hand = draw(n, include_content=include_content)
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
