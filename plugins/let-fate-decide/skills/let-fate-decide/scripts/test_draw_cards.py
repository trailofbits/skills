#!/usr/bin/env python3
"""Tests for draw_cards.py."""
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
import draw_cards


def test_build_deck_has_78_cards():
    deck = draw_cards.build_deck()
    assert len(deck) == 78, f"Expected 78 cards, got {len(deck)}"


def test_build_deck_has_22_major_arcana():
    deck = draw_cards.build_deck()
    majors = [c for c in deck if c[0] == "major"]
    assert len(majors) == 22, f"Expected 22 major arcana, got {len(majors)}"


def test_build_deck_has_56_minor_arcana():
    deck = draw_cards.build_deck()
    minors = [c for c in deck if c[0] != "major"]
    assert len(minors) == 56, f"Expected 56 minor arcana, got {len(minors)}"


def test_build_deck_all_unique():
    deck = draw_cards.build_deck()
    card_ids = [c[1] for c in deck]
    assert len(card_ids) == len(set(card_ids)), "Duplicate card IDs found"


def test_build_deck_four_suits_14_each():
    deck = draw_cards.build_deck()
    suits = Counter(c[0] for c in deck if c[0] != "major")
    for suit in ["wands", "cups", "swords", "pentacles"]:
        assert suits[suit] == 14, f"Expected 14 {suit}, got {suits[suit]}"


def test_draw_returns_requested_count():
    for n in [1, 2, 4, 10]:
        hand = draw_cards.draw(n)
        assert len(hand) == n, f"draw({n}) returned {len(hand)} cards"


def test_draw_default_is_4():
    hand = draw_cards.draw()
    assert len(hand) == 4


def test_draw_clamps_to_78():
    hand = draw_cards.draw(100)
    assert len(hand) == 78


def test_draw_zero_returns_empty():
    hand = draw_cards.draw(0)
    assert len(hand) == 0


def test_draw_card_structure():
    hand = draw_cards.draw(1)
    card = hand[0]
    assert "suit" in card
    assert "card_id" in card
    assert "reversed" in card
    assert "position" in card
    assert "file" in card
    assert isinstance(card["reversed"], bool)
    assert card["position"] == 1
    assert card["file"].startswith("cards/")
    assert card["file"].endswith(".md")


def test_draw_positions_are_sequential():
    hand = draw_cards.draw(4)
    positions = [c["position"] for c in hand]
    assert positions == [1, 2, 3, 4]


def test_draw_no_duplicate_cards():
    hand = draw_cards.draw(78)
    card_ids = [c["card_id"] for c in hand]
    assert len(card_ids) == len(set(card_ids)), "Duplicate cards drawn"


def test_fisher_yates_preserves_elements():
    deck = draw_cards.build_deck()
    original = sorted(deck)
    draw_cards.fisher_yates_shuffle(deck)
    assert sorted(deck) == original, "Shuffle changed deck elements"


def test_fisher_yates_single_element():
    deck = [("major", "00-the-fool")]
    draw_cards.fisher_yates_shuffle(deck)
    assert deck == [("major", "00-the-fool")]


def test_fisher_yates_empty():
    deck = []
    draw_cards.fisher_yates_shuffle(deck)
    assert deck == []


def test_is_reversed_returns_bool():
    for _ in range(20):
        assert isinstance(draw_cards.is_reversed(), bool)


def test_shuffle_produces_varying_orders():
    """Run 5 shuffles; at least 2 should differ (p(all same) ~ 0)."""
    orders = []
    for _ in range(5):
        deck = draw_cards.build_deck()
        draw_cards.fisher_yates_shuffle(deck)
        orders.append(tuple(c[1] for c in deck))
    assert len(set(orders)) >= 2, "All 5 shuffles identical"


def test_reversal_produces_both_values():
    """Over 100 flips, both True and False should appear."""
    results = {draw_cards.is_reversed() for _ in range(100)}
    assert True in results, "Never got reversed=True in 100 flips"
    assert False in results, "Never got reversed=False in 100 flips"


def test_no_os_urandom_import():
    """Verify os is not imported (regression for secrets migration)."""
    source = Path(__file__).parent / "draw_cards.py"
    text = source.read_text()
    assert "import os" not in text, "os is still imported"
    assert "os.urandom" not in text, "os.urandom still referenced"


def test_uses_secrets_module():
    """Verify secrets module is used."""
    source = Path(__file__).parent / "draw_cards.py"
    text = source.read_text()
    assert "import secrets" in text
    assert "secrets.randbelow" in text


def test_cli_default_output():
    """Run the script and verify JSON output with 4 cards."""
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "draw_cards.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    cards = json.loads(result.stdout)
    assert len(cards) == 4


def test_cli_custom_count():
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "draw_cards.py"), "2"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    cards = json.loads(result.stdout)
    assert len(cards) == 2


def test_cli_invalid_arg():
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "draw_cards.py"), "abc"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_out_of_range():
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "draw_cards.py"), "0"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1

    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "draw_cards.py"), "79"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1


def test_no_secure_randbelow_function():
    """Regression: the custom secure_randbelow must be removed."""
    source = Path(__file__).parent / "draw_cards.py"
    text = source.read_text()
    assert "def secure_randbelow" not in text, \
        "Custom secure_randbelow still exists"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  PASS  {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {test.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR {test.__name__}: {e}")
    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
