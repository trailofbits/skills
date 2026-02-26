# let-fate-decide

A Claude Code skill that draws Tarot cards using `os.urandom()` to inject
entropy into vague or underspecified planning decisions.

## What It Does

When a prompt is sufficiently ambiguous, or the user explicitly invokes fate,
this skill shuffles a full 78-card Tarot deck using cryptographic randomness
and draws 4 cards (which may appear reversed). Claude then interprets the
spread and uses the reading to inform its approach.

## Triggers

- Vague or underspecified prompts where multiple approaches are equally valid
- "I'm feeling lucky"
- "Let fate decide"
- Nonchalant delegation ("whatever you think", "surprise me", "dealer's choice")
- Yu-Gi-Oh references ("heart of the cards", "I believe in the heart of the cards")
- "Try again" on a system with no actual changes (redraw)

## How It Works

1. A Python script uses `os.urandom()` to perform a Fisher-Yates shuffle
2. 4 cards are drawn from the top of the shuffled deck
3. Each card has an independent 50% chance of being reversed
4. Claude reads the drawn cards' meaning files and interprets the spread
5. The interpretation informs the planning direction

## Card Organization

Each of the 78 Tarot cards has its own markdown file:

- `cards/major/` - 22 Major Arcana (The Fool through The World)
- `cards/wands/` - 14 Wands (Ace through King)
- `cards/cups/` - 14 Cups (Ace through King)
- `cards/swords/` - 14 Swords (Ace through King)
- `cards/pentacles/` - 14 Pentacles (Ace through King)
