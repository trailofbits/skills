# let-fate-decide

A Claude Code skill that draws Tarot cards using `secrets` to inject
entropy into vague or underspecified planning decisions.

## What It Does

When a prompt is sufficiently ambiguous, or the user explicitly invokes fate,
this skill shuffles a full 78-card Tarot deck using cryptographic randomness
and draws 4 cards (which may appear reversed). Claude then interprets the
spread and uses the reading to inform its approach.

## Triggers

- Vague or ambiguous prompts where multiple reasonable approaches exist
- "I'm feeling lucky", "let fate decide", "YOLO"
- Casual delegation ("whatever", "up to you", "your call", "idk", "just do something", "wing it", "I trust you", "doesn't matter", "surprise me", "dealer's choice")
- Yu-Gi-Oh references ("heart of the cards", "I believe in the heart of the cards")
- Shrug-like brevity — very short prompts that fully delegate the decision
- About to arbitrarily pick between equally valid approaches (draw cards instead)
- "Try again" on a system with no actual changes (redraw)

## How It Works

1. A Python script uses `secrets` to perform a Fisher-Yates shuffle
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
