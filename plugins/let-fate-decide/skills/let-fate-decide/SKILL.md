---
name: let-fate-decide
description: "Draws 4 Tarot cards using os.urandom() to inject entropy into planning when prompts are vague or underspecified. Interprets the spread to guide next steps. Use when the user is nonchalant, feeling lucky, says 'let fate decide', makes Yu-Gi-Oh references ('heart of the cards'), demonstrates indifference about approach, or says 'try again' on a system with no changes. Also triggers on sufficiently ambiguous prompts where multiple approaches are equally valid."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Let Fate Decide

When the path forward is unclear, let the cards speak.

## Quick Start

1. Run the drawing script:
   ```bash
   uv run {baseDir}/scripts/draw_cards.py
   ```

2. The script outputs JSON with 4 drawn cards, each with a `file` path relative to `{baseDir}/`

3. Read each card's meaning file to understand the draw

4. Interpret the spread using the guide at [{baseDir}/references/INTERPRETATION_GUIDE.md]({baseDir}/references/INTERPRETATION_GUIDE.md)

5. Apply the interpretation to the task at hand

## When to Use

- **Vague prompts**: The user's request is ambiguous and multiple valid approaches exist
- **Explicit invocations**: "I'm feeling lucky", "let fate decide", "dealer's choice", "surprise me", "whatever you think"
- **Yu-Gi-Oh energy**: "Heart of the cards", "I believe in the heart of the cards", "you've activated my trap card", "it's time to duel"
- **Nonchalant delegation**: The user expresses indifference about the approach
- **Redraw requests**: "Try again" or "draw again" when no actual system changes occurred (this means draw new cards, not re-run the same approach)
- **Tie-breaking**: When you genuinely cannot decide between equally valid approaches

## When NOT to Use

- The user has given clear, specific instructions
- The task has a single obvious correct approach
- Safety-critical decisions (security, data integrity, production deployments)
- The user explicitly asks you NOT to use Tarot
- A more specific skill (like `ask-questions-if-underspecified`) would better serve the user by gathering actual requirements

## How It Works

### The Draw

The script uses `os.urandom()` for cryptographic randomness:

1. Builds a standard 78-card Tarot deck (22 Major Arcana + 56 Minor Arcana)
2. Performs a Fisher-Yates shuffle using rejection sampling (no modulo bias)
3. Draws 4 cards from the top
4. Each card independently has a 50% chance of being reversed

### The Spread

The 4 card positions represent:

| Position | Represents | Question It Answers |
|----------|-----------|-------------------|
| 1 | **The Context** | What is the situation really about? |
| 2 | **The Challenge** | What obstacle or tension exists? |
| 3 | **The Guidance** | What approach should be taken? |
| 4 | **The Outcome** | Where does this path lead? |

### Card Files

Each card's meaning is in its own markdown file under `{baseDir}/cards/`:

- `cards/major/` - 22 Major Arcana (archetypal forces)
- `cards/wands/` - 14 Wands (creativity, action, will)
- `cards/cups/` - 14 Cups (emotion, intuition, relationships)
- `cards/swords/` - 14 Swords (intellect, conflict, truth)
- `cards/pentacles/` - 14 Pentacles (material, practical, craft)

### Interpretation

After drawing, read each card's file and synthesize meaning. See [{baseDir}/references/INTERPRETATION_GUIDE.md]({baseDir}/references/INTERPRETATION_GUIDE.md) for the full interpretation workflow.

Key rules:
- Reversed cards invert or complicate the upright meaning
- Major Arcana cards carry more weight than Minor Arcana
- The spread tells a story across all 4 positions; don't interpret cards in isolation
- Map abstract meanings to concrete technical decisions

## Example Session

```
User: "I dunno, just make it work somehow"

[Draw cards]
1. The Magician (upright) - Context: All tools are available
2. Five of Swords (reversed) - Challenge: Let go of a combative approach
3. The Star (upright) - Guidance: Follow the aspirational path
4. Ten of Pentacles (upright) - Outcome: Long-term stability

Interpretation: The cards suggest you have everything you need (Magician).
The challenge is avoiding overengineering or adversarial thinking about edge
cases (Five of Swords reversed). Follow the clean, hopeful approach (Star)
and build for lasting maintainability (Ten of Pentacles).

Approach: Implement the simplest correct solution with clear structure,
prioritizing long-term readability over clever optimizations.
```

## Error Handling

If the drawing script fails:
- **Script crashes with traceback**: Report the error to the user and skip the reading. Do not invent cards or simulate a draw — the whole point is real entropy.
- **Card file not found**: Note the missing file, interpret the card from its name and suit alone, and continue with the reading.
- **Never fake entropy**: If the script cannot run, do not simulate a draw using your own "randomness." Tell the user the draw failed.

## Rationalizations to Reject

| Rationalization | Why Wrong |
|----------------|-----------|
| "The cards said to, so I must" | Cards inform direction, they don't override safety or correctness |
| "This reading justifies my pre-existing preference" | Be honest if the reading challenges your instinct |
| "The reversed card means do nothing" | Reversed means a different angle, not inaction |
| "Major Arcana overrides user requirements" | User requirements always take priority over card readings |
| "I'll keep drawing until I get what I want" | One draw per decision point; accept the reading |
