# let-fate-decide

A Claude Code skill that draws Tarot cards using `secrets` to inject
entropy into vague or underspecified planning decisions.

## What It Does

When a prompt is sufficiently ambiguous, or the user explicitly invokes fate,
this skill shuffles a 22-card Major Arcana deck and a 56-card Minor Arcana
deck independently using cryptographic randomness, then deals the 12 Houses of
the Zodiac spread. Each house receives one Major Arcana card followed by two
Minor Arcana cards, and all 36 cards may appear reversed. Claude then
interprets the spread and uses the reading to inform its approach.

## Triggers

- Vague or ambiguous prompts where multiple reasonable approaches exist
- "I'm feeling lucky", "let fate decide", "dealer's choice", "surprise me", "whatever you think", "YOLO"
- Casual delegation ("whatever", "up to you", "your call", "idk", "just do something", "wing it", "I trust you", "doesn't matter", "do what you want", "I don't care", "any approach works", "you pick")
- Yu-Gi-Oh references ("heart of the cards", "I believe in the heart of the cards", "you've activated my trap card", "it's time to duel")
- Shrug-like brevity -- very short prompts that fully delegate the decision
- About to arbitrarily pick between 2+ valid approaches (draw cards instead)
- "Try again" on a system with no actual changes (redraw)

## How It Works

The spread is drawn by the `draw` agent (`agents/draw.md`), dispatched as
`let-fate-decide:draw`.


1. A Python script uses `secrets.randbelow()` to perform Fisher-Yates shuffles
2. A Major Arcana deck and Minor Arcana deck are shuffled separately
3. 12 houses are dealt, each with 1 Major Arcana and 2 Minor Arcana cards
4. Each card has an independent 50% chance of being reversed
5. Claude reads the house reference files and drawn cards' meaning files
6. Claude interprets the spread
7. The interpretation informs the planning direction

The default spread records a conservative unordered-card entropy budget
exceeding 100 bits: roughly `log2(C(22,12))` bits from Major Arcana selection,
`log2(C(56,24))` bits from Minor Arcana selection (assuming
`secrets.randbelow()` is cryptographically secure), and 36 bits from
independent card reversal choices. Exact values are computed at draw time and
reported in the JSON output under `entropy_bits`. The actual ordered assignment
of cards to houses contains more entropy.

In security, audit, and correctness workflows, this skill is only a discovery
and hypothesis-generation aid. It can suggest where to look next, but evidence
from review, testing, reproduction, or formal reasoning must decide whether a
risk is real or resolved.

## Reference Organization

Each zodiac house has its own markdown file under `houses/`. These files
explain the house's technical meaning for building new projects, vulnerability
discovery, correctness verification, and recurring workflows from the local
security and engineering workflows this skill supports.

`references/TECHNICAL_CONTEXT_LENSES.md` distills those workflow themes into
audit-stage, evidence-mode, domain, failure-class, and human/organizational
lenses.

Each of the 78 Tarot cards has its own markdown file:

- `cards/major/` - 22 Major Arcana (The Fool through The World)
- `cards/wands/` - 14 Wands (Ace through King)
- `cards/cups/` - 14 Cups (Ace through King)
- `cards/swords/` - 14 Swords (Ace through King)
- `cards/pentacles/` - 14 Pentacles (Ace through King)

## Calcifier recipe for `let-fate-decide`

The [`let-fate-decide` Python recipe](skills/let-fate-decide/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/let-fate-decide/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/let-fate-decide/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `task` | `str` | Required |
| `working_directory` | `str` | `'.'` |
| `answer_mode` | `Literal['task', 'portent']` | `'task'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
