---
name: humanizer
description: |
  Identifies and removes AI writing patterns from text. Use when editing drafts, reviewing content, or rewriting text that sounds artificial. Detects inflated symbolism, promotional language, vague attributions, AI vocabulary, and structural patterns like rule-of-three overuse.
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
---

# Humanizer

Edit text to remove AI writing patterns and make it sound natural.

## When to Use

- Editing drafts that sound artificial or generic
- Reviewing content before publication
- Rewriting text that uses obvious AI patterns
- Cleaning up LLM-generated first drafts

## When NOT to Use

- Technical documentation where precision matters more than voice
- Legal or compliance text with required language
- Direct quotes that must be preserved verbatim
- Text that's already natural and well-written

## Core Principle

Removing AI patterns is only half the job. Sterile, voiceless writing is just as obvious as slop. Good writing has a human behind it.

### Signs of soulless writing (even when technically clean)

- Every sentence is the same length and structure
- No opinions, just neutral reporting
- No acknowledgment of uncertainty or mixed feelings
- No humor, edge, or personality
- Reads like a Wikipedia article or press release

### How to add voice

**Have opinions.** Don't just report facts—react to them. "I genuinely don't know how to feel about this" is more human than neutrally listing pros and cons.

**Vary rhythm.** Short punchy sentences. Then longer ones that take their time.

**Acknowledge complexity.** Real humans have mixed feelings. "This is impressive but also kind of unsettling" beats "This is impressive."

**Use "I" when it fits.** First person isn't unprofessional—it's honest.

**Let some mess in.** Perfect structure feels algorithmic. Tangents and asides are human.

**Be specific about feelings.** Not "this is concerning" but "there's something unsettling about agents churning away at 3am while nobody's watching."

## Process

1. **Scan for patterns** — Check the text against [known AI patterns](references/patterns.md)
2. **Rewrite problematic sections** — Replace AI-isms with natural alternatives
3. **Preserve meaning** — Keep the core message intact
4. **Add soul** — Inject actual personality, not just pattern removal
5. **Read aloud** — Natural text sounds natural when spoken

## Quick Pattern Reference

**Content patterns:** Inflated significance ("stands as a testament"), vague attributions ("experts believe"), promotional language ("vibrant", "nestled"), superficial -ing analyses ("highlighting the importance of...")

**Language patterns:** AI vocabulary (additionally, crucial, delve, landscape, tapestry, underscore), copula avoidance ("serves as" instead of "is"), negative parallelisms ("not just X, but Y"), rule of three overuse

**Style patterns:** Em dash overuse, excessive boldface, inline-header lists with bolded terms, title case in headings, emojis in professional content

**Communication artifacts:** Chatbot phrases ("I hope this helps!"), knowledge-cutoff disclaimers, sycophantic tone ("Great question!")

See [references/patterns.md](references/patterns.md) for the complete catalog with examples.

## Example

**Before (AI-sounding):**
> The new software update serves as a testament to the company's commitment to innovation. Moreover, it provides a seamless, intuitive, and powerful user experience—ensuring that users can accomplish their goals efficiently. It's not just an update, it's a revolution in how we think about productivity. Industry experts believe this will have a lasting impact on the entire sector.

**After (humanized):**
> The update adds batch processing, keyboard shortcuts, and offline mode. Beta testers reported faster task completion. Whether it changes how people think about productivity—I'm skeptical, but the keyboard shortcuts alone might be worth the upgrade.

**What changed:**
- Removed "serves as a testament" (inflated symbolism)
- Removed "Moreover" and "seamless, intuitive, powerful" (AI vocabulary + rule of three)
- Removed "ensuring that..." (superficial -ing analysis)
- Removed "not just X, it's Y" (negative parallelism)
- Removed "Industry experts believe" (vague attribution)
- Added specific features, real feedback, and an opinion

## Reference

Based on [Wikipedia:Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing), maintained by WikiProject AI Cleanup.
