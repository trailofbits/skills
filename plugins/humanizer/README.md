# Humanizer

Identifies and removes AI writing patterns to make text sound natural and human-written.

## Installation

Add to your Claude Code configuration:

```json
{
  "plugins": ["github:trailofbits/skills/plugins/humanizer"]
}
```

## Usage

The skill activates when editing text that sounds artificial. It detects 24 pattern categories including:

- **Content patterns** — Inflated significance, vague attributions, promotional language
- **Language patterns** — AI vocabulary words, copula avoidance, rule of three
- **Style patterns** — Em dash overuse, inline-header lists, decorative emojis
- **Communication artifacts** — Chatbot phrases, sycophantic tone

## Example

**Before:**
> The software update serves as a testament to the company's commitment to innovation. Moreover, it provides a seamless, intuitive, and powerful user experience. Industry experts believe this will have a lasting impact.

**After:**
> The update adds batch processing, keyboard shortcuts, and offline mode. Beta testers reported faster task completion.

## Key Insight

Removing AI patterns is only half the job. Sterile, voiceless writing is just as obvious as slop. The skill also guides adding authentic voice—opinions, varied rhythm, and specific details.

## Reference

Based on [Wikipedia:Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing), maintained by WikiProject AI Cleanup.

## Credits

Original skill by [blader/humanizer](https://github.com/blader/humanizer). Restructured for the Trail of Bits skills repository.
