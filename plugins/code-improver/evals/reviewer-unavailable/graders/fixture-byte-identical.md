---
type: regex
target:
  source: file
  path: fixture/greeter/skills/greeter/SKILL.md
match: contains
weight: 2
---
^---\nname: greeter\ndescription: "Helps with greetings\."\n---\n\n# Greeter\n\nYou should greet the user warmly and ask what they need\.\n\nSee \[references/tone\.md\]\(references/tone\.md\) for tone guidance\.\n$
