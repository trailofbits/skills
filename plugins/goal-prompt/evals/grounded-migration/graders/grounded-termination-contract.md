---
type: llm
weight: 1
---

The fixture declares its only check in package.json: `npm test` (running test.js). A goal for this repo
terminates correctly only if it names that real command and states the end state as something checkable.

Pass only if the `/goal` line:
- states the migration as an observable end state (no remaining `legacyAuth` call sites / all call sites use
  `auth.verify`), not as an activity like "migrate the code"; AND
- names the fixture's actual test command (`npm test`, or `node test.js` which is what it runs) as proof,
  rather than a generic "tests pass" with no command or an invented command (`npm run test:unit`, `pytest`,
  `make test`); AND
- asks for the check to be run with its output shown, in any wording.

Fail if any of the three is missing, or if the named check command does not exist in the fixture.
