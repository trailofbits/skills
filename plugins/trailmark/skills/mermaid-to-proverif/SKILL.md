---
name: mermaid-to-proverif
description: "Translates an annotated Mermaid sequenceDiagram of a cryptographic protocol into a ProVerif model (.pv) and verifies it. Use when formally verifying a protocol, proving secrecy, authentication, or forward secrecy, checking for replay attacks, or producing a .pv file from a sequence diagram."
---

# Mermaid to ProVerif

Translate the supplied `sequenceDiagram` (usually the output of `crypto-protocol-diagram`) into
one `.pv` model and verify it with ProVerif. Use the diagram's participants, arrows, notes, and
requested properties; do not invent protocol steps. If there is no diagram yet, ask for one or
run `crypto-protocol-diagram` first; to check an existing `.pv`, run `proverif` on it directly.

## Rules

- Declare only the primitives the diagram uses, with the exact declarations in
  [crypto-to-proverif-mapping.md](references/crypto-to-proverif-mapping.md). Destructors
  (decryption, signature verification, commitment opening) are inline `reduc` functions so a
  failed check aborts the process; equations are for constructor identities such as DH only.
- One `let` process per participant, mirroring the diagram's message order; long-term keys are
  parameters, ephemeral values use `new`; the main process publishes public keys on `c` and runs
  every role under replication (`!`). One shared public channel `c`; private channels only for
  state threading inside one party.
- Fire `begin` events before a party sends an identity-binding message and `end` events after it
  verifies the peer; parameters must identify the session (public keys plus the session key or
  transcript).
- Queries: reachability of every party's `end` event first (they are sanity checks; a dead
  process makes every other result vacuous), then secrecy via a private witness encrypted under
  the session key, then injective correspondence where replay matters. Ephemeral keys in the
  diagram mean the Forward Secrecy pattern in
  [security-properties.md](references/security-properties.md) is required.
- File order: channels, `noselect`, types, constants, functions, equations, tables, events,
  queries, `let` processes, main process. Remove unused declarations.

## Procedure

1. Extract participants, arrows, cryptographic operations, events, and the requested properties
   from the diagram. Read the mapping reference for every operation you declare.
2. Write the model to `<protocol-name>.pv`.
3. Verify it mechanically:

   ```bash
   uv run --no-project {baseDir}/scripts/verify_pv.py <protocol-name>.pv
   ```

   It fails when ProVerif is missing, the model does not compile, a sanity event is unreachable,
   a property is false or cannot be proved, or there are no RESULT lines. Fix the model, not the
   query, and rerun until it passes. If ProVerif is not installed, say so and deliver the
   unverified model with that caveat.
4. Deliver the `.pv` path and a four-line summary: protocol, output path, queries (each with the
   property it tests), and modeling assumptions.

## When you need more

- [security-properties.md](references/security-properties.md): weak vs injective authentication,
  forward secrecy, unlinkability, the key-exposure oracle, and the decision tree.
- [proverif-syntax.md](references/proverif-syntax.md): tables, `noselect` for non-termination,
  typed-syntax errors.
- `examples/simple-handshake/sample-output.pv`: a complete signed-DH model; read it only for an
  unfamiliar primitive or pattern.
