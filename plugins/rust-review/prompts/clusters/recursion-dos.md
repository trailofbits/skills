---
name: cluster-recursion-dos
kind: cluster
consolidated: false
covers:
  - recursive-format-stack-overflow       # RECURSEFMT
  - recursive-drop-stack-overflow         # RECURSEDROP
  - recursive-deserialize-stack-overflow  # RECURSEDES
---

# Cluster: Recursion-induced stack overflow

Stack overflow is *not* a panic. It cannot be caught with `std::panic::catch_unwind`, and it aborts the process unconditionally regardless of `panic = "abort" | "unwind"`. On a server, an attacker who controls the *depth* of a parsed/formatted/dropped data structure converts that depth into a per-frame stack consumer and crashes the **entire process** (a stack overflow in any thread aborts the whole process via the runtime's SIGSEGV handler — never just the offending thread). The shared mental model across this cluster: **recursive descent over attacker-shaped data depth → stack consumption proportional to depth → SIGSEGV abort**.

Three families share the same recursive-descent pattern but trigger at different lifecycle stages:

- **Parse** — `Deserialize` walks input depth.
- **Format/serialize** — `Display`/`Debug`/`Serialize` walks value depth.
- **Drop** — implicit `Drop` walks chain depth (the `Box<Self>` / linked-list footgun).

Note the asymmetry: `serde_json` enforces a 128-deep recursion limit during deserialization, but `Display`/`Debug`/`Serialize` and implicit `Drop` impose **no depth cap**. Input that parses successfully may still overflow when logged, re-serialized, or dropped.

ID prefixes: `RECURSEFMT`, `RECURSEDROP`, `RECURSEDES`.

---

## Phase A — Build the recursive-type map (ONCE)

A type is *recursive* if it (transitively) contains itself behind an indirection. Find them:

```
rg seed: "Box<\s*Self\s*>|Vec<\s*Self\s*>|Option<\s*Box<\s*Self"
rg seed: "(Rc|Arc)<\s*(Self|RefCell<\s*Self|Mutex<\s*Self|RwLock<\s*Self|Box<\s*Self)"
rg seed: "HashMap<[^,>]+,\s*(Self|Box<\s*Self)"
rg seed: "enum\s+\w+\b"   # candidates for recursive enum (AST/JSON-value shapes)
rg seed: "struct\s+\w+\b" # candidates for recursive struct (tree/linked-list shapes)
```

For each candidate, confirm recursion by inspection: a field, variant payload, or alias whose type names the parent (directly or via `Box`/`Vec`/`Rc`/`Arc`/`HashMap`/`BTreeMap`/`IndexMap`).

Also flag **library types known to be recursive** (treat as recursive without further inspection):

- `serde_json::Value`, `serde_yaml::Value`, `toml::Value`, `ron::Value`, `ciborium::Value`
- `syn::Expr`, `syn::Type`, `syn::Item` and the rest of `syn`'s AST
- `proc_macro2::TokenStream` / `TokenTree::Group`
- Any crate-local `enum`/`struct` named `Value`, `Node`, `Expr`, `Ast`, `Term`, `Json`, `Yaml`, `Toml`, `Tree`, `List` whose definition matches the recursive-shape greps above.

Record `rec_map[type_name] = { kind: enum|struct|alias, indirection: Box|Vec|Rc|Arc|Map, manual_drop: bool, manual_debug: bool, manual_display: bool }`.

`manual_drop`/`manual_debug`/`manual_display` are negative-signal flags — a hand-written iterative impl can neutralize the finding. Confirm by reading the body (a manual `impl Drop` that still recurses is not a fix).

---

## Phase B — Map untrusted-input sources

Recursion DoS requires an attacker-controlled depth source. Identify entry points and trace data flow into types from `rec_map`:

```
rg seed: "(serde_json|serde_yaml|toml|ron|ciborium|bincode|postcard)::from_(str|slice|reader|value)"
rg seed: "\.deserialize\s*\(|#\[derive\(.*Deserialize"
rg seed: "(reqwest|hyper|axum|actix|warp|rocket|tonic)::"
rg seed: "tokio::(net|io)::|std::net::"
rg seed: "std::io::(stdin|BufReader)"
```

A site only matters if (a) the input crosses a trust boundary and (b) it lands in a type from `rec_map`.

---

## Phase C — Run finders in declared order

1. **`RECURSEDES` — Unbounded deserialization depth.** Attacker controls *input depth* during parse. Fires when an untrusted deserialize site targets a recursive type from `rec_map` *without* an explicit depth limit configured. Run **first** because it bounds what shapes the later stages even see.
2. **`RECURSEFMT` — Recursive format/serialize on untrusted-shaped value.** Attacker controls *value depth* by the time formatting runs. Fires when a recursive type from `rec_map` reaches `format!`/`{:?}`/log/`Serialize` sinks without truncation. `serde_json`'s parse-side limit does **not** apply here.
3. **`RECURSEDROP` — Stack overflow on drop.** Fires when a recursive type from `rec_map` lacks an iterative `Drop` impl *and* may reach a depth large enough to overflow (e.g., it was parsed from untrusted input, even successfully). The classic `Box<Node>` linked-list footgun.

---

## Deconfliction

- All three findings can coexist on the same type — each represents a distinct lifecycle stage with its own mitigation. Report separately when they apply at separate code sites; merge into one finding only when the *same* code site is implicated by multiple finders.
- A correctly enforced parse-side depth limit (`RECURSEDES` clean) **does not** clear `RECURSEFMT` or `RECURSEDROP`: values may be built programmatically, cloned, or composed past the parse limit.
- Conversely, an iterative `Drop` impl (`RECURSEDROP` clean) does not clear `RECURSEFMT`.
- Do **not** report under [[cluster-panic-dos]]: stack overflow aborts and is uncatchable; panics may be caught. Severity and remediation differ.

Build `rec_map` ONCE.
