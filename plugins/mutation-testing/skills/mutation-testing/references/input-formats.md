# Input Format Examples

Parsing anchors for mutation testing tools with non-standard output formats. Most tools (mutmut, cargo-mutants, mutahunter) produce straightforward JSON or CSV that can be parsed directly from field names. The formats below have non-obvious structure that benefits from explicit examples.

---

## slither-mutate (Solidity)

Plain text log with mutation type markers in brackets and file paths.

```
[CR] Mutation: ConditionalOperatorReplacement
  Original: require(amount > 0)
  Mutated:  require(amount >= 0)
  File: src/Token.sol
  Line: 45
  Status: SURVIVED
```

**Key fields:** Mutation type in `[CR]`/`[SR]`/`[LOR]`/etc. brackets, `File:`, `Line:`, `Status:` labels.
**Parsing anchor:** Lines starting with `[` followed by a two-to-four letter mutation code.

---

## mull (C/C++)

JSON output using the mutation-testing-elements schema, SQLite database, or HTML report.

JSON (mutation-testing-elements schema):

```json
{
  "files": {
    "src/parser.c": {
      "mutants": [
        {
          "id": "mull-1",
          "mutatorName": "cxx_ge_to_lt",
          "location": {"start": {"line": 88, "column": 12}},
          "status": "Survived",
          "replacement": "<"
        }
      ]
    }
  }
}
```

**Key fields:** `files.<path>.mutants[]` array, `mutatorName` (e.g., `cxx_ge_to_lt`, `cxx_add_to_sub`, `cxx_remove_void_call`), `location.start.line`, `status`.
**Parsing anchor:** Top-level `"files"` key with nested `"mutants"` arrays. Mutator names use the `cxx_` prefix.

**SQLite format:** Tables include `mutant`, `mutation_point`, and `mutation_result`. Export to CSV or JSON before analysis.

---

## dextool-mutate (C/C++)

HTML, JSON, or SQLite report with conventional mutation operator names.

JSON format:

```json
{
  "mutants": [
    {
      "id": 157,
      "file": "src/buffer.c",
      "line": 42,
      "operator": "ROR",
      "original": "size > capacity",
      "mutation": "size >= capacity",
      "status": "alive"
    }
  ]
}
```

**Key fields:** `file`, `line`, `operator`, `original`, `mutation`, `status`.
**Parsing anchor:** Operator codes follow conventional names: AOR (arithmetic operator replacement), ROR (relational operator replacement), LCR (logical connector replacement), SDL (statement deletion), UOI (unary operator insertion). Filter for `"status": "alive"`.

**SQLite format:** Main table is `mutation` with columns `mut_id`, `file`, `line`, `operator`, `status`. Export to CSV or JSON before analysis.
