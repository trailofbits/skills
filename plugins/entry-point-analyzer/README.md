# Entry Point Analyzer

A Claude Code plugin and Codex skill for systematically identifying **state-changing** entry points in smart contract codebases to guide security audits.

## Purpose

When auditing smart contracts, examining each file or function individually is inefficient. What auditors need is to start from **entry points**—the externally callable functions that represent the attack surface. This skill automates the identification and classification of state-changing entry points, excluding view/pure/read-only functions that cannot directly cause loss of funds or state corruption.

## Supported Languages

| Language | File Extensions | Framework Support |
|----------|-----------------|-------------------|
| Solidity | `.sol` | OpenZeppelin, custom modifiers |
| Vyper | `.vy` | Native patterns |
| Solana | `.rs` | Anchor, Native |
| Move | `.move` | Aptos, Sui |
| TON | `.fc`, `.func`, `.tact` | FunC, Tact |
| CosmWasm | `.rs` | cw-ownable, cw-controllers |

## Access Classifications

The skill categorizes entry points into four levels:

1. **Public (Unrestricted)** — Callable by anyone; highest audit priority
2. **Role-Restricted** — Limited to specific roles (admin, governance, guardian, etc.)
3. **Review Required** — Ambiguous access patterns needing manual verification
4. **Contract-Only** — Functions with enforced caller checks tied to integration contracts

## Output

Generates a structured markdown report with:
- Summary table of entry point counts by category
- Detailed tables for each access level
- Function signatures with file:line references
- Restriction patterns and role assignments
- List of analyzed files

## Usage

Trigger the skill with requests like:
- "Analyze the entry points in this codebase"
- "Find all external functions and access levels"
- "List audit flows for src/core/"
- "What privileged operations exist in this project?"

In Claude Code, invoke the skill or pass a directory to the slash command:

```text
/entry-point-analyzer:entry-point-analyzer
/entry-point-analyzer:entry-points src/core/
```

In Codex, invoke the skill directly:

```text
Use $entry-point-analyzer to analyze src/core/.
```

## Directory Filtering

Specify a subdirectory to limit scope:
- "Analyze only `src/core/`"
- "Find entry points in `contracts/protocol/`"

## Role Detection

The skill infers roles from common patterns:

| Pattern | Detected Role |
|---------|---------------|
| `onlyOwner`, `msg.sender == owner` | Owner |
| `onlyAdmin`, `ADMIN_ROLE` | Admin |
| `onlyGovernance`, `governance` | Governance |
| `onlyGuardian`, `onlyPauser` | Guardian |
| `onlyKeeper`, `onlyRelayer` | Keeper/Relayer |
| `onlyStrategy`, `strategist` | Strategist |
| Dynamic checks (`authorized[msg.sender]`) | Review Required |

## Installation

### Claude Code

```text
/plugin marketplace add trailofbits/skills
/plugin install entry-point-analyzer@trailofbits
```

### Codex

```sh
codex plugin marketplace add trailofbits/skills
codex plugin add entry-point-analyzer@trailofbits
```

Start a new session after installation. The skill includes its language
references and can run without Slither; if Slither is installed, it uses the
entry-points printer before manual access-control classification.

## License

See LICENSE.txt for terms.

## Calcifier recipe for `entry-point-analyzer`

The [`entry-point-analyzer` Python recipe](skills/entry-point-analyzer/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/entry-point-analyzer/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/entry-point-analyzer/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `project_directory` | `str` | `'.'` |
| `directory_filter` | `str` | `'.'` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
