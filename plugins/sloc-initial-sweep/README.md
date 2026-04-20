# sloc-initial-sweep

Logical/physical SLOC counter for audit scoping, with per-folder and per-language breakdowns.

## What it does
- Computes logical (NCSS) and physical SLOC.
- Supports common audit stacks: Solidity, TypeScript/JavaScript, Python, Rust, Go, Vyper.
- Highlights largest modules/files to prioritize review order.

## Layout
```
plugins/sloc-initial-sweep/
├── README.md
└── skills/sloc-initial-sweep/
    ├── SKILL.md
    ├── scripts/sloc_counter.py
    ├── references/SLOC_Standards.md
    └── examples/sample_output.md
```

## Usage
In Claude Code (plugin baseDir provided automatically):
```
@skills/sloc-initial-sweep/SKILL.md
Calculate logical SLOC for contracts/, exclude contracts/mocks/
```

Manual script run:
```bash
python3 {baseDir}/skills/sloc-initial-sweep/scripts/sloc_counter.py <repo_root> \
  --dirs contracts \
  --extensions .sol \
  --method logical
```

## Notes
- Default path assumes `baseDir` is the plugin root.
- Avoid writing artifacts inside target repos; keep results in scratch space.
