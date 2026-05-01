#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Control-Flow Graph analyzer for zeroization path coverage.

This tool builds CFGs from source code or LLVM IR to verify that:
- Zeroization occurs on ALL execution paths
- Early returns don't skip cleanup
- Error paths include proper cleanup
- Wipes dominate all function exits
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CFGNode:
    """Node in control flow graph."""

    id: str
    type: str  # 'entry', 'exit', 'statement', 'branch', 'return'
    line_num: int | None = None
    statement: str | None = None
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    has_wipe: bool = False
    has_sensitive_var: bool = False


class CFGBuilder:
    """Build control flow graph from source or IR."""

    def __init__(self, source_file: Path, sensitive_patterns: list[str], wipe_patterns: list[str]):
        self.source_file = source_file
        self.sensitive_patterns = sensitive_patterns
        self.wipe_patterns = wipe_patterns
        self.nodes: dict[str, CFGNode] = {}
        self.entry_node: str | None = None
        self.exit_nodes: set[str] = set()
        self.node_counter = 0

    def create_node(
        self, node_type: str, line_num: int | None = None, statement: str | None = None
    ) -> str:
        """Create a new CFG node."""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1

        node = CFGNode(id=node_id, type=node_type, line_num=line_num, statement=statement)

        # Check if this node has sensitive variable
        if statement:
            for pattern in self.sensitive_patterns:
                if re.search(pattern, statement, re.IGNORECASE):
                    node.has_sensitive_var = True
                    break

            # Check if this node has wipe
            for pattern in self.wipe_patterns:
                if re.search(pattern, statement):
                    node.has_wipe = True
                    break

        self.nodes[node_id] = node
        return node_id

    def add_edge(self, from_id: str, to_id: str) -> None:
        """Add directed edge in CFG."""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].successors.append(to_id)
            self.nodes[to_id].predecessors.append(from_id)

    def build_from_source(self) -> None:
        """Build CFG from source code (simplified C/C++ parser)."""
        with open(self.source_file) as f:
            lines = f.readlines()

        self.entry_node = self.create_node("entry")
        current_node = self.entry_node

        in_function = False
        brace_depth = 0
        branch_stack = []  # Stack of (condition_node, merge_node) pairs

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Function start
            if "{" in line and not in_function:
                in_function = True
                brace_depth = line.count("{")
                continue

            if not in_function:
                continue

            # Track brace depth
            brace_depth += line.count("{") - line.count("}")

            # Function end
            if brace_depth == 0:
                in_function = False
                # Connect to exit
                exit_node = self.create_node("exit", line_num)
                self.add_edge(current_node, exit_node)
                self.exit_nodes.add(exit_node)
                continue

            # Return statement
            if re.match(r"\s*return\b", stripped):
                return_node = self.create_node("return", line_num, stripped)
                self.add_edge(current_node, return_node)
                exit_node = self.create_node("exit", line_num)
                self.add_edge(return_node, exit_node)
                self.exit_nodes.add(exit_node)
                # Reset current for next statement (in case there's dead code)
                current_node = return_node
                continue

            # If statement
            if re.match(r"\s*if\s*\(", stripped):
                branch_node = self.create_node("branch", line_num, stripped)
                self.add_edge(current_node, branch_node)

                # Create merge point for later
                merge_node = self.create_node("statement", line_num, "// merge point")
                branch_stack.append((branch_node, merge_node))

                # True branch starts after condition
                true_node = self.create_node("statement", line_num, "// true branch")
                self.add_edge(branch_node, true_node)
                current_node = true_node
                continue

            # Else statement
            if re.match(r"\s*else\b", stripped):
                if branch_stack:
                    branch_node, merge_node = branch_stack[-1]
                    # False branch
                    false_node = self.create_node("statement", line_num, "// false branch")
                    self.add_edge(branch_node, false_node)
                    # Connect previous path to merge
                    self.add_edge(current_node, merge_node)
                    current_node = false_node
                continue

            # End of branch (closing brace)
            if stripped == "}" and branch_stack:
                branch_node, merge_node = branch_stack.pop()
                self.add_edge(current_node, merge_node)
                current_node = merge_node
                continue

            # Regular statement
            stmt_node = self.create_node("statement", line_num, stripped)
            self.add_edge(current_node, stmt_node)
            current_node = stmt_node

        # Ensure we have at least one exit node
        if not self.exit_nodes:
            exit_node = self.create_node("exit")
            self.add_edge(current_node, exit_node)
            self.exit_nodes.add(exit_node)

    def find_all_paths_to_exit(self) -> list[list[str]]:
        """Find all paths from entry to any exit node."""
        if not self.entry_node:
            return []

        all_paths = []

        def dfs(node_id: str, path: list[str], visited: set[str]) -> None:
            if node_id in visited:
                return  # Avoid cycles

            visited.add(node_id)
            path.append(node_id)

            node = self.nodes[node_id]

            # If this is an exit node, save the path
            if node_id in self.exit_nodes:
                all_paths.append(path.copy())
            else:
                # Continue to successors
                for succ_id in node.successors:
                    dfs(succ_id, path, visited.copy())

            path.pop()

        dfs(self.entry_node, [], set())
        return all_paths

    def check_path_has_wipe(self, path: list[str]) -> tuple[bool, str | None]:
        """Check if a path contains a wipe operation."""
        for node_id in path:
            if self.nodes[node_id].has_wipe:
                return True, node_id
        return False, None

    def check_path_has_sensitive_var(self, path: list[str]) -> bool:
        """Check if a path uses sensitive variables."""
        return any(self.nodes[node_id].has_sensitive_var for node_id in path)

    def compute_dominators(self) -> dict[str, set[str]]:
        """Compute dominator sets for all nodes."""
        if not self.entry_node:
            return {}

        # Initialize
        dominators = {}
        all_nodes = set(self.nodes.keys())

        dominators[self.entry_node] = {self.entry_node}

        for node_id in all_nodes:
            if node_id != self.entry_node:
                dominators[node_id] = all_nodes.copy()

        # Iterate until fixpoint
        changed = True
        while changed:
            changed = False
            for node_id in all_nodes:
                if node_id == self.entry_node:
                    continue

                # Dom(n) = {n} ∪ (∩ Dom(p) for all predecessors p)
                new_dom = {node_id}
                if self.nodes[node_id].predecessors:
                    pred_doms = [dominators[pred] for pred in self.nodes[node_id].predecessors]
                    if pred_doms:
                        new_dom = new_dom.union(set.intersection(*pred_doms))

                if new_dom != dominators[node_id]:
                    dominators[node_id] = new_dom
                    changed = True

        return dominators

    def verify_wipe_dominates_exits(self) -> dict:
        """Verify that wipe operations dominate all exit nodes."""
        dominators = self.compute_dominators()

        # Find all wipe nodes
        wipe_nodes = [node_id for node_id, node in self.nodes.items() if node.has_wipe]

        results = {
            "wipe_dominates_all_exits": True,
            "wipe_nodes": wipe_nodes,
            "problematic_exits": [],
        }

        for exit_id in self.exit_nodes:
            exit_doms = dominators.get(exit_id, set())

            # Check if any wipe node dominates this exit
            has_dominating_wipe = any(wipe_id in exit_doms for wipe_id in wipe_nodes)

            if not has_dominating_wipe:
                results["wipe_dominates_all_exits"] = False
                results["problematic_exits"].append(
                    {
                        "exit_node": exit_id,
                        "line": self.nodes[exit_id].line_num,
                        "dominators": list(exit_doms),
                    }
                )

        return results

    def analyze(self) -> dict:
        """Perform comprehensive CFG analysis."""
        # Find all paths
        all_paths = self.find_all_paths_to_exit()

        # Check each path
        paths_with_wipe = 0
        paths_without_wipe = []
        paths_with_sensitive_vars = 0

        for i, path in enumerate(all_paths):
            has_wipe, wipe_node = self.check_path_has_wipe(path)
            has_sensitive = self.check_path_has_sensitive_var(path)

            if has_wipe:
                paths_with_wipe += 1
            elif has_sensitive:
                # Sensitive path without wipe
                paths_without_wipe.append(
                    {
                        "path_id": i,
                        "length": len(path),
                        "nodes": [
                            {
                                "id": node_id,
                                "line": self.nodes[node_id].line_num,
                                "statement": self.nodes[node_id].statement,
                            }
                            for node_id in path
                        ],
                    }
                )

            if has_sensitive:
                paths_with_sensitive_vars += 1

        # Dominator analysis
        dominator_results = self.verify_wipe_dominates_exits()

        return {
            "cfg_stats": {
                "total_nodes": len(self.nodes),
                "total_paths": len(all_paths),
                "exit_nodes": len(self.exit_nodes),
            },
            "wipe_coverage": {
                "paths_with_wipe": paths_with_wipe,
                "paths_without_wipe": len(paths_without_wipe),
                "paths_with_sensitive_vars": paths_with_sensitive_vars,
                "coverage_percentage": (paths_with_wipe / len(all_paths) * 100) if all_paths else 0,
            },
            "problematic_paths": paths_without_wipe,
            "dominator_analysis": dominator_results,
        }


def main():
    parser = argparse.ArgumentParser(description="Control-flow graph analyzer")
    parser.add_argument("--src", required=True, help="Source file to analyze")
    parser.add_argument("--out", required=True, help="Output JSON file")

    args = parser.parse_args()

    # Default patterns
    sensitive_patterns = [
        r"\b(secret|key|seed|priv|private|sk|shared_secret|nonce|token|pwd|pass)\b"
    ]
    wipe_patterns = [
        r"\bexplicit_bzero\s*\(",
        r"\bmemset_s\s*\(",
        r"\bOPENSSL_cleanse\s*\(",
        r"\bsodium_memzero\s*\(",
        r"\bzeroize\s*\(",
    ]

    # Build CFG
    builder = CFGBuilder(Path(args.src), sensitive_patterns, wipe_patterns)
    try:
        builder.build_from_source()
    except OSError as e:
        print(f"Error: cannot read source file {args.src}: {e}", file=sys.stderr)
        sys.exit(1)

    # Analyze
    results = {"source_file": args.src, "analysis": builder.analyze()}

    # Write output
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"OK: CFG analysis written to {args.out}")


if __name__ == "__main__":
    main()
