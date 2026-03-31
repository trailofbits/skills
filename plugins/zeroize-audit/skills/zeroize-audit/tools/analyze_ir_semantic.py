#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Semantic LLVM IR analyzer for zeroization detection.

This tool parses LLVM IR structurally (not just regex) to detect:
- Memory operations in SSA form (mem2reg output)
- Loop-unrolled zeroization patterns
- Complex optimization transformations
- Store/load chains that affect zeroization
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IRInstruction:
    """Represents an LLVM IR instruction."""

    line_num: int
    opcode: str
    operands: list[str]
    result: str | None
    raw_line: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class BasicBlock:
    """Represents a basic block in LLVM IR."""

    label: str
    instructions: list[IRInstruction]
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)


@dataclass
class Function:
    """Represents a function in LLVM IR."""

    name: str
    basic_blocks: dict[str, BasicBlock]
    entry_block: str | None = None
    arguments: list[str] = field(default_factory=list)


class SemanticIRAnalyzer:
    """Semantic analyzer for LLVM IR."""

    def __init__(self, ir_file: Path, config: dict):
        self.ir_file = ir_file
        self.config = config
        self.functions: dict[str, Function] = {}
        self.current_function: Function | None = None
        self.current_block: BasicBlock | None = None

    def parse_ir(self) -> None:
        """Parse LLVM IR file into structured representation."""
        with open(self.ir_file) as f:
            lines = f.readlines()

        line_num = 0
        for line in lines:
            line_num += 1
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith(";"):
                continue

            # Function definition
            if line.startswith("define "):
                self._parse_function_def(line)
                continue

            # Function end
            if line == "}" and self.current_function:
                self.functions[self.current_function.name] = self.current_function
                self.current_function = None
                self.current_block = None
                continue

            # Basic block label
            if self.current_function and ":" in line and not line.startswith("%"):
                label = line.split(":")[0].strip()
                self.current_block = BasicBlock(label=label, instructions=[])
                self.current_function.basic_blocks[label] = self.current_block
                if not self.current_function.entry_block:
                    self.current_function.entry_block = label
                continue

            # Instruction
            if self.current_function and self.current_block:
                inst = self._parse_instruction(line, line_num)
                if inst:
                    self.current_block.instructions.append(inst)

                    # Track control flow
                    if inst.opcode in ["br", "switch", "ret"]:
                        self._update_control_flow(inst)

    def _parse_function_def(self, line: str) -> None:
        """Parse function definition."""
        # Extract function name: define ... @func_name(...)
        match = re.search(r"@([a-zA-Z0-9_\.]+)\s*\(", line)
        if match:
            func_name = match.group(1)
            self.current_function = Function(name=func_name, basic_blocks={})

            # Extract arguments
            args_match = re.search(r"\((.*?)\)", line)
            if args_match:
                args_str = args_match.group(1)
                # Simple argument parsing (just count for now)
                self.current_function.arguments = [
                    arg.strip() for arg in args_str.split(",") if arg.strip()
                ]

    def _parse_instruction(self, line: str, line_num: int) -> IRInstruction | None:
        """Parse single instruction."""
        # Pattern: %result = opcode operands
        # or: opcode operands (for void instructions)

        result = None
        rest = line

        if "=" in line:
            parts = line.split("=", 1)
            result = parts[0].strip()
            rest = parts[1].strip()

        # Extract opcode
        tokens = rest.split(None, 1)
        if not tokens:
            return None

        opcode = tokens[0]
        operands_str = tokens[1] if len(tokens) > 1 else ""

        # Parse operands (simplified)
        operands = self._parse_operands(operands_str)

        return IRInstruction(
            line_num=line_num, opcode=opcode, operands=operands, result=result, raw_line=line
        )

    def _parse_operands(self, operands_str: str) -> list[str]:
        """Parse instruction operands."""
        # Simple tokenization (can be improved)
        operands = []
        current = ""
        depth = 0

        for char in operands_str:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == "," and depth == 0:
                if current.strip():
                    operands.append(current.strip())
                current = ""
                continue
            current += char

        if current.strip():
            operands.append(current.strip())

        return operands

    def _update_control_flow(self, inst: IRInstruction) -> None:
        """Update CFG based on control flow instruction."""
        if not self.current_block:
            return

        if inst.opcode == "br":
            # Conditional: br i1 %cond, label %true, label %false
            # Unconditional: br label %target
            labels = [
                op.replace("label", "").replace("%", "").strip()
                for op in inst.operands
                if "label" in op
            ]
            self.current_block.successors.extend(labels)

            # Update predecessors
            for label in labels:
                if label in self.current_function.basic_blocks:
                    self.current_function.basic_blocks[label].predecessors.append(
                        self.current_block.label
                    )

        elif inst.opcode == "switch":
            # switch i32 %val, label %default [ ... cases ... ]
            labels = [
                op.replace("label", "").replace("%", "").strip()
                for op in inst.operands
                if "label" in op
            ]
            self.current_block.successors.extend(labels)

    def find_memory_operations(self, func: Function) -> dict[str, list[IRInstruction]]:
        """Find all memory operations (load, store, memset, memcpy, etc.)."""
        mem_ops = {"store": [], "load": [], "memset": [], "memcpy": [], "call": []}

        for bb in func.basic_blocks.values():
            for inst in bb.instructions:
                if inst.opcode == "store":
                    mem_ops["store"].append(inst)
                elif inst.opcode == "load":
                    mem_ops["load"].append(inst)
                elif inst.opcode == "call":
                    # Check for memset/memcpy/zeroize calls
                    call_target = self._extract_call_target(inst)
                    if "memset" in call_target or "llvm.memset" in call_target:
                        mem_ops["memset"].append(inst)
                    elif "memcpy" in call_target or "llvm.memcpy" in call_target:
                        mem_ops["memcpy"].append(inst)
                    elif any(
                        fn in call_target
                        for fn in ["explicit_bzero", "OPENSSL_cleanse", "sodium_memzero", "zeroize"]
                    ):
                        mem_ops["call"].append(inst)

        return mem_ops

    def _extract_call_target(self, inst: IRInstruction) -> str:
        """Extract function name from call instruction."""
        for op in inst.operands:
            if "@" in op:
                match = re.search(r"@([a-zA-Z0-9_\.]+)", op)
                if match:
                    return match.group(1)
        return ""

    def detect_loop_unrolled_wipes(self, func: Function) -> list[dict]:
        """Detect zeroization patterns from loop unrolling."""
        findings = []

        for bb_label, bb in func.basic_blocks.items():
            # Look for patterns like:
            # store i8 0, i8* %ptr.0
            # store i8 0, i8* %ptr.1
            # store i8 0, i8* %ptr.2
            # ... (repeated pattern indicating unrolled loop)

            zero_stores = []
            for inst in bb.instructions:
                # Check if storing 0
                if (
                    inst.opcode == "store"
                    and inst.operands
                    and ("i8 0" in inst.operands[0] or "i32 0" in inst.operands[0])
                ):
                    zero_stores.append(inst)

            # If we have 4+ consecutive zero stores, likely an unrolled wipe loop
            if len(zero_stores) >= 4:
                # Check if addresses are sequential
                addresses = [self._extract_store_address(inst) for inst in zero_stores]
                if self._are_sequential_addresses(addresses):
                    findings.append(
                        {
                            "type": "LOOP_UNROLLED_WIPE",
                            "block": bb_label,
                            "count": len(zero_stores),
                            "first_line": zero_stores[0].line_num,
                            "evidence": (
                                f"Found {len(zero_stores)} consecutive zero stores"
                                " (likely unrolled loop)"
                            ),
                        }
                    )

        return findings

    def _extract_store_address(self, inst: IRInstruction) -> str:
        """Extract address operand from store instruction."""
        # store type value, type* pointer
        if len(inst.operands) >= 2:
            return inst.operands[1]
        return ""

    def _are_sequential_addresses(self, addresses: list[str]) -> bool:
        """Check if addresses look sequential (e.g., %ptr.0, %ptr.1, %ptr.2)."""
        if len(addresses) < 2:
            return False

        # Simple heuristic: check for pattern like %name.0, %name.1, etc.
        base_pattern = re.sub(r"\d+", "", addresses[0])
        return all(re.sub(r"\d+", "", addr) == base_pattern for addr in addresses[1:])

    def detect_volatile_stores(self, func: Function) -> list[IRInstruction]:
        """Find volatile store instructions (cannot be optimized away)."""
        volatile_stores = []

        for bb in func.basic_blocks.values():
            for inst in bb.instructions:
                if inst.opcode == "store" and "volatile" in inst.raw_line:
                    volatile_stores.append(inst)

        return volatile_stores

    def analyze_mem2reg_output(self, func: Function) -> dict:
        """Analyze memory operations in SSA form (after mem2reg pass)."""
        # After mem2reg, local variables are promoted to registers
        # Look for phi nodes and register operations

        phi_nodes = []
        register_ops = []

        for bb in func.basic_blocks.values():
            for inst in bb.instructions:
                if inst.opcode == "phi":
                    phi_nodes.append(inst)
                elif inst.result and inst.result.startswith("%"):
                    register_ops.append(inst)

        return {
            "phi_count": len(phi_nodes),
            "register_ops": len(register_ops),
            "has_mem2reg": len(phi_nodes) > 0,
        }

    def analyze_function(self, func_name: str) -> dict:
        """Perform comprehensive analysis on a function."""
        if func_name not in self.functions:
            return {"error": f"Function {func_name} not found"}

        func = self.functions[func_name]

        # Find memory operations
        mem_ops = self.find_memory_operations(func)

        # Detect patterns
        loop_unrolled = self.detect_loop_unrolled_wipes(func)
        volatile_stores = self.detect_volatile_stores(func)
        mem2reg_info = self.analyze_mem2reg_output(func)

        # Check for wipe presence
        has_wipe = (
            len(mem_ops["memset"]) > 0 or len(mem_ops["call"]) > 0 or len(volatile_stores) > 0
        )

        return {
            "function": func_name,
            "basic_blocks": len(func.basic_blocks),
            "memory_operations": {
                "stores": len(mem_ops["store"]),
                "loads": len(mem_ops["load"]),
                "memset_calls": len(mem_ops["memset"]),
                "secure_wipe_calls": len(mem_ops["call"]),
                "volatile_stores": len(volatile_stores),
            },
            "patterns": {
                "loop_unrolled_wipes": loop_unrolled,
                "has_volatile_stores": len(volatile_stores) > 0,
            },
            "ssa_analysis": mem2reg_info,
            "has_zeroization": has_wipe,
            "wipe_instructions": [
                {"line": inst.line_num, "type": "memset", "raw": inst.raw_line}
                for inst in mem_ops["memset"]
            ]
            + [
                {"line": inst.line_num, "type": "secure_call", "raw": inst.raw_line}
                for inst in mem_ops["call"]
            ]
            + [
                {"line": inst.line_num, "type": "volatile_store", "raw": inst.raw_line}
                for inst in volatile_stores
            ],
        }


def main():
    parser = argparse.ArgumentParser(description="Semantic LLVM IR analyzer")
    parser.add_argument("--ir", required=True, help="LLVM IR file (.ll)")
    parser.add_argument("--function", help="Specific function to analyze (default: all)")
    parser.add_argument("--config", help="Configuration YAML file")
    parser.add_argument("--out", required=True, help="Output JSON file")

    args = parser.parse_args()

    # Load config (simplified)
    config = {}

    # Parse IR
    analyzer = SemanticIRAnalyzer(Path(args.ir), config)
    try:
        analyzer.parse_ir()
    except OSError as e:
        print(f"Error: cannot read IR file {args.ir}: {e}", file=sys.stderr)
        sys.exit(1)

    # Analyze functions
    results = {"ir_file": args.ir, "functions_found": len(analyzer.functions), "analyses": []}

    if args.function:
        # Analyze specific function
        analysis = analyzer.analyze_function(args.function)
        results["analyses"].append(analysis)
    else:
        # Analyze all functions
        for func_name in analyzer.functions:
            analysis = analyzer.analyze_function(func_name)
            results["analyses"].append(analysis)

    # Write output
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"OK: semantic IR analysis written to {args.out}")


if __name__ == "__main__":
    main()
