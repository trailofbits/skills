#!/usr/bin/env python3
"""
SLOC Counter - Logical and Physical Source Lines of Code Counter
Supports Solidity, TypeScript, JavaScript, Python, Rust, and Go
"""

import os
import sys
from collections import defaultdict


def strip_comments(code: str) -> str:
    """Remove line and block comments while preserving string literals."""
    out = []
    i = 0
    n = len(code)
    state = "normal"
    quote = ""
    
    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        
        if state == "normal":
            if ch == "/" and nxt == "/":
                state = "line"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                i += 2
                continue
            if ch in ('"', "'", "`"):
                state = "string"
                quote = ch
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
            continue
            
        if state == "line":
            if ch == "\n":
                out.append("\n")
                state = "normal"
            i += 1
            continue
            
        if state == "block":
            if ch == "\n":
                out.append("\n")
                i += 1
                continue
            if ch == "*" and nxt == "/":
                state = "normal"
                i += 2
                continue
            i += 1
            continue
            
        if state == "string":
            out.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    out.append(code[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if ch == quote:
                state = "normal"
                quote = ""
            i += 1
            continue
            
    return "".join(out)


def logical_sloc(code: str) -> int:
    """Count logical statements for Solidity/TypeScript-like languages."""
    code = strip_comments(code)
    count = 0
    i = 0
    n = len(code)
    token = []
    pending_decl = None
    pending_for = False
    paren_depth = 0
    for_paren_depth = None
    in_string = False
    quote = ""
    
    DECL_KEYWORDS = {
        "contract", "interface", "library", "struct", "enum",
        "function", "constructor", "modifier", "fallback", "receive"
    }
    CONTROL_KEYWORDS = {
        "if", "else", "for", "while", "do", "switch", "case",
        "default", "try", "catch", "assembly", "unchecked"
    }

    def flush_token():
        nonlocal pending_decl, pending_for, count, token
        if not token:
            return
        word = "".join(token)
        if word in DECL_KEYWORDS:
            pending_decl = word
        if word in CONTROL_KEYWORDS:
            count += 1
            if word == "for":
                pending_for = True
        token = []

    while i < n:
        ch = code[i]
        
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                in_string = False
                quote = ""
            i += 1
            continue

        if ch in ('"', "'", "`"):
            flush_token()
            in_string = True
            quote = ch
            i += 1
            continue

        if ch.isalnum() or ch == "_":
            token.append(ch)
            i += 1
            continue

        flush_token()

        if ch == "(":
            paren_depth += 1
            if pending_for:
                for_paren_depth = paren_depth
                pending_for = False
            i += 1
            continue
            
        if ch == ")":
            if for_paren_depth is not None and paren_depth == for_paren_depth:
                for_paren_depth = None
            paren_depth = max(paren_depth - 1, 0)
            i += 1
            continue

        if ch == "{":
            if pending_decl:
                count += 1
                pending_decl = None
            i += 1
            continue

        if ch == ";":
            if for_paren_depth is None or paren_depth < for_paren_depth:
                count += 1
            pending_decl = None
            i += 1
            continue

        i += 1

    flush_token()
    return count


def physical_sloc(code: str) -> int:
    """Count physical non-empty, non-comment lines."""
    stripped = strip_comments(code)
    return sum(1 for line in stripped.splitlines() if line.strip())


def count_sloc(root_dir, include_dirs, extensions, method="logical"):
    """
    Count SLOC for specified directories and file extensions.
    
    Args:
        root_dir: Root directory to scan
        include_dirs: List of subdirectories to include
        extensions: Set of file extensions to count (e.g., {".sol", ".ts"})
        method: "logical" or "physical"
    
    Returns:
        dict: Results with totals and per-folder breakdown
    """
    counter_func = logical_sloc if method == "logical" else physical_sloc
    
    files = []
    for rel in include_dirs:
        base = os.path.join(root_dir, rel)
        if not os.path.exists(base):
            print(f"Warning: Directory not found: {base}", file=sys.stderr)
            continue
            
        for dirpath, _, filenames in os.walk(base):
            for name in filenames:
                ext = os.path.splitext(name)[1]
                if ext in extensions:
                    files.append(os.path.join(dirpath, name))
    
    files = sorted(set(files))
    
    by_folder = defaultdict(int)
    by_folder_files = defaultdict(int)
    by_language = defaultdict(int)
    by_language_files = defaultdict(int)
    
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            continue
            
        sloc = counter_func(text)
        
        # Determine language
        ext = os.path.splitext(path)[1]
        lang_map = {
            ".sol": "solidity",
            ".ts": "typescript",
            ".js": "javascript",
            ".py": "python",
            ".rs": "rust",
            ".go": "go"
        }
        lang = lang_map.get(ext, ext[1:] if ext else "unknown")
        
        # Determine folder (use immediate parent if within included dir)
        rel = os.path.relpath(path, root_dir)
        parts = rel.split(os.sep)
        # If file is directly in an include_dir, use that dir
        # Otherwise, use the subdirectory within the include_dir
        if len(parts) > 1 and parts[0] in include_dirs:
            folder = os.path.join(parts[0], parts[1]) if len(parts) > 2 else parts[0]
        else:
            folder = parts[0]
        
        by_folder[folder] += sloc
        by_folder_files[folder] += 1
        by_language[lang] += sloc
        by_language_files[lang] += 1
    
    total = sum(by_folder.values())
    
    return {
        "total": total,
        "file_count": len(files),
        "method": method,
        "by_folder": dict(by_folder),
        "by_folder_files": dict(by_folder_files),
        "by_language": dict(by_language),
        "by_language_files": dict(by_language_files)
    }


def print_results(results):
    """Pretty-print SLOC results."""
    print(f"\n{'='*60}")
    print(f"SLOC Analysis - {results['method'].upper()} Method")
    print(f"{'='*60}\n")
    
    print(f"Total SLOC: {results['total']:,}")
    print(f"Files Scanned: {results['file_count']}\n")
    
    if results['by_language']:
        print("By Language:")
        print("-" * 40)
        for lang in sorted(results['by_language'], key=results['by_language'].get, reverse=True):
            sloc = results['by_language'][lang]
            files = results['by_language_files'][lang]
            print(f"  {lang:15} {sloc:>8,} SLOC  ({files} files)")
        print()
    
    if results['by_folder']:
        print("By Directory:")
        print("-" * 40)
        for folder in sorted(results['by_folder'], key=results['by_folder'].get, reverse=True):
            sloc = results['by_folder'][folder]
            files = results['by_folder_files'][folder]
            print(f"  {folder:25} {sloc:>8,} SLOC  ({files} files)")
        print()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Count SLOC for codebases")
    parser.add_argument("root", help="Root directory to scan")
    parser.add_argument("-d", "--dirs", nargs="+", default=["contracts", "src", "scripts"],
                        help="Directories to include (default: contracts src scripts)")
    parser.add_argument("-e", "--extensions", nargs="+", default=[".sol", ".ts", ".js"],
                        help="File extensions to count (default: .sol .ts .js)")
    parser.add_argument("-m", "--method", choices=["logical", "physical"], default="logical",
                        help="Counting method (default: logical)")
    
    args = parser.parse_args()
    
    extensions = set(args.extensions)
    results = count_sloc(args.root, args.dirs, extensions, args.method)
    print_results(results)
