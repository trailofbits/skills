#!/usr/bin/env python3
"""
Convert Claude Code skills to Cursor-compatible rules.

This script reads Claude Code plugin skills (SKILL.md files) and converts them
to Cursor-compatible rule files that can be placed in .cursor/rules/.

Usage:
    python convert_to_cursor.py [--output-dir DIR] [--plugin PLUGIN_NAME]
    
Examples:
    # Convert all plugins
    python convert_to_cursor.py
    
    # Convert specific plugin
    python convert_to_cursor.py --plugin constant-time-analysis
    
    # Custom output directory
    python convert_to_cursor.py --output-dir ./my-cursor-rules
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


def parse_yaml_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and body from markdown content."""
    frontmatter = {}
    body = content
    
    if content.startswith('---'):
        parts = content.split('---', 2)
        if len(parts) >= 3:
            yaml_content = parts[1].strip()
            body = parts[2].strip()
            
            # Simple YAML parsing for name and description
            for line in yaml_content.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    frontmatter[key] = value
    
    return frontmatter, body


def read_plugin_json(plugin_dir: Path) -> Optional[dict]:
    """Read plugin.json from a Claude plugin directory."""
    plugin_json_path = plugin_dir / '.claude-plugin' / 'plugin.json'
    if plugin_json_path.exists():
        with open(plugin_json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def find_skill_files(plugin_dir: Path) -> list[Path]:
    """Find all SKILL.md files in a plugin directory."""
    skills_dir = plugin_dir / 'skills'
    if not skills_dir.exists():
        return []
    
    skill_files = []
    for skill_file in skills_dir.rglob('SKILL.md'):
        skill_files.append(skill_file)
    return skill_files


def find_reference_files(skill_dir: Path) -> list[Path]:
    """Find reference/resource files associated with a skill."""
    reference_files = []
    
    # Check common reference directory names
    for ref_dir_name in ['references', 'reference', 'resources', 'workflows']:
        ref_dir = skill_dir / ref_dir_name
        if ref_dir.exists():
            for ref_file in ref_dir.rglob('*.md'):
                reference_files.append(ref_file)
    
    return reference_files


def convert_base_dir_paths(content: str, plugin_name: str) -> str:
    """Convert {baseDir} paths to relative paths for Cursor."""
    # Replace {baseDir} with a note about the plugin location
    content = re.sub(
        r'\{baseDir\}',
        f'plugins/{plugin_name}',
        content
    )
    return content


def get_glob_patterns(skill_name: str, skill_content: str) -> str:
    """Determine appropriate glob patterns based on skill content."""
    content_lower = skill_content.lower()
    
    # Map skill topics to file extensions
    patterns = []
    
    if 'cairo' in content_lower or 'starknet' in content_lower:
        patterns.append('*.cairo')
    if 'solidity' in content_lower or 'ethereum' in content_lower:
        patterns.extend(['*.sol'])
    if 'rust' in content_lower:
        patterns.append('*.rs')
    if 'python' in content_lower:
        patterns.append('*.py')
    if 'javascript' in content_lower or 'typescript' in content_lower:
        patterns.extend(['*.js', '*.ts', '*.jsx', '*.tsx'])
    if 'go' in content_lower or 'golang' in content_lower:
        patterns.append('*.go')
    if any(x in content_lower for x in ['c++', 'cpp', ' c ', 'c code']):
        patterns.extend(['*.c', '*.cpp', '*.h', '*.hpp'])
    if 'java' in content_lower and 'javascript' not in content_lower:
        patterns.append('*.java')
    if 'vyper' in content_lower:
        patterns.append('*.vy')
    if 'solana' in content_lower:
        patterns.append('*.rs')
    if 'move' in content_lower:
        patterns.append('*.move')
    
    # If no specific patterns found, return empty (will use alwaysApply or manual)
    if not patterns:
        return ''
    
    # Remove duplicates and join
    return ', '.join(sorted(set(patterns)))


def generate_cursor_rule(
    skill_name: str,
    skill_content: str,
    plugin_info: Optional[dict],
    reference_contents: list[tuple[str, str]],
    plugin_name: str
) -> str:
    """Generate a Cursor-compatible rule from a Claude skill."""
    frontmatter, body = parse_yaml_frontmatter(skill_content)
    
    # Get description for Cursor frontmatter
    description = frontmatter.get('description', plugin_info.get('description', '') if plugin_info else '')
    if not description:
        description = f"Trail of Bits skill: {skill_name}"
    
    # Escape quotes in description for YAML
    description = description.replace('"', '\\"')
    
    # Determine glob patterns based on content
    globs = get_glob_patterns(skill_name, skill_content)
    
    # Build the Cursor rule with proper frontmatter
    lines = []
    
    # Cursor-specific YAML frontmatter
    lines.append('---')
    lines.append(f'description: "{description}"')
    if globs:
        lines.append(f'globs: "{globs}"')
        lines.append('alwaysApply: false')
    else:
        # For general skills without specific file types, make them agent-requested
        lines.append('alwaysApply: false')
    lines.append('---')
    lines.append('')
    
    # Header with skill name
    lines.append(f"# {skill_name}")
    lines.append("")
    
    # Add plugin attribution
    if plugin_info:
        author = plugin_info.get('author', {})
        author_name = author.get('name', 'Trail of Bits') if isinstance(author, dict) else author
        lines.append(f"*From Trail of Bits Skills - Author: {author_name}*")
        lines.append("")
    
    # Convert {baseDir} paths in the body
    body = convert_base_dir_paths(body, plugin_name)
    
    # Add the main skill content
    lines.append(body)
    
    # Add reference content if available
    if reference_contents:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Additional References")
        lines.append("")
        
        for ref_name, ref_content in reference_contents:
            lines.append(f"### {ref_name}")
            lines.append("")
            # Convert paths in reference content too
            ref_content = convert_base_dir_paths(ref_content, plugin_name)
            lines.append(ref_content)
            lines.append("")
    
    return '\n'.join(lines)


def convert_plugin(plugin_dir: Path, output_dir: Path) -> list[str]:
    """Convert a single Claude plugin to Cursor rules."""
    plugin_info = read_plugin_json(plugin_dir)
    plugin_name = plugin_dir.name
    
    skill_files = find_skill_files(plugin_dir)
    converted_files = []
    
    for skill_file in skill_files:
        skill_dir = skill_file.parent
        skill_name = skill_dir.name
        
        # Read skill content
        with open(skill_file, 'r', encoding='utf-8') as f:
            skill_content = f.read()
        
        # Find and read reference files
        reference_files = find_reference_files(skill_dir)
        reference_contents = []
        
        for ref_file in reference_files:
            ref_name = ref_file.stem.replace('-', ' ').replace('_', ' ').title()
            with open(ref_file, 'r', encoding='utf-8') as f:
                ref_content = f.read()
                # Remove YAML frontmatter from references if present
                _, ref_body = parse_yaml_frontmatter(ref_content)
                reference_contents.append((ref_name, ref_body))
        
        # Generate Cursor rule
        cursor_rule = generate_cursor_rule(
            skill_name=skill_name,
            skill_content=skill_content,
            plugin_info=plugin_info,
            reference_contents=reference_contents,
            plugin_name=plugin_name
        )
        
        # Write to output
        output_file = output_dir / f"{skill_name}.mdc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(cursor_rule)
        
        converted_files.append(str(output_file))
    
    return converted_files


def main():
    parser = argparse.ArgumentParser(
        description='Convert Claude Code skills to Cursor-compatible rules'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help='Output directory for Cursor rules (default: .cursor/rules/)'
    )
    parser.add_argument(
        '--plugin',
        type=str,
        default=None,
        help='Convert only a specific plugin (by name)'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List available plugins without converting'
    )
    
    args = parser.parse_args()
    
    # Find the repository root (where plugins/ directory is)
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    plugins_dir = repo_root / 'plugins'
    
    if not plugins_dir.exists():
        print(f"Error: plugins directory not found at {plugins_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Get list of plugins
    plugin_dirs = [d for d in plugins_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
    
    if args.list:
        print("Available plugins:")
        for plugin_dir in sorted(plugin_dirs):
            plugin_info = read_plugin_json(plugin_dir)
            desc = plugin_info.get('description', 'No description') if plugin_info else 'No description'
            print(f"  {plugin_dir.name}: {desc}")
        return
    
    # Set output directory
    output_dir = args.output_dir or (repo_root / '.cursor' / 'rules')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Filter plugins if specific one requested
    if args.plugin:
        plugin_dirs = [d for d in plugin_dirs if d.name == args.plugin]
        if not plugin_dirs:
            print(f"Error: plugin '{args.plugin}' not found", file=sys.stderr)
            sys.exit(1)
    
    # Convert plugins
    total_converted = []
    for plugin_dir in plugin_dirs:
        print(f"Converting plugin: {plugin_dir.name}")
        converted = convert_plugin(plugin_dir, output_dir)
        total_converted.extend(converted)
        for f in converted:
            print(f"  Created: {f}")
    
    print(f"\nConverted {len(total_converted)} skill(s) to Cursor rules in {output_dir}")
    
    # Create an index file
    index_file = output_dir / 'index.md'
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write("# Trail of Bits Skills for Cursor\n\n")
        f.write("This directory contains Cursor-compatible rules converted from Trail of Bits Claude Code skills.\n\n")
        f.write("## Available Rules\n\n")
        
        for rule_file in sorted(output_dir.glob('*.mdc')):
            rule_name = rule_file.stem.replace('-', ' ').title()
            f.write(f"- [{rule_name}]({rule_file.name})\n")
        
        f.write("\n## Usage\n\n")
        f.write("These rules are automatically loaded by Cursor when this repository is opened.\n")
        f.write("You can also reference specific rules using `@` mentions in your prompts.\n")
    
    print(f"Created index: {index_file}")


if __name__ == '__main__':
    main()
