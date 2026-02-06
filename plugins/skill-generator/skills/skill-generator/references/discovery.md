# Discovery Methodology

How to analyze any documentation source and identify skill candidates.

## Overview

Discovery transforms unstructured documentation into a structured list of skill candidates with types, relationships, and content boundaries. The goal is a generation plan the user can approve.

## Phase 0: Locate and Access Source

### Source Types

| Source Type | Access Method | Content Extraction |
|-------------|--------------|-------------------|
| Local directory | Glob for `**/*.md`, `**/*.rst`, `**/*.txt` | Read files directly |
| Git repository | Clone (shallow) or find locally | Scan directory tree |
| Website / docs | WebFetch navigation page, then key pages | Extract from HTML-to-markdown |
| PDF files | Read with PDF tool (page ranges for large PDFs) | Extract by heading structure |
| Single file | Read directly | Parse sections by headings |

### For Git Repositories

```bash
# Shallow clone if remote
git clone --depth=1 {url}

# Common documentation locations
{repo}/docs/
{repo}/documentation/
{repo}/content/
{repo}/wiki/
{repo}/README.md + linked files
```

### For Websites

1. WebFetch the landing/index page
2. Extract navigation structure (sidebar, table of contents)
3. Identify distinct topic pages
4. WebFetch each topic page (limit: 10-15 pages per batch)

### For PDFs

1. Read first 2-3 pages to understand structure
2. Extract table of contents if present
3. Read section by section using page ranges

## Phase 1: Content Analysis

### Step 1: Scan for Topics

Identify distinct topics by looking for:

| Signal | Indicates |
|--------|-----------|
| Top-level directories with markdown files | Major topics |
| H1 or H2 headings in long documents | Subtopics within a document |
| Separate pages on a docs site | Individual topics |
| Named sections in a PDF | Chapter-level topics |
| README files in subdirectories | Self-contained modules |

### Step 2: Extract Metadata Per Topic

For each candidate topic, extract:

```yaml
- name: "{topic-name-kebab-case}"
  title: "{Human Readable Title}"
  source_path: "{path/to/content}"
  estimated_lines: {approximate content length}
  has_code_examples: {true/false}
  has_cli_commands: {true/false}
  has_install_steps: {true/false}
  related_topics: ["{other-topic-1}", "{other-topic-2}"]
```

### Step 3: Classify Skill Type

Apply these rules in order (first match wins):

```
Is this about a specific CLI tool or software?
├─ Has installation steps, CLI commands, config files?
│  └─ TYPE: tool
│
├─ Is this about finding vulnerabilities or security issues?
│  Has severity classifications, threat models, attack patterns?
│  └─ TYPE: audit
│
├─ Is this a methodology that applies across multiple tools?
│  Describes steps, patterns, or techniques independent of one tool?
│  └─ TYPE: technique
│
├─ Is this behavioral guidance, best practices, or decision rules?
│  Tells Claude HOW to think or WHEN to act, not just what to do?
│  └─ TYPE: guidance
│
└─ None of the above match clearly?
   └─ FLAG for user decision in the plan
```

### Step 4: Map Relationships

Identify connections between topics:

| Relationship Type | Detection Method | Example |
|------------------|-----------------|---------|
| Explicit reference | Topic A links to or mentions topic B | "See the coverage analysis section" |
| Tool → technique | Tool uses a technique described elsewhere | AFL++ → harness writing |
| Technique → tool | Technique has tool-specific sections | Coverage → libFuzzer, AFL++ |
| Shared domain | Topics cover the same domain area | All crypto-related topics |
| Prerequisite | Topic A must be understood before topic B | Installation → Usage |

### Step 5: Filter Candidates

Remove topics that shouldn't become skills:

| Exclusion Criteria | Reason |
|-------------------|--------|
| Content < 50 lines after extraction | Insufficient substance for a standalone skill |
| Pure reference table with no guidance | Better as a references/ file within another skill |
| Changelog, release notes, contribution guide | Meta-documentation, not actionable guidance |
| Duplicate of content in another topic | Merge into the primary topic |
| GUI-only tool that Claude cannot operate | Claude cannot interact with graphical interfaces |
| Content is behind authentication/paywall | Cannot extract content |

## Phase 2: Build Generation Plan

### Plan Format

```markdown
# Skill Generation Plan

## Summary
- **Source:** {description of source}
- **Total topics scanned:** {count}
- **Skills to generate:** {count}
- **Skipped:** {count}

## Skills to Generate

| # | Skill Name | Type | Source | Related Skills |
|---|------------|------|--------|---------------|
| 1 | {name} | tool | {source section} | {related names} |
| 2 | {name} | technique | {source section} | {related names} |

## Skipped Topics

| Topic | Reason |
|-------|--------|
| {name} | {specific reason} |

## Plugin Structure

Generated files will be written to:
{output_path}/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   ├── {skill-1}/SKILL.md
│   └── {skill-2}/SKILL.md
└── README.md
```

### Present and Wait

**Always present the plan and wait for explicit user approval.**

Acceptable user modifications:
- Remove skills from the plan
- Change skill types
- Rename skills
- Add topics not detected
- Merge related topics into one skill
- Split a large topic into multiple skills

## Edge Cases

| Situation | Handling |
|-----------|---------|
| Source has no clear structure | Ask user to identify key topics manually |
| Single large document | Split by H2 headings into separate skills |
| Mixed content types | Classify each section independently |
| Content references external sources | WebFetch critical references, note others |
| Source is in a non-English language | Generate skill in the source language, note in plan |
| Content is outdated | Note in plan, proceed if user approves |
| Overlapping topics | Present as options — merge or separate? |
