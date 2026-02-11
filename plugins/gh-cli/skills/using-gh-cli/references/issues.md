# Issues

The `gh issue` subcommands cover listing, viewing, creating, and managing issues.

## Searching Across Repos

```bash
# Search issues across all repos (not limited to --repo)
gh search issues "memory leak language:rust"

# Search with filters
gh search issues "label:bug state:open" --repo owner/repo
```
