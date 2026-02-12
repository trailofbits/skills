# Pull Requests

## Reading PR Comments via API

The `gh pr` subcommands cover listing, viewing, creating, reviewing, and merging PRs.
For reading PR comments, use the API directly:

```bash
# List review comments (on the diff)
gh api repos/owner/repo/pulls/123/comments --jq '.[].body'

# List issue-style comments (on the conversation)
gh api repos/owner/repo/issues/123/comments --jq '.[].body'
```
