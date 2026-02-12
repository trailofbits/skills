# API

The `gh api` command provides direct access to any GitHub REST or GraphQL endpoint with automatic authentication.

## Filtering with `--jq`

```bash
# Extract specific fields
gh api repos/owner/repo --jq '.stargazers_count'

# Complex filtering
gh api repos/owner/repo/pulls \
  --jq '.[] | select(.user.login == "username") | {number, title}'

# Tab-separated output for scripting
gh api repos/owner/repo/pulls \
  --jq '.[] | [.number, .title, .user.login] | @tsv'
```

## Pagination

```bash
# Auto-paginate all results
gh api repos/owner/repo/issues --paginate --jq '.[].title'

# Limit per-page (useful to avoid huge responses)
gh api 'repos/owner/repo/issues?per_page=10' --jq '.[].title'
```

## Headers

```bash
# Raw file content (skip base64 encoding)
gh api repos/owner/repo/contents/file.md \
  -H "Accept: application/vnd.github.raw+json"

# Check rate limit
gh api rate_limit --jq '.rate'
```

## GraphQL

```bash
# Simple query
gh api graphql -f query='
  query {
    repository(owner: "owner", name: "repo") {
      stargazerCount
      description
    }
  }
'

# With variables
gh api graphql -f query='
  query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      issues(first: 10, states: OPEN) {
        nodes { number title }
      }
    }
  }
' -f owner="owner" -f name="repo"

# Filter GraphQL response
gh api graphql -f query='...' --jq '.data.repository.issues.nodes[].title'
```
