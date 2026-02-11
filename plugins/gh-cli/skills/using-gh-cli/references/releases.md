# Releases

The `gh release` subcommands cover listing, viewing, creating, downloading, and managing releases.

## Downloading Specific Assets

```bash
# Download specific asset by name pattern
gh release download v1.2.3 --repo owner/repo --pattern "*.tar.gz"

# Download source code archive (not just uploaded assets)
gh release download v1.2.3 --repo owner/repo --archive tar.gz

# Download to a specific directory
gh release download v1.2.3 --repo owner/repo --dir ./downloads
```

## Getting Latest Release Tag via API

```bash
# Useful when gh release view output is too verbose
gh api repos/owner/repo/releases/latest --jq '.tag_name'
```
