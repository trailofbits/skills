# Actions

The `gh run` and `gh workflow` subcommands cover listing, viewing, watching, and re-running workflow runs.

## Viewing Failed Logs

```bash
# View only failed step logs (much shorter than --log)
gh run view 12345 --repo owner/repo --log-failed

# View specific job logs
gh run view 12345 --repo owner/repo --job 67890 --log
```

## Downloading Artifacts

```bash
# List artifacts for a run
gh api repos/owner/repo/actions/runs/12345/artifacts \
  --jq '.artifacts[] | {name, id}'

# Download a specific artifact (returns zip)
gh api repos/owner/repo/actions/artifacts/67890/zip > artifact.zip
```

## Triggering Workflows with Inputs

```bash
# Trigger a workflow_dispatch event with inputs
gh workflow run deploy.yml --repo owner/repo -f environment=staging -f version=1.2.3

# Trigger on a specific branch
gh workflow run build.yml --repo owner/repo --ref feature-branch
```
