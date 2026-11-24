# Example request

> Use regression-hunt to review the PR URLs and repository/commit pairs in my change list.
> Write the campaign to a new directory beside my checkout. Use local execution within the
> available CPU/memory limits. Delegate through the host's agent tools. Report confirmed
> regressions, incomplete fixes, latent and pre-existing bugs, and unresolved work
> separately.

Supply PR URLs directly or a text/CSV/JSON list; the orchestrator normalizes them into
`campaign.json`. For a local commit supply its repository path and SHA. For a range or ambiguous
landing supply both baseline and target. No merged-only or organization-authorship filter applies.

To resume:

> Resume the existing campaign. Verify saved evidence, check unfinished agent handles, and
> continue only the work that remains or has become stale.

To rebuild a report without new investigation:

> Use report-regressions on the campaign directory and return the local report paths.
