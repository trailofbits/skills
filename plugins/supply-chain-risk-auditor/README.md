# Supply Chain Risk Auditor

Generate a report on the supply-chain threat landscape of a project's direct dependencies, considering factors like popularity, number of maintainers, CVE history, and frequency of maintenance. Flag dependencies that have high-risk factors and suggest alternatives if any are available.

**Note:** This skill does NOT scan source code for CVEs or credentials.

**Author:** Spencer Michaels

## When to Use

Use this skill when a client is concerned about supply-chain threats to their application and wants to identify dependencies are at the highest risk of takeover or compromise, with an eye toward replacing them with better-secured alternatives.

## What It Does

This skill enumerates all of the direct dependencies of a target project, then uses the `gh` command line tool to query a variety of information about each dependency, including maintainer identities, commit history, frequency of updates, security contacts, and so on. Based on these factors, it holistically assesses the supply-chain risk presented by each dependency, enumerates the details in a table, and presents a summary report to the user with recommendations for remediation.


## Installation

```
	/plugin install trailofbits/skills/plugins/supply-chain-risk-auditor
```
