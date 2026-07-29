# JavaScript/TypeScript Release Practices

## Supported versions

Support the active and maintenance Node.js LTS lines, and declare the floor
in `engines.node`. Dropping an EOL Node version is routine maintenance.

## Package metadata

- Set `license` (SPDX identifier), `repository`, and `engines` in
  `package.json`; registries and tooling surface these directly.
- Commit the lockfile (`package-lock.json`, `pnpm-lock.yaml`, or
  `yarn.lock`) so fresh clones build reproducibly.
- Publish under an npm **organization scope** (`@org/package`) rather than
  a personal account so ownership survives maintainer turnover.

## Formatting, linting, and type checking

Keep an existing ESLint + Prettier or Biome setup; if none exists, add
Biome (a single tool) or ESLint + Prettier, and enforce them in CI. For
TypeScript, run `tsc --noEmit` in CI even when a bundler performs the
builds — bundlers typically skip type checking.

## Documentation

[TypeDoc](https://typedoc.org/) generates API documentation from TypeScript
sources; publish it to GitHub Pages from CI and link it from the README.

## Publishing to npm

- Use npm [trusted publishing](https://docs.npmjs.com/trusted-publishers/)
  (OIDC from GitHub Actions or GitLab CI, generally available since July
  2025) instead of long-lived tokens.
- Under trusted publishing, the npm CLI publishes **provenance attestations
  by default** — no `--provenance` flag needed.
- Run `npm audit` (or the equivalent for pnpm/yarn) in CI to flag
  dependencies with known advisories.
