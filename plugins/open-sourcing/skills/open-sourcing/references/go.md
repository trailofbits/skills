# Go Release Practices

Use the standard `go` toolchain for everything.

## Module setup

- Initialize with the canonical repository path:
  `go mod init github.com/<org>/<project>`. The module path is the import
  path, so set it correctly before anyone depends on the project.
- Set the `go` directive in `go.mod` to the latest stable release for
  greenfield code.

## Project layout

- `cmd/<appname>/main.go` for each binary entry point.
- `internal/` for packages that must not be imported by other modules — use
  it liberally; exporting a package is an API commitment.
- Do not create a `pkg/` directory reflexively; the
  [official module layout guidance](https://go.dev/doc/modules/layout)
  recommends putting importable packages at the repository root unless there
  is a concrete conflict.
- Keep packages focused on a single responsibility, handle every error, and
  reserve `panic` for unrecoverable states. Follow
  [Effective Go](https://go.dev/doc/effective_go) and the
  [Go style guide](https://google.github.io/styleguide/go/).

## Testing, formatting, and linting

- `go test ./...` in CI, with `-race` enabled — the race detector is cheap
  insurance for any code with goroutines.
- `gofmt` (or `go fmt`) before committing; enforce in CI.
- [golangci-lint](https://golangci-lint.run/) with a committed configuration.
- [govulncheck](https://go.dev/blog/vuln) in CI to flag known-vulnerable
  dependencies actually reachable from the code.

## Documentation

Write doc comments for every exported identifier — complete sentences
beginning with the identifier name. [pkg.go.dev](https://pkg.go.dev/) renders
them automatically once the module is public and tagged.

## Publishing and releases

- There is no central upload step: pushing a semver tag (`vX.Y.Z`) to the
  public repository *is* publishing. The module proxy and pkg.go.dev pick it
  up automatically. See [developing modules](https://go.dev/doc/modules/developing).
- Because tags are immutable once fetched through the module proxy, never
  retag; publish a new patch version instead.
- For binaries, use [goreleaser](https://goreleaser.com/) to build
  multi-platform artifacts, generate release notes from commits, and attach
  everything to the GitHub Release on each tag. Consider GitHub
  [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
  for provenance on released binaries.
