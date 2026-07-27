# Python Release Practices

For project scaffolding, dependency management (uv), formatting/linting
(ruff), and type checking (ty), use the **modern-python skill** from this
marketplace — do not duplicate its guidance. If that skill is not installed,
apply the toolchain directly with standard configurations: uv for
dependencies and builds, `ruff format`/`ruff check` for style, ty for type
checking (note: ty is pre-1.0 with breaking changes between releases — pin
a version rather than an open floor), pytest for tests.

Per the tooling principle in SKILL.md Step 6: leave an existing working
toolchain in place, warning the maintainer about the current equivalents
(black → `ruff format`, mypy → ty, pre-commit → prek); adopt the modern
tools only for categories the project lacks entirely.

This file covers only what the modern-python skill does not:
supported-version policy, documentation, and publishing.

## Supported Python versions

- Greenfield projects: target the latest stable Python.
- If broader compatibility is needed, use the **N-3 rule**: support no more
  than three minor versions behind current (e.g., with 3.14 current, the
  floor is 3.11). Declare the floor with `requires-python` in
  `pyproject.toml` and test the full range in CI.

## Documentation

- **API docs:** [pdoc](https://github.com/mitmproxy/pdoc) — note *pdoc*, not
  *pdoc3*, which is a hostile fork.
- **Full documentation sites:** [Sphinx](https://www.sphinx-doc.org/) with the
  [furo](https://github.com/pradyunsg/furo) theme, or
  [MkDocs with Material](https://squidfunk.github.io/mkdocs-material/).
- Deploy to GitHub Pages from CI
  ([actions/deploy-pages](https://github.com/actions/deploy-pages) or
  [actions-gh-pages](https://github.com/peaceiris/actions-gh-pages)) and link
  the site from the README and the repository's website field.

## Packaging

`pyproject.toml` is the only packaging file needed unless building native
CPython extensions (`setup.py` for C, maturin/`Cargo.toml` for Rust). Build
distributions with `uv build`.

## Publishing to PyPI

Use [trusted publishing](https://docs.pypi.org/trusted-publishers/) — an OIDC
trust relationship between PyPI and the GitHub Actions workflow — instead of
API tokens. Configure it on PyPI under the project's publishing settings,
restricted to a dedicated `pypi` environment in the repository.

Example release workflow. Actions are pinned to full commit SHAs per the CI
hardening notes in SKILL.md; the SHAs below correspond to the tags in the
trailing comments and will drift — resolve current ones before use, and let
Dependabot keep them updated:

```yaml
name: release

on:
  release:
    types: [published]

permissions: {}

jobs:
  build:
    name: Build distributions
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0

      - name: Build distributions
        run: uv build

      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: distributions
          path: dist/

  provenance:
    name: Generate SLSA provenance
    runs-on: ubuntu-latest
    needs: [build]
    permissions:
      id-token: write
      attestations: write
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: distributions
          path: dist/

      - uses: actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1
        with:
          subject-path: dist/*

  publish:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    needs: [build, provenance]
    environment:
      name: pypi
    permissions:
      id-token: write  # required for trusted publishing and attestations
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: distributions
          path: dist/

      - uses: pypa/gh-action-pypi-publish@ba38be9e461d3875417946c167d0b5f3d385a247 # v1.14.1
        with:
          attestations: true
```

`attestations: true` generates [PEP 740](https://peps.python.org/pep-0740/)
publish attestations — the default since gh-action-pypi-publish v1.11, kept
explicit here for clarity — and the provenance job attaches
[SLSA build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
to the built distributions.

## Quality extras worth adding before release

- Property-based tests with
  [Hypothesis](https://hypothesis.readthedocs.io/) for parsing- or
  algorithm-heavy code (see the property-based-testing skill in this
  marketplace).
- Docstring coverage enforcement with
  [interrogate](https://interrogate.readthedocs.io/) or ruff's `D` rules so
  public APIs stay documented as the project grows.
- Dependency auditing in CI with `uv audit` (currently in preview) or
  [pip-audit](https://github.com/pypa/pip-audit).
