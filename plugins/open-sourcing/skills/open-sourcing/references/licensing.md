# Choosing and Applying an Open-Source License

A repository is not open source until it has a license. Without one, default
copyright applies and nobody can legally use, modify, or redistribute the code
regardless of it being publicly visible.

## Decision criteria

Choose a license based on the answers to these questions, in order:

1. **Does the organization have a license policy?** Apply it. If an
   organization profile was loaded in Step 1 of the workflow, its policy
   takes precedence over the generic guidance below.
2. **Is this software at all?** Datasets, detection rulesets, documentation,
   and publications are often better served by Creative Commons licenses than
   software licenses.
3. **Would competitors gain a significant advantage by modifying this work
   without contributing changes back?** If yes, a network-copyleft license
   (AGPLv3) protects against service providers privatizing improvements.
4. **Do the project's dependencies constrain the choice?** A project that
   statically links GPL code cannot be released under a permissive license.
   Check dependency licenses before deciding.
5. **What does the ecosystem expect?** Libraries intended for broad adoption
   (especially ones businesses must get legal approval to use) see far more
   uptake under permissive licenses.

## Common choices

| License | Type | Choose when |
|---------|------|-------------|
| [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) | Permissive | Default for libraries and tools; includes an explicit patent grant, which MIT lacks |
| [MIT](https://opensource.org/license/mit) | Permissive | Maximum simplicity; ecosystem convention (e.g., much of npm) |
| [AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html) | Network copyleft | The project offers competitors a significant advantage if modified privately, including as a hosted service |
| [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) | Copyleft | Copyleft desired but the network-use clause is not needed |
| [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) | Share-alike (non-software) | Publications and documentation; allows commercial use with attribution |
| [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) | Non-commercial (non-software) | Rulesets or datasets where commercial use should require a separate agreement |

Avoid novel, custom, or "source-available" licenses (BSL, custom
non-competes) unless legal counsel is driving that decision; they create
adoption friction and are not open source under the
[OSD](https://opensource.org/osd).

## Applying the license

Choosing is half the job. Then:

- **Add a `LICENSE` file** at the repository root containing the full license
  text. For Apache 2.0, fill in the copyright notice; for CC licenses, link
  the legal code and state the license clearly in the README.
- **Set the license in package metadata** using SPDX identifiers so package
  indexes display it correctly:
  - Python: `license = "Apache-2.0"` (SPDX expression, PEP 639) in `pyproject.toml`
  - Rust: `license = "Apache-2.0"` in `Cargo.toml`
  - Ruby: `spec.license = "Apache-2.0"` in the gemspec
  - Node: `"license": "Apache-2.0"` in `package.json`
- **State the license in the README**, typically a short section at the end.
- **Keep all of these consistent.** A `LICENSE` file that says AGPLv3 with
  `pyproject.toml` metadata that says MIT is a real (and common) bug.

## Copyright lines

A copyright line uses the current year only; open-ended ranges
("2020-present") add nothing legally:

```
Copyright (c) 2026 Example Org <opensource@example.org>
```

## Forks and adopted projects

When taking over maintenance of an existing open-source project:

- **Keep the existing license** and add a copyright line for the new
  maintainer below the original:

  ```
  Copyright (c) 2019 John Q. Public <john@example.com>
  Copyright (c) 2026 Example Org <opensource@example.org>
  ```

- **Do not relicense** unless every copyright holder agrees or the original
  license explicitly permits it. Permissively licensed projects may be
  *re-released* under a stronger license for new contributions, but the
  original code remains under its original terms and the original notices
  must be preserved.

When in doubt about any licensing question, consult whoever handles legal or
open-source policy for the organization before publishing.
