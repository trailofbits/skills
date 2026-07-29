# Ruby Release Practices

## Supported versions

Ruby releases a minor version yearly and the community supports roughly the
last three. Support those three; going lower buys little and costs CI matrix
time. Declare the floor with `required_ruby_version` in the gemspec.

## Dependencies

Use [Bundler](https://bundler.io/). Configure it to install into a vendor
directory rather than the user's global gem store, and keep that directory
out of git:

```sh
bundle config set --local path vendor/bundle
echo vendor/bundle/ >> .gitignore
```

## Formatting and linting

Use [RuboCop](https://github.com/rubocop/rubocop). The default cops are
reasonable; projects commonly relax the metrics cops (method length,
complexity) in `.rubocop.yml` rather than fighting them. Enforce in CI.

## Publishing to RubyGems

- Publish to [RubyGems.org](https://rubygems.org/).
- Use RubyGems [trusted publishing](https://guides.rubygems.org/trusted-publishing/)
  from GitHub Actions instead of API keys.
- Add the organization's shared account as a gem **co-owner**
  (`gem owner <gem> --add <email>`) so the package survives maintainer
  turnover.
- Set `spec.license` (SPDX identifier) and `spec.metadata` links
  (`source_code_uri`, `changelog_uri`) in the gemspec.
