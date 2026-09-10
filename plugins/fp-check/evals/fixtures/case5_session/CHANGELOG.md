# Changelog

Notable changes to the session service. Dates are release dates.

## [1.4.1] - 2026-05-02

### Fixed

- Session tokens are reduced to a keyed digest before the store compares them,
  so the comparison no longer runs over the stored value itself (#412).

## [1.4.0] - 2026-04-11

### Added

- In-memory session store with per-record expiry and idle timeout (#397).
- `sign_out` clears the session server-side rather than only expiring the
  cookie (#401).
