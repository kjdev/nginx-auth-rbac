# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-09-02

### Changed

- The module now registers its PRECONTENT-phase handler at a fixed priority via the new `nxe-phase` submodule instead of relying on module load order, so its position relative to other dynamic modules sharing the same phase (`auth_gate`, `auth_cedar`, `internal_redirect`, ...) no longer depends on `load_module` ordering in `nginx.conf`

### Dependencies

- Add the `nxe-phase` submodule (shared phase-handler-ordering helper)

## [0.2.1] - 2026-06-04

### Dependencies

- Bump `nxe-json` submodule to 0.5.0 (NUL-terminated stringify buffers, sorted compact serializer, object iteration API, deep copy, and scalar constructors; none consumed by this module yet)

## [0.2.0] - 2026-05-18

### Added

- `NGX_RBAC_JSON` build-time environment variable to control JSON role parsing (`yes` default, `no` disables entirely)

### Changed

- JSON role parsing (`auth_rbac_role_separator json`) now goes through the `nxe-json` submodule's `nxe_json_parse_untrusted()`, which applies depth, array-size, string-length, and object-key-count limits in addition to the previous size cap and duplicate-key rejection. Inputs exceeding these limits fail closed (role value rejected, request denied)
- Default build now requires jansson at link time (previously JSON support was silently disabled when jansson was missing). To build without jansson, set `NGX_RBAC_JSON=no`
- Building from source now requires initializing the `nxe-json` submodule (`git clone --recursive` or `git submodule update --init --recursive`)

## [0.1.0] - 2026-03-24

### Added

- Initial implementation of the RBAC (Role-Based Access Control) module
- Policy-based access control (`rbac_policy` block directive)
- Role definitions with hierarchy support (`role name > parent`)
- grant/deny rules with deny-first evaluation
- Path match types: exact (`=`), prefix, and regex (`~`)
- HTTP method constraints (e.g. `on GET,POST`)
- Role sources: comma-separated and JSON array (`auth_rbac_role_separator json`)
- Custom error codes (`auth_rbac_denied`, `auth_rbac_unauthorized`)
- nginx variables: `$rbac_role`, `$rbac_roles`, `$rbac_result`, `$rbac_matched_rule`
