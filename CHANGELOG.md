# Changelog

## [a2a0c65](../../commit/a2a0c65) - 2026-04-22

### Added

- `NGX_RBAC_JSON` build-time environment variable to control JSON role parsing (`yes` default, `no` disables entirely)

### Changed

- Default build now requires jansson at link time (previously JSON support was silently disabled when jansson was missing). To build without jansson, set `NGX_RBAC_JSON=no`

## [87b4812](../../commit/87b4812) - 2026-04-22

### Changed

- Replace direct `jansson` calls in JSON role parsing (`auth_rbac_role_separator json`) with the `nxe_json` API from the `nxe-json` submodule. Parsing now goes through `nxe_json_parse_untrusted()`, which applies depth, array-size, string-length, and object-key-count limits in addition to the previous size cap and duplicate-key rejection. Inputs exceeding these limits fail closed (role value rejected, request denied)
- Rename build-time feature flag `NGX_RBAC_HAVE_JANSSON` to `NGX_RBAC_HAVE_JSON`

## [edbe198](../../commit/edbe198) - 2026-04-22

### Added

- Add `nxe-json` 0.1.0 submodule under `nxe-json/` (jansson wrapper with built-in size, depth, array, string, and key-count limits)

### Changed

- Building from source now requires initializing the submodule (`git clone --recursive` or `git submodule update --init --recursive`)

## [b48c50b](../../commit/b48c50b) - 2026-03-24

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
