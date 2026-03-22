# Changelog

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
