# Directives and Variables Reference

## Directives

| Directive | Default | Context |
|---|---|---|
| [`rbac_policy`](#rbac_policy) name { ... } | — | http |
| [`auth_rbac`](#auth_rbac) policy_name \| off | — | http, server, location |
| [`auth_rbac_role`](#auth_rbac_role) value | — | http, server, location |
| [`auth_rbac_role_separator`](#auth_rbac_role_separator) separator \| json | `,` | http, server, location |
| [`auth_rbac_denied`](#auth_rbac_denied) code | `403` | http, server, location |
| [`auth_rbac_unauthorized`](#auth_rbac_unauthorized) code | `401` | http, server, location |

### `rbac_policy`

```
Syntax:  rbac_policy name { ... }
Default: —
Context: http
```

Defines a policy block. The following sub-directives are available inside the block:

- `role name;` — defines a role
- `role name > parent;` — defines a role that inherits from a parent role (inherits all permissions of the parent)
- `grant role [on METHOD[,METHOD...]] path;` — defines an access grant rule
- `deny role [on METHOD[,METHOD...]] path;` — defines an access deny rule
- `default allow|deny;` — default action when no rule matches

The wildcard `*` can be used as a role name to match all roles. A maximum of 64 roles are supported.

Path match types:

| Notation | Type | Description |
|----------|------|-------------|
| `=/path` | Exact match | Matches only when the path is an exact match |
| `/path` | Prefix match | Matches when the path starts with the specified prefix (`/path/*` is equivalent) |
| `~regex` | Regex match | Matches using a PCRE regular expression |

Path matching is performed against the URI path component (`r->uri`). Query strings (`?key=value`) are separated by nginx and are not included in the matching target.

Methods: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`

> **Note:** HTTP methods not listed above (e.g., `TRACE`, `CONNECT`) do not match method-constrained rules. With `default allow`, requests using these methods may be implicitly allowed. Using `default deny` is recommended for security.

### `auth_rbac`

```
Syntax:  auth_rbac policy_name | off
Default: —
Context: http, server, location
```

Enables RBAC using the specified policy. Use `off` to disable.

### `auth_rbac_role`

```
Syntax:  auth_rbac_role value
Default: —
Context: http, server, location
```

Specifies the source of the role value. Accepts a compound value including nginx variables (e.g., `$http_x_user_roles`, `$jwt_claim_roles`).

### `auth_rbac_role_separator`

```
Syntax:  auth_rbac_role_separator separator | json
Default: ,
Context: http, server, location
```

The delimiter used to split the role string. When set to `json`, the value is parsed as a JSON array (requires jansson).

### `auth_rbac_denied`

```
Syntax:  auth_rbac_denied code
Default: 403
Context: http, server, location
```

The HTTP status code returned when a role is recognized but access is denied.

### `auth_rbac_unauthorized`

```
Syntax:  auth_rbac_unauthorized code
Default: 401
Context: http, server, location
```

The HTTP status code returned when the role is empty or unrecognized.

## Embedded Variables

| Variable | Description |
|---|---|
| [`$rbac_role`](#rbac_role) | Raw role string from the request |
| [`$rbac_roles`](#rbac_roles) | Comma-separated list of roles after hierarchy expansion |
| [`$rbac_result`](#rbac_result) | RBAC evaluation result (`allowed` / `denied` / `unauthorized`) |
| [`$rbac_matched_rule`](#rbac_matched_rule) | Text representation of the matched rule |

### `$rbac_role`

The raw role string extracted from the request. Returns the value as specified by `auth_rbac_role`.

### `$rbac_roles`

A comma-separated list of roles after role hierarchy expansion. For example, if `admin` inherits `editor > viewer`, this returns `admin,editor,viewer`.

### `$rbac_result`

The RBAC evaluation result. One of the following:

| Value | Description |
|-------|-------------|
| `allowed` | Access granted |
| `denied` | Access denied (role was recognized but lacks permission) |
| `unauthorized` | Not authenticated (role is empty or unrecognized) |

### `$rbac_matched_rule`

A text representation of the matched rule. For example: `grant admin /api`, `deny * =/admin/danger`

## Evaluation Flow

1. The `PRECONTENT_PHASE` handler fires (subrequests are skipped)
2. The value of `auth_rbac_role` is evaluated to obtain the role string
3. The role string is split by the separator (default `,`, or as a JSON array when `json` is set)
4. Each role name is looked up in the policy and converted to an `effective_roles` bitmask
5. All deny rules are checked first — a match results in DENIED
6. All grant rules are checked — a match results in ALLOWED
7. If neither matches, the `default allow|deny` setting is applied

---

## See Also

- [Installation Guide](INSTALL.md) — Build instructions and dependency setup
- [Directive Reference](DIRECTIVES.md) — Full specification of all directives
- [Configuration Examples](EXAMPLES.md) — Example configurations for various use cases
- [Troubleshooting](TROUBLESHOOTING.md) — Common issues and solutions
- [Security Guidelines](SECURITY.md) — Security best practices for production
