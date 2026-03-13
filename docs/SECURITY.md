# Security Guidelines

This document describes security best practices for operators deploying the nginx-auth-rbac module in production environments.

## Recommend default deny

Always explicitly specify **`default deny`** in your policies.

```nginx
rbac_policy api {
    role admin;
    role editor;
    role viewer;

    grant admin  /api/admin;
    grant editor /api/articles;
    grant viewer /api/public;

    default deny;  # always specify explicitly
}
```

`default deny` (whitelist approach) ensures only explicitly granted paths are accessible. When a new endpoint is added, it remains inaccessible until a corresponding grant rule is written, so misconfigurations fail safely.

`default allow` (blacklist approach) requires writing deny rules for every new path without fail — a missing rule immediately becomes a vulnerability. Limit its use to internal tools or phased migration scenarios.

## Understanding deny-first evaluation

This module evaluates deny rules before grant rules. Evaluation order:

1. All deny rules are checked — if any matches, the request is denied immediately
2. All grant rules are checked — if any matches, the request is allowed
3. If neither matches, `default allow|deny` applies

This allows you to grant broad access while reliably carving out exceptions with deny:

```nginx
rbac_policy api {
    role admin;

    grant admin /api;          # admin can access everything under /api
    deny  admin /api/internal; # but /api/internal is always denied

    default deny;
}
```

The position of deny rules (before or after grant) in the policy block does not affect behavior. Deny rules are always evaluated first.

## Role header trust

Variables passed to `auth_rbac_role` **must come from a trusted source**.

HTTP request headers (such as `X-User-Roles`) can be freely set by clients. Using headers directly without going through an authentication module allows attackers to impersonate any role.

**Bad example (using client headers directly)**:

```nginx
# DANGEROUS: client can send X-User-Roles: admin
location /api {
    auth_rbac_role $http_x_user_roles;
    auth_rbac api_policy;
}
```

**Correct example (using variables set by the authentication module)**:

```nginx
# nginx-oidc sets $oidc_claim_roles from the verified token
location /api {
    auth_rbac_role $oidc_claim_roles;
    auth_rbac api_policy;
}
```

To prevent external header override, clear client headers with `proxy_set_header` and forward only authenticated values:

```nginx
server {
    set $user_roles $oidc_claim_roles;

    location /api {
        # Ignore client's X-User-Roles, use only authenticated values
        proxy_set_header X-User-Roles $user_roles;
        auth_rbac_role   $user_roles;
        auth_rbac        api_policy;
        proxy_pass       http://backend;
    }
}
```

## HTTPS required

Role information is transmitted in request headers. Without TLS, third parties on the network path can eavesdrop on or tamper with role information. **Always use HTTPS in production**.

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location /api {
        auth_rbac      api_policy;
        auth_rbac_role $oidc_claim_roles;
        proxy_pass     http://backend;
    }
}

server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

Even on internal networks (intra-cluster communication), TLS protection is recommended for traffic containing role information.

## Principle of least privilege

Grant each role only the minimum paths and methods required for its function.

```nginx
rbac_policy api {
    role admin;
    role editor;
    role viewer;

    # viewer: GET only, limited to public APIs
    grant viewer on GET /api/public;
    grant viewer on GET /api/articles;

    # editor: article CRUD only
    grant editor on GET,POST         /api/articles;
    grant editor on PUT,PATCH,DELETE /api/articles;

    # admin: admin API only
    grant admin /api/admin;

    deny * /api/admin/system;

    default deny;
}
```

Key points:

- Avoid broad grants like `grant role /` targeting the root path
- Omitting methods means all methods (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS) are allowed
- Read-only roles should only be granted `on GET,HEAD`
- Write operations (POST/PUT/PATCH/DELETE) should be explicitly granted only to roles that need them
- When changing role hierarchies, audit the effective permissions including inherited ones

## Wildcard role `*` caution

The wildcard role `*` matches all roles in the policy.

**Appropriate use in deny rules**:

```nginx
# Block everyone regardless of role during maintenance
deny * /api/maintenance;
```

**Security risk in grant rules**:

```nginx
# DANGEROUS: any authenticated user can access this
grant * /api/public;
```

If you need to allow all authenticated users to access a path, define an explicit base role instead of using `*`:

```nginx
rbac_policy app {
    role authenticated;
    role admin > authenticated;

    grant authenticated /public;
    grant admin         /admin;

    default deny;
}
```

## Path matching behavior

This module matches the URI (`$uri`) as provided by the nginx core after standard normalization (percent-decoding, removal of `/../` segments). The module itself does **not** perform additional normalization. Be aware of the following:

- **Double slashes** — `/admin//secret` matches a prefix rule `/admin/` because nginx does not collapse consecutive slashes by default. Use the [`merge_slashes`](https://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes) directive (enabled by default) to collapse them.
- **Trailing slash** — An exact match rule `=/admin` does **not** match `/admin/`. Use prefix match (`/admin`) or define separate rules if both forms must be covered.
- **Prefix boundary** — A prefix rule `/api` matches `/api-v2/users` as well as `/api/users`. To restrict to a subtree, add a trailing slash: `/api/`.

When in doubt, use regex rules (`~`) for fine-grained control, and verify matches with the `$rbac_matched_rule` variable.

## Logging and auditing

Include the module's nginx variables in access logs to maintain an audit trail.

| Variable | Description |
|----------|-------------|
| `$rbac_result` | Evaluation result (`allowed` / `denied` / `unauthorized`) |
| `$rbac_matched_rule` | Matched rule text (e.g., `grant admin /api`) |
| `$rbac_role` | Raw role string from input |
| `$rbac_roles` | Roles after hierarchy expansion (comma-separated) |

**Recommended log configuration**:

```nginx
log_format rbac_audit '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status '
                      'rbac_result=$rbac_result '
                      'rbac_role="$rbac_role" '
                      'rbac_matched="$rbac_matched_rule"';

access_log /var/log/nginx/access.log rbac_audit;
```

Example log output:

```
192.168.1.1 - - [13/Mar/2026:10:00:00 +0900] "GET /api/admin HTTP/1.1" 403 rbac_result=denied rbac_role="viewer" rbac_matched=""
192.168.1.2 - - [13/Mar/2026:10:00:01 +0900] "GET /api/users HTTP/1.1" 200 rbac_result=allowed rbac_role="admin" rbac_matched="grant admin /api"
```

Ship logs to a centralized log management system (Elasticsearch, Splunk, etc.) and set up alerts for repeated `denied` / `unauthorized` results from the same source IP to detect unauthorized access attempts.

## Production recommendations

### Disable debug headers

During development, `$rbac_*` variables may be added as response headers for debugging. **Always remove these in production** — role information in response headers leaks the permission structure to attackers.

```nginx
# Development only — remove in production
# add_header X-RBAC-Result  $rbac_result;
# add_header X-RBAC-Role    $rbac_role;
# add_header X-RBAC-Matched $rbac_matched_rule;
```

### Customize error pages

Default nginx error pages contain server information. Use custom error pages:

```nginx
server_tokens off;

error_page 401 /errors/401.html;
error_page 403 /errors/403.html;

location ^~ /errors/ {
    internal;
    root /usr/share/nginx/html;
}
```

### Unify response codes

Returning different codes for 403 and 401 reveals whether the user is "authenticated but unauthorized" or "unauthenticated." If you prefer not to expose this distinction, unify the codes:

```nginx
location /api {
    auth_rbac              api_policy;
    auth_rbac_role         $oidc_claim_roles;
    auth_rbac_denied       404;  # make it look like the resource doesn't exist
    auth_rbac_unauthorized 404;
    proxy_pass             http://backend;
}
```

### Validate policies before deployment

Policy parsing errors cause nginx to refuse to start or reload. Always validate configuration changes beforehand:

```bash
nginx -t -c /etc/nginx/nginx.conf
```

### Minimal production configuration example

```nginx
http {
    server_tokens off;

    log_format rbac_audit '$remote_addr [$time_local] '
                          '"$request" $status '
                          'rbac=$rbac_result '
                          'role="$rbac_role"';

    rbac_policy api_policy {
        role viewer;
        role editor > viewer;
        role admin  > editor;

        grant viewer on GET       /api/public;
        grant editor on GET,POST  /api/articles;
        grant admin               /api/admin;
        deny * /api/admin/system;

        default deny;
    }

    server {
        listen 443 ssl;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_certificate     /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;

        access_log /var/log/nginx/api_access.log rbac_audit;
        error_page 401 /errors/401.html;
        error_page 403 /errors/403.html;

        location /api {
            auth_rbac      api_policy;
            auth_rbac_role $oidc_claim_roles;
            proxy_pass     http://backend;
        }
    }
}
```

---

## See Also

- [Installation Guide](INSTALL.md) — Build instructions and dependency setup
- [Directive Reference](DIRECTIVES.md) — Full specification of all directives
- [Configuration Examples](EXAMPLES.md) — Example configurations for various use cases
- [Troubleshooting](TROUBLESHOOTING.md) — Common issues and solutions
- [Security Guidelines](SECURITY.md) — Security best practices for production
