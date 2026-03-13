# nginx-auth-rbac Configuration Examples

## Basic RBAC Configuration

Control API access with simple admin/viewer roles:

```nginx
rbac_policy basic {
    role admin;
    role viewer;
    grant admin /api;
    grant viewer /public;
    default deny;
}

server {
    location / {
        auth_rbac basic;
        auth_rbac_role $http_x_user_roles;
        proxy_pass http://backend;
    }
}
```

## Role Hierarchy

A hierarchy of admin > editor > viewer, where higher-level roles inherit all permissions of lower-level roles:

```nginx
rbac_policy cms {
    role viewer;
    role editor > viewer;
    role admin > editor;

    grant viewer /public;
    grant editor /articles;
    grant admin /api;

    default deny;
}
```

The admin role also has access to /articles and /public.

## Method Constraints

Allow editors to only GET/POST articles, while admins have access to all methods:

```nginx
rbac_policy api {
    role viewer;
    role editor > viewer;
    role admin > editor;

    grant viewer on GET /articles;
    grant editor on GET,POST /articles;
    grant admin /api;

    default deny;
}
```

## Path Match Types

```nginx
rbac_policy paths {
    role admin;

    grant admin =/api/status;      # exact match only
    grant admin /api;              # all paths starting with /api
    grant admin /assets/*;         # under /assets/ (prefix match)
    grant admin ~^/api/v[0-9]+/;   # regular expression match

    default deny;
}
```

## Deny-First Rules

Explicitly block specific paths:

```nginx
rbac_policy secure {
    role admin;
    role operator;

    deny * =/admin/danger;         # block a specific path for all roles
    grant admin /admin;
    grant operator /api;

    default deny;
}
```

Deny rules are evaluated before grant rules.

## Domain-Based Access Control

Use `map` to assign roles based on the request hostname, enabling different access levels per domain:

```nginx
map $host $role {
    admin.example.com    admin;
    app.example.com      editor;
    default              viewer;
}

rbac_policy site {
    role viewer;
    role editor > viewer;
    role admin > editor;

    deny * =/admin/danger;
    grant viewer /public;
    grant editor /app;
    grant admin /;

    default deny;
}

server {
    server_name admin.example.com app.example.com www.example.com;

    location / {
        auth_rbac site;
        auth_rbac_role $role;
        proxy_pass http://backend;
    }

    location /public {
        auth_rbac off;
        proxy_pass http://backend;
    }
}
```

- `admin.example.com` — full access to all paths
- `app.example.com` — access to /app and /public
- Other domains — access to /public only

## IP-Based Access Control with geo

Use `geo` to assign roles based on client IP ranges, useful for office/VPN environments:

```nginx
geo $role {
    default         viewer;
    192.168.0.0/16  admin;
    10.0.0.0/8      operator;
}

rbac_policy internal {
    role viewer;
    role operator > viewer;
    role admin > operator;

    grant viewer /status;
    grant operator /api;
    grant admin /;

    default deny;
}

server {
    location / {
        auth_rbac internal;
        auth_rbac_role $role;
        proxy_pass http://backend;
    }
}
```

- Internal network (192.168.0.0/16) — full admin access
- VPN/datacenter (10.0.0.0/8) — API operations
- External — health check endpoint only

## Integration with nginx-oidc

Use as an authorization layer after authentication by nginx-oidc or similar modules:

```nginx
rbac_policy app {
    role viewer;
    role editor > viewer;
    role admin > editor;

    grant viewer /;
    grant editor on GET,POST,PUT /articles;
    grant admin /api;
    deny * =/api/internal;

    default deny;
}

server {
    # Authentication module (e.g., nginx-oidc) sets the role variable
    # e.g., auth_oidc sets $http_x_user_roles

    location / {
        auth_rbac app;
        auth_rbac_role $http_x_user_roles;
        proxy_pass http://backend;
    }

    location /public {
        auth_rbac off;    # bypass RBAC for public paths
        proxy_pass http://backend;
    }
}
```

## Integration with auth_request

Use nginx's `auth_request` module to authenticate via an external service and pass the resulting roles to RBAC:

```nginx
rbac_policy app {
    role viewer;
    role editor > viewer;
    role admin > editor;

    grant viewer /;
    grant editor on GET,POST,PUT /articles;
    grant admin /api;

    default deny;
}

server {
    location / {
        # subrequest-based authentication
        auth_request /auth;
        auth_request_set $roles $upstream_http_x_user_roles;

        # RBAC authorization using roles from auth response
        auth_rbac app;
        auth_rbac_role $roles;
        proxy_pass http://backend;
    }

    location = /auth {
        internal;
        proxy_pass http://auth-server/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }
}
```

The auth server should return roles in the `X-User-Roles` response header (e.g., `admin,editor`).

## JSON Array Roles

When receiving roles as a JSON array from OIDC/JWT:

```nginx
server {
    location / {
        auth_rbac my_policy;
        auth_rbac_role $jwt_claim_roles;    # format: ["admin","editor"]
        auth_rbac_role_separator json;
        proxy_pass http://backend;
    }
}
```

Requires the jansson library.

## Using RBAC Variables

Output RBAC evaluation results to logs or response headers:

```nginx
server {
    location / {
        auth_rbac my_policy;
        auth_rbac_role $http_x_user_roles;

        # forward role information to the backend
        proxy_set_header X-RBAC-Role $rbac_role;
        proxy_set_header X-RBAC-Roles $rbac_roles;
        proxy_set_header X-RBAC-Result $rbac_result;

        proxy_pass http://backend;
    }

    # include RBAC information in access logs
    log_format rbac '$remote_addr - $rbac_role [$time_local] '
                    '"$request" $status $rbac_result '
                    '"$rbac_matched_rule"';
    access_log /var/log/nginx/rbac.log rbac;
}
```

## Custom Error Codes

Customize the status code returned on denial:

```nginx
server {
    location /api {
        auth_rbac my_policy;
        auth_rbac_role $http_x_user_roles;
        auth_rbac_denied 403;        # insufficient permissions
        auth_rbac_unauthorized 401;  # not authenticated
        proxy_pass http://backend;
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
