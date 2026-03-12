/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * RBAC policy parsing and hierarchy resolution
 */

#include "ngx_rbac_policy.h"


/* Method name to bitmask mapping */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  mask;
} ngx_rbac_method_map_t;

static ngx_rbac_method_map_t ngx_rbac_methods[] = {
    { ngx_string("GET"),     NGX_RBAC_METHOD_GET },
    { ngx_string("HEAD"),    NGX_RBAC_METHOD_HEAD },
    { ngx_string("POST"),    NGX_RBAC_METHOD_POST },
    { ngx_string("PUT"),     NGX_RBAC_METHOD_PUT },
    { ngx_string("DELETE"),  NGX_RBAC_METHOD_DELETE },
    { ngx_string("PATCH"),   NGX_RBAC_METHOD_PATCH },
    { ngx_string("OPTIONS"), NGX_RBAC_METHOD_OPTIONS },
    { ngx_null_string, 0 }
};


ngx_uint_t
ngx_rbac_policy_parse_methods(ngx_conf_t *cf, ngx_str_t *methods_str)
{
    u_char *p, *start, *end;
    ngx_uint_t mask;
    ngx_str_t method;
    ngx_rbac_method_map_t *m;

    if (methods_str->len == 0) {
        return NGX_RBAC_METHOD_ALL;
    }

    mask = 0;
    start = methods_str->data;
    end = methods_str->data + methods_str->len;

    for (p = start; ; p++) {
        if (p == end || *p == ',') {
            /* trim whitespace */
            while (start < p && *start == ' ') {
                start++;
            }

            method.data = start;
            method.len = p - start;

            while (method.len > 0 && method.data[method.len - 1] == ' ') {
                method.len--;
            }

            if (method.len > 0) {
                for (m = ngx_rbac_methods; m->name.len; m++) {
                    if (method.len == m->name.len
                        && ngx_strncasecmp(method.data, m->name.data,
                                           method.len) == 0)
                    {
                        mask |= m->mask;
                        break;
                    }
                }

                if (m->name.len == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "rbac: unknown HTTP method \"%V\"",
                                       &method);
                    return 0;
                }
            }

            if (p == end) {
                break;
            }

            start = p + 1;
        }
    }

    if (mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "rbac: empty HTTP method list");
        return 0;
    }

    return mask;
}


ngx_int_t
ngx_rbac_policy_parse_path(ngx_conf_t *cf, ngx_str_t *path_str,
    ngx_rbac_rule_t *rule)
{
    u_char *p;

    if (path_str->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "rbac: empty path");
        return NGX_ERROR;
    }

    p = path_str->data;

    /* exact match: =/path */
    if (p[0] == '=') {
        if (path_str->len < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: empty path after \"=\"");
            return NGX_ERROR;
        }

        rule->path_type = NGX_RBAC_PATH_EXACT;
        rule->path.data = p + 1;
        rule->path.len = path_str->len - 1;
        return NGX_OK;
    }

    /* regex match: ~/regex */
    if (p[0] == '~') {
        if (path_str->len < 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: empty pattern after \"~\"");
            return NGX_ERROR;
        }

#if (NGX_PCRE)
        ngx_regex_compile_t rc;
        u_char errstr[NGX_MAX_CONF_ERRSTR];

        rule->path_type = NGX_RBAC_PATH_REGEX;
        rule->path.data = p + 1;
        rule->path.len = path_str->len - 1;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = rule->path;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: regex compile failed: %V", &rc.err);
            return NGX_ERROR;
        }

        rule->regex = rc.regex;
        return NGX_OK;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "rbac: regex path requires PCRE");
        return NGX_ERROR;
#endif
    }

    /* trailing asterisk shorthand: strip '*' and use prefix match */
    if (path_str->len >= 2
        && p[path_str->len - 1] == '*'
        && p[path_str->len - 2] == '/')
    {
        rule->path_type = NGX_RBAC_PATH_PREFIX;
        rule->path.data = p;
        rule->path.len = path_str->len - 1; /* remove trailing '*' */
        return NGX_OK;
    }

    /* prefix match: /path */
    rule->path_type = NGX_RBAC_PATH_PREFIX;
    rule->path.data = p;
    rule->path.len = path_str->len;

    return NGX_OK;
}


ngx_rbac_role_t *
ngx_rbac_policy_find_role(ngx_rbac_policy_t *policy, ngx_str_t *name)
{
    ngx_uint_t i;
    ngx_rbac_role_t *role;

    if (policy->roles == NULL) {
        return NULL;
    }

    role = policy->roles->elts;

    for (i = 0; i < policy->roles->nelts; i++) {
        if (role[i].name.len == name->len
            && ngx_strncmp(role[i].name.data, name->data, name->len) == 0)
        {
            return &role[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_rbac_policy_resolve_hierarchy(ngx_conf_t *cf, ngx_rbac_policy_t *policy)
{
    ngx_uint_t i, n, pass, cur, steps;
    ngx_rbac_role_t *roles, *parent;
    ngx_flag_t changed;
    uint64_t new_mask;

    if (policy->roles == NULL || policy->roles->nelts == 0) {
        return NGX_OK;
    }

    roles = policy->roles->elts;
    n = policy->roles->nelts;

    /*
     * Cycle detection: follow the parent chain from each role.
     * Since each role has at most one parent, a chain longer than
     * n steps means there is a cycle (including self-reference).
     */
    for (i = 0; i < n; i++) {
        cur = i;
        for (steps = 0; steps < n; steps++) {
            if (roles[cur].parent_index == NGX_CONF_UNSET_UINT
                || roles[cur].parent_index >= n)
            {
                break;
            }

            cur = roles[cur].parent_index;
        }

        if (steps == n) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: cycle detected in role hierarchy "
                               "of policy \"%V\" at role \"%V\"",
                               &policy->name, &roles[i].name);
            return NGX_ERROR;
        }
    }

    /* Initialize each role with its own bit */
    for (i = 0; i < n; i++) {
        roles[i].effective_roles = (uint64_t) 1 << roles[i].index;
    }

    /*
     * Propagate parent roles to children.
     * "role admin > editor" means admin inherits editor's permissions.
     * Each pass propagates one level. At most n passes needed.
     */
    for (pass = 0; pass < n; pass++) {
        changed = 0;

        for (i = 0; i < n; i++) {
            if (roles[i].parent_index == NGX_CONF_UNSET_UINT
                || roles[i].parent_index >= n)
            {
                continue;
            }

            parent = &roles[roles[i].parent_index];
            new_mask = roles[i].effective_roles | parent->effective_roles;

            if (new_mask != roles[i].effective_roles) {
                roles[i].effective_roles = new_mask;
                changed = 1;
            }
        }

        if (!changed) {
            break;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_rbac_policy_resolve_rules(ngx_conf_t *cf, ngx_rbac_policy_t *policy)
{
    ngx_uint_t i;
    ngx_rbac_rule_t *rules, *rule;

    if (policy->rules == NULL || policy->rules->nelts == 0) {
        return NGX_OK;
    }

    rules = policy->rules->elts;

    for (i = 0; i < policy->rules->nelts; i++) {
        rule = &rules[i];

        /*
         * role_mask is set during rule parsing and holds only the named
         * role's own bit.  It is intentionally not expanded with hierarchy
         * bits here — hierarchy matching is handled on the user side
         * (see ngx_rbac_roles_to_bitmask).  This function only validates
         * that all masks were resolved to a non-zero value.
         */

        if (rule->role_mask == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: unresolved role in rule \"%V\" "
                               "of policy \"%V\"",
                               &rule->rule_text, &policy->name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
