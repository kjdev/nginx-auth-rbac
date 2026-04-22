/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * RBAC role extraction from variables
 */

#include "ngx_rbac_role.h"
#include "ngx_rbac_policy.h"

#if (NGX_RBAC_HAVE_JSON)
#include "nxe_json.h"
#endif


#if (NGX_RBAC_HAVE_JSON)
static ngx_array_t *
ngx_rbac_extract_roles_json(ngx_http_request_t *r, ngx_str_t *value)
{
    nxe_json_t *root, *elem;
    ngx_array_t *roles;
    ngx_str_t *role;
    ngx_str_t str;
    size_t i, len;

    /*
     * auth_rbac_role values come from nginx variables populated by
     * authentication modules (JWT claims, upstream headers, etc.).
     * Even signature-verified JWT payloads have attacker-controlled
     * structure, so parse with the DoS-protected variant.
     */
    root = nxe_json_parse_untrusted(value, r->pool);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "rbac: JSON parse failed");
        return NULL;
    }

    if (!nxe_json_is_array(root)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "rbac: JSON role value is not an array");
        nxe_json_free(root);
        return NULL;
    }

    len = nxe_json_array_size(root);
    if (len == 0) {
        nxe_json_free(root);
        return NULL;
    }

    roles = ngx_array_create(r->pool, len, sizeof(ngx_str_t));
    if (roles == NULL) {
        nxe_json_free(root);
        return NULL;
    }

    for (i = 0; i < len; i++) {
        /* borrowed reference; do not free */
        elem = nxe_json_array_get(root, i);

        if (nxe_json_string(elem, &str) != NGX_OK || str.len == 0) {
            continue;
        }

        role = ngx_array_push(roles);
        if (role == NULL) {
            nxe_json_free(root);
            return NULL;
        }

        role->len = str.len;
        role->data = ngx_pnalloc(r->pool, role->len);
        if (role->data == NULL) {
            nxe_json_free(root);
            return NULL;
        }

        ngx_memcpy(role->data, str.data, role->len);
    }

    nxe_json_free(root);

    if (roles->nelts == 0) {
        return NULL;
    }

    return roles;
}
#endif


static ngx_array_t *
ngx_rbac_extract_roles_separator(ngx_http_request_t *r, ngx_str_t *value,
    ngx_str_t *separator)
{
    ngx_array_t *roles;
    ngx_str_t *role;
    u_char *p, *start, *end;
    ngx_uint_t sep_len;

    roles = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (roles == NULL) {
        return NULL;
    }

    sep_len = separator->len;

    if (sep_len == 0) {
        return NULL;
    }

    start = value->data;
    end = value->data + value->len;

    for (p = start; ; p++) {
        ngx_flag_t at_end = (p == end);
        ngx_flag_t at_sep = 0;

        if (!at_end && sep_len > 0 && (ngx_uint_t) (end - p) >= sep_len) {
            if (ngx_strncmp(p, separator->data, sep_len) == 0) {
                at_sep = 1;
            }
        }

        if (at_end || at_sep) {
            u_char *trimmed_end;

            /* trim leading whitespace */
            while (start < p && (*start == ' ' || *start == '\t')) {
                start++;
            }

            /* trim trailing whitespace */
            trimmed_end = p;
            while (trimmed_end > start
                   && (*(trimmed_end - 1) == ' '
                       || *(trimmed_end - 1) == '\t'))
            {
                trimmed_end--;
            }

            if (trimmed_end > start) {
                role = ngx_array_push(roles);
                if (role == NULL) {
                    return NULL;
                }

                role->data = start;
                role->len = trimmed_end - start;
            }

            if (at_end) {
                break;
            }

            p += sep_len - 1; /* -1 because loop increments */
            start = p + 1;
        }
    }

    if (roles->nelts == 0) {
        return NULL;
    }

    return roles;
}


ngx_array_t *
ngx_rbac_extract_roles(ngx_http_request_t *r, ngx_str_t *value,
    ngx_str_t *separator)
{
    if (value->len == 0) {
        return NULL;
    }

#if (NGX_RBAC_HAVE_JSON)
    if (separator->len == 4
        && ngx_strncmp(separator->data, "json", 4) == 0)
    {
        return ngx_rbac_extract_roles_json(r, value);
    }
#endif

    return ngx_rbac_extract_roles_separator(r, value, separator);
}


uint64_t
ngx_rbac_roles_to_bitmask(ngx_rbac_policy_t *policy,
    ngx_array_t *role_names, ngx_http_request_t *r)
{
    ngx_uint_t i;
    ngx_str_t *names;
    ngx_rbac_role_t *role;
    uint64_t mask;

    if (role_names == NULL) {
        return 0;
    }

    mask = 0;
    names = role_names->elts;

    for (i = 0; i < role_names->nelts; i++) {
        role = ngx_rbac_policy_find_role(policy, &names[i]);
        if (role == NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "rbac: unknown role \"%V\" ignored", &names[i]);
            continue;
        }

        mask |= role->effective_roles;
    }

    return mask;
}
