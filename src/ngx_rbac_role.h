/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_RBAC_ROLE_H_INCLUDED_
#define _NGX_RBAC_ROLE_H_INCLUDED_

#include "ngx_http_auth_rbac_module.h"

/**
 * Split a role string into an array of role name strings.
 * Use separator "json" to parse a JSON array; otherwise split on the
 * separator character(s).
 */
ngx_array_t *ngx_rbac_extract_roles(ngx_http_request_t *r, ngx_str_t *value,
    ngx_str_t *separator);

/** Convert an array of role name strings to a combined effective bitmask. */
uint64_t ngx_rbac_roles_to_bitmask(ngx_rbac_policy_t *policy,
    ngx_array_t *role_names, ngx_http_request_t *r);

#endif /* _NGX_RBAC_ROLE_H_INCLUDED_ */
