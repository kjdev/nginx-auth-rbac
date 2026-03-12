/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_RBAC_VARIABLE_H_INCLUDED_
#define _NGX_RBAC_VARIABLE_H_INCLUDED_

#include "ngx_http_auth_rbac_module.h"

/** Variable handler for $rbac_role: the raw role string from the request. */
ngx_int_t ngx_rbac_variable_role(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/** Variable handler for $rbac_roles: comma-separated resolved role names. */
ngx_int_t ngx_rbac_variable_roles(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/** Variable handler for $rbac_matched_rule: description of the matched rule. */
ngx_int_t ngx_rbac_variable_matched_rule(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/** Variable handler for $rbac_result: "allowed", "denied", or "unauthorized". */
ngx_int_t ngx_rbac_variable_result(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

#endif /* _NGX_RBAC_VARIABLE_H_INCLUDED_ */
