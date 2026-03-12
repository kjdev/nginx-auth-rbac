/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * RBAC nginx variable providers
 */

#include "ngx_rbac_variable.h"


ngx_int_t
ngx_rbac_variable_role(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_rbac_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_rbac_module);
    if (ctx == NULL || ctx->raw_roles.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->raw_roles.data;
    v->len = ctx->raw_roles.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


ngx_int_t
ngx_rbac_variable_roles(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_rbac_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_rbac_module);
    if (ctx == NULL || ctx->expanded_roles.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->expanded_roles.data;
    v->len = ctx->expanded_roles.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


ngx_int_t
ngx_rbac_variable_matched_rule(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_rbac_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_rbac_module);
    if (ctx == NULL || ctx->matched_rule.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->matched_rule.data;
    v->len = ctx->matched_rule.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


ngx_int_t
ngx_rbac_variable_result(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_rbac_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_rbac_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    switch (ctx->result) {

    case NGX_RBAC_RESULT_ALLOWED:
        v->data = (u_char *) "allowed";
        v->len = sizeof("allowed") - 1;
        break;

    case NGX_RBAC_RESULT_DENIED:
        v->data = (u_char *) "denied";
        v->len = sizeof("denied") - 1;
        break;

    case NGX_RBAC_RESULT_UNAUTHORIZED:
        v->data = (u_char *) "unauthorized";
        v->len = sizeof("unauthorized") - 1;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
