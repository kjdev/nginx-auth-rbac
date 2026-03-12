/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_RBAC_MATCHER_H_INCLUDED_
#define _NGX_RBAC_MATCHER_H_INCLUDED_

#include "ngx_http_auth_rbac_module.h"

/** Match the request URI against the path pattern in a rule. */
ngx_int_t ngx_rbac_match_path(ngx_http_request_t *r, ngx_rbac_rule_t *rule);

/** Return the bitmask bit corresponding to the request's HTTP method. */
ngx_uint_t ngx_rbac_request_method_bit(ngx_http_request_t *r);

/**
 * Evaluate all policy rules against the request and user roles.
 * Deny rules are checked first; returns NGX_RBAC_RESULT_DENIED,
 * NGX_RBAC_RESULT_ALLOWED, or the policy default when no rule matches.
 */
ngx_uint_t ngx_rbac_evaluate(ngx_http_request_t *r,
    ngx_rbac_policy_t *policy, uint64_t user_roles,
    ngx_http_auth_rbac_ctx_t *ctx);

#endif /* _NGX_RBAC_MATCHER_H_INCLUDED_ */
