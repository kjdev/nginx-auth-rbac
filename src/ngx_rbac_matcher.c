/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * RBAC path/method/role matching engine
 */

#include "ngx_rbac_matcher.h"


ngx_int_t
ngx_rbac_match_path(ngx_http_request_t *r, ngx_rbac_rule_t *rule)
{
    switch (rule->path_type) {

    case NGX_RBAC_PATH_EXACT:
        if (r->uri.len == rule->path.len
            && ngx_strncmp(r->uri.data, rule->path.data, r->uri.len) == 0)
        {
            return NGX_OK;
        }
        break;

    case NGX_RBAC_PATH_PREFIX:
        if (r->uri.len >= rule->path.len
            && ngx_strncmp(r->uri.data, rule->path.data, rule->path.len) == 0)
        {
            return NGX_OK;
        }
        break;

#if (NGX_PCRE)
    case NGX_RBAC_PATH_REGEX:
        if (rule->regex) {
            ngx_int_t n;

            n = ngx_regex_exec(rule->regex, &r->uri, NULL, 0);
            if (n >= 0) {
                return NGX_OK;
            }
            if (n == NGX_REGEX_NO_MATCHED) {
                break;
            }

            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "rbac: regex exec failed: %i", n);
        }
        break;
#endif

    default:
        break;
    }

    return NGX_DECLINED;
}


ngx_uint_t
ngx_rbac_request_method_bit(ngx_http_request_t *r)
{
    switch (r->method) {

    case NGX_HTTP_GET:
        return NGX_RBAC_METHOD_GET;

    case NGX_HTTP_HEAD:
        return NGX_RBAC_METHOD_HEAD;

    case NGX_HTTP_POST:
        return NGX_RBAC_METHOD_POST;

    case NGX_HTTP_PUT:
        return NGX_RBAC_METHOD_PUT;

    case NGX_HTTP_DELETE:
        return NGX_RBAC_METHOD_DELETE;

    case NGX_HTTP_PATCH:
        return NGX_RBAC_METHOD_PATCH;

    case NGX_HTTP_OPTIONS:
        return NGX_RBAC_METHOD_OPTIONS;

    default:
        return 0;
    }
}


static ngx_int_t
ngx_rbac_match_rule(ngx_http_request_t *r, ngx_rbac_rule_t *rule,
    uint64_t user_roles)
{
    ngx_uint_t method_bit;

    /* Check role match */
    if (rule->role_mask != NGX_RBAC_ROLE_WILDCARD
        && (rule->role_mask & user_roles) == 0)
    {
        return NGX_DECLINED;
    }

    /*
     * Check method match.
     * Unknown methods (TRACE, CONNECT, etc.) return method_bit=0 and
     * only match rules with NGX_RBAC_METHOD_ALL (no "on" clause).
     */
    method_bit = ngx_rbac_request_method_bit(r);
    if (rule->methods != NGX_RBAC_METHOD_ALL) {
        if (method_bit == 0 || !(rule->methods & method_bit)) {
            return NGX_DECLINED;
        }
    }

    /* Check path match */
    return ngx_rbac_match_path(r, rule);
}


ngx_uint_t
ngx_rbac_evaluate(ngx_http_request_t *r, ngx_rbac_policy_t *policy,
    uint64_t user_roles, ngx_http_auth_rbac_ctx_t *ctx)
{
    ngx_uint_t i;
    ngx_rbac_rule_t *rules, *rule;

    if (policy->rules == NULL || policy->rules->nelts == 0) {
        ctx->result = policy->default_allow
                      ? NGX_RBAC_RESULT_ALLOWED : NGX_RBAC_RESULT_DENIED;
        return ctx->result;
    }

    rules = policy->rules->elts;

    /* Phase 1: check all deny rules first */
    for (i = 0; i < policy->rules->nelts; i++) {
        rule = &rules[i];

        if (!rule->is_deny) {
            continue;
        }

        if (ngx_rbac_match_rule(r, rule, user_roles) == NGX_OK) {
            ctx->result = NGX_RBAC_RESULT_DENIED;
            ctx->matched_rule = rule->rule_text;
            return NGX_RBAC_RESULT_DENIED;
        }
    }

    /* Phase 2: check all grant rules */
    for (i = 0; i < policy->rules->nelts; i++) {
        rule = &rules[i];

        if (rule->is_deny) {
            continue;
        }

        if (ngx_rbac_match_rule(r, rule, user_roles) == NGX_OK) {
            ctx->result = NGX_RBAC_RESULT_ALLOWED;
            ctx->matched_rule = rule->rule_text;
            return NGX_RBAC_RESULT_ALLOWED;
        }
    }

    /* No rule matched: use default */
    ctx->result = policy->default_allow
                  ? NGX_RBAC_RESULT_ALLOWED : NGX_RBAC_RESULT_DENIED;

    return ctx->result;
}
