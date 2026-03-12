/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_HTTP_AUTH_RBAC_MODULE_H_INCLUDED_
#define _NGX_HTTP_AUTH_RBAC_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/** @name HTTP method bitmask flags
 *  @{ */
#define NGX_RBAC_METHOD_GET     0x0001  /**< GET method */
#define NGX_RBAC_METHOD_HEAD    0x0002  /**< HEAD method */
#define NGX_RBAC_METHOD_POST    0x0004  /**< POST method */
#define NGX_RBAC_METHOD_PUT     0x0008  /**< PUT method */
#define NGX_RBAC_METHOD_DELETE  0x0010  /**< DELETE method */
#define NGX_RBAC_METHOD_PATCH   0x0020  /**< PATCH method */
#define NGX_RBAC_METHOD_OPTIONS 0x0040  /**< OPTIONS method */
#define NGX_RBAC_METHOD_ALL     0x007F  /**< All methods combined */
/** @} */

/** @name Path match type constants
 *  @{ */
#define NGX_RBAC_PATH_EXACT     0  /**< Exact match: =/path */
#define NGX_RBAC_PATH_PREFIX    1  /**< Prefix match: /path or /path/ */
#define NGX_RBAC_PATH_REGEX     2  /**< Regex match: ~/regex */
/** @} */

/** @name Evaluation result codes
 *  @{ */
#define NGX_RBAC_RESULT_ALLOWED      0  /**< Access granted */
#define NGX_RBAC_RESULT_DENIED       1  /**< Access denied (role matched deny rule) */
#define NGX_RBAC_RESULT_UNAUTHORIZED 2  /**< No role present; authentication required */
/** @} */

/** Maximum number of roles per policy (fits in a uint64_t bitmask). */
#define NGX_RBAC_MAX_ROLES  64

#if NGX_RBAC_MAX_ROLES > 64
#error "NGX_RBAC_MAX_ROLES exceeds uint64_t bitmask capacity"
#endif

/** Wildcard role bitmask: matches any role. */
#define NGX_RBAC_ROLE_WILDCARD  UINT64_MAX


/** Role definition within a policy. */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  index;            /**< Bit position in bitmask (0-63) */
    ngx_uint_t  parent_index;     /**< Parent role index; NGX_CONF_UNSET_UINT if none */
    uint64_t    effective_roles;  /**< Bitmask including self and all inherited roles */
} ngx_rbac_role_t;

/** A single grant or deny rule within a policy. */
typedef struct {
    unsigned     is_deny:1;
    uint64_t     role_mask;      /**< Target role bitmask */
    ngx_uint_t   methods;        /**< Applicable HTTP method bitmask */
    ngx_uint_t   path_type;      /**< One of NGX_RBAC_PATH_* constants */
    ngx_str_t    path;           /**< Path match pattern */
#if (NGX_PCRE)
    ngx_regex_t *regex;          /**< Compiled regex for NGX_RBAC_PATH_REGEX */
#endif
    ngx_str_t    rule_text;      /**< Original rule string (used by $rbac_matched_rule) */
} ngx_rbac_rule_t;

/** Named RBAC policy containing roles and rules. */
typedef struct {
    ngx_str_t    name;
    ngx_array_t *roles;          /**< Array of ngx_rbac_role_t */
    ngx_array_t *rules;          /**< Array of ngx_rbac_rule_t */
    ngx_uint_t   n_roles;        /**< Number of roles defined */
    unsigned     default_allow:1; /**< Default verdict when no rule matches */
} ngx_rbac_policy_t;

/** Module main configuration (http block scope). */
typedef struct {
    ngx_array_t *policies;       /**< Array of ngx_rbac_policy_t */
} ngx_http_auth_rbac_main_conf_t;

/** Module location configuration (server/location block scope). */
typedef struct {
    ngx_rbac_policy_t        *policy;
    ngx_str_t                 policy_name;       /**< Policy name before resolution */
    ngx_http_complex_value_t *role_variable;     /**< Source variable for role string */
    ngx_str_t                 role_separator;    /**< Delimiter for role splitting */
    ngx_uint_t                denied_code;       /**< HTTP status for denied (403) */
    ngx_uint_t                unauthorized_code; /**< HTTP status for unauthorized (401) */
    ngx_uint_t                explicit_off;      /**< Non-zero when auth_rbac is off */
} ngx_http_auth_rbac_loc_conf_t;

/** Per-request context; caches evaluation results for variable handlers. */
typedef struct {
    ngx_uint_t  result;          /**< One of NGX_RBAC_RESULT_* */
    ngx_str_t   raw_roles;       /**< Raw role string from the source variable */
    ngx_str_t   expanded_roles;  /**< Role names after hierarchy expansion */
    ngx_str_t   matched_rule;    /**< Text of the rule that determined the result */
} ngx_http_auth_rbac_ctx_t;


/** nginx module descriptor for the RBAC module. */
extern ngx_module_t ngx_http_auth_rbac_module;

#endif /* _NGX_HTTP_AUTH_RBAC_MODULE_H_INCLUDED_ */
