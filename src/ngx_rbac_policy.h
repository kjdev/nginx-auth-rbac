/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_RBAC_POLICY_H_INCLUDED_
#define _NGX_RBAC_POLICY_H_INCLUDED_

#include "ngx_http_auth_rbac_module.h"

/** Parse HTTP method names from a string and return a bitmask. */
ngx_uint_t ngx_rbac_policy_parse_methods(ngx_conf_t *cf,
    ngx_str_t *methods_str);

/** Parse a path string and populate match type and pattern in a rule. */
ngx_int_t ngx_rbac_policy_parse_path(ngx_conf_t *cf, ngx_str_t *path_str,
    ngx_rbac_rule_t *rule);

/** Look up a role by name in the policy, returning NULL if not found. */
ngx_rbac_role_t *ngx_rbac_policy_find_role(ngx_rbac_policy_t *policy,
    ngx_str_t *name);

/** Resolve parent role references and build the role hierarchy bitmasks. */
ngx_int_t ngx_rbac_policy_resolve_hierarchy(ngx_conf_t *cf,
    ngx_rbac_policy_t *policy);

/** Resolve role name references in all rules to bitmasks. */
ngx_int_t ngx_rbac_policy_resolve_rules(ngx_conf_t *cf,
    ngx_rbac_policy_t *policy);

#endif /* _NGX_RBAC_POLICY_H_INCLUDED_ */
