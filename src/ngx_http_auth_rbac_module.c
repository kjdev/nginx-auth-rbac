/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nginx RBAC (Role-Based Access Control) module
 */

#include "ngx_http_auth_rbac_module.h"
#include "ngx_rbac_policy.h"
#include "ngx_rbac_matcher.h"
#include "ngx_rbac_role.h"
#include "ngx_rbac_variable.h"


/* Forward declarations */
static ngx_int_t ngx_http_auth_rbac_init(ngx_conf_t *cf);
static void *ngx_http_auth_rbac_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_auth_rbac_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_auth_rbac_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_rbac_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_auth_rbac_handler(ngx_http_request_t *r);
static char *ngx_http_auth_rbac_policy_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_rbac_policy_command(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_rbac_set_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_rbac_set_role(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_rbac_set_status_code(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


/* Variable definitions */
static ngx_http_variable_t ngx_http_auth_rbac_vars[] = {
    { ngx_string("rbac_role"), NULL, ngx_rbac_variable_role,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("rbac_roles"), NULL, ngx_rbac_variable_roles,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("rbac_matched_rule"), NULL, ngx_rbac_variable_matched_rule,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("rbac_result"), NULL, ngx_rbac_variable_result,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};


/* Command definitions */
static ngx_command_t ngx_http_auth_rbac_commands[] = {

    { ngx_string("rbac_policy"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      ngx_http_auth_rbac_policy_block,
      NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },

    { ngx_string("auth_rbac"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_rbac_set_auth,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    { ngx_string("auth_rbac_role"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_rbac_set_role,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    { ngx_string("auth_rbac_role_separator"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_rbac_loc_conf_t, role_separator), NULL },

    { ngx_string("auth_rbac_denied"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_rbac_set_status_code,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_rbac_loc_conf_t, denied_code), NULL },

    { ngx_string("auth_rbac_unauthorized"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_http_auth_rbac_set_status_code,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_rbac_loc_conf_t, unauthorized_code), NULL },

    ngx_null_command
};


/* Module context */
static ngx_http_module_t ngx_http_auth_rbac_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_auth_rbac_init,                /* postconfiguration */

    ngx_http_auth_rbac_create_main_conf,    /* create main configuration */
    ngx_http_auth_rbac_init_main_conf,      /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_auth_rbac_create_loc_conf,     /* create location configuration */
    ngx_http_auth_rbac_merge_loc_conf       /* merge location configuration */
};


/* Module definition */
ngx_module_t ngx_http_auth_rbac_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_rbac_module_ctx,         /* module context */
    ngx_http_auth_rbac_commands,            /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ---- Configuration lifecycle ---- */

static void *
ngx_http_auth_rbac_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_rbac_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_rbac_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->policies = ngx_array_create(cf->pool, 4,
                                      sizeof(ngx_rbac_policy_t));
    if (conf->policies == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_rbac_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_auth_rbac_main_conf_t *rmcf = conf;
    ngx_rbac_policy_t *policies;
    ngx_uint_t i;

    if (rmcf->policies == NULL || rmcf->policies->nelts == 0) {
        return NGX_CONF_OK;
    }

    policies = rmcf->policies->elts;

    for (i = 0; i < rmcf->policies->nelts; i++) {
        if (ngx_rbac_policy_resolve_hierarchy(cf, &policies[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_rbac_policy_resolve_rules(cf, &policies[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_auth_rbac_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_rbac_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_rbac_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->denied_code = NGX_CONF_UNSET_UINT;
    conf->unauthorized_code = NGX_CONF_UNSET_UINT;
    /* policy, role_variable, policy_name: zero-initialized (NULL) */
    /* role_separator: zero-initialized (empty) */
    /* explicit_off: zero-initialized (0) */

    return conf;
}


static char *
ngx_http_auth_rbac_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_rbac_loc_conf_t *prev = parent;
    ngx_http_auth_rbac_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->role_separator,
                             prev->role_separator, ",");
    ngx_conf_merge_uint_value(conf->denied_code,
                              prev->denied_code, 403);
    ngx_conf_merge_uint_value(conf->unauthorized_code,
                              prev->unauthorized_code, 401);

    /* Inherit policy and role_variable from parent unless explicitly off */
    if (!conf->explicit_off) {
        if (conf->policy == NULL && prev->policy != NULL) {
            conf->policy = prev->policy;
        }

        if (conf->role_variable == NULL && prev->role_variable != NULL) {
            conf->role_variable = prev->role_variable;
        }
    }

    return NGX_CONF_OK;
}


/* ---- Postconfiguration: register handler and variables ---- */

static ngx_int_t
ngx_http_auth_rbac_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t *var, *v;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_rbac_handler;

    /* Register variables */
    for (v = ngx_http_auth_rbac_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/* ---- PRECONTENT phase handler ---- */

static ngx_int_t
ngx_http_auth_rbac_handler(ngx_http_request_t *r)
{
    ngx_http_auth_rbac_loc_conf_t *rlcf;
    ngx_http_auth_rbac_ctx_t *ctx;
    ngx_str_t role_value;
    ngx_array_t *role_names;
    uint64_t user_roles;
    ngx_uint_t result;
    u_char *p;
    ngx_uint_t i, len;
    ngx_rbac_role_t *roles;
    /* Skip subrequests */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_rbac_module);

    /* Not configured or explicitly off */
    if (rlcf->policy == NULL) {
        return NGX_DECLINED;
    }

    /* Evaluate role variable */
    if (rlcf->role_variable == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_rbac_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->result = NGX_RBAC_RESULT_UNAUTHORIZED;
        ngx_http_set_ctx(r, ctx, ngx_http_auth_rbac_module);

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "rbac: auth_rbac_role not configured, uri=%V", &r->uri);
        return rlcf->unauthorized_code;
    }

    if (ngx_http_complex_value(r, rlcf->role_variable, &role_value) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create request context */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_rbac_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Empty role value → unauthorized */
    if (role_value.len == 0) {
        ctx->result = NGX_RBAC_RESULT_UNAUTHORIZED;
        ngx_http_set_ctx(r, ctx, ngx_http_auth_rbac_module);

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "rbac: role variable is empty, uri=%V", &r->uri);
        return rlcf->unauthorized_code;
    }

    /* Store raw roles */
    ctx->raw_roles = role_value;

    /* Extract role names */
    role_names = ngx_rbac_extract_roles(r, &role_value, &rlcf->role_separator);
    if (role_names == NULL) {
        ctx->result = NGX_RBAC_RESULT_UNAUTHORIZED;
        ngx_http_set_ctx(r, ctx, ngx_http_auth_rbac_module);
        return rlcf->unauthorized_code;
    }

    /* Convert to bitmask */
    user_roles = ngx_rbac_roles_to_bitmask(rlcf->policy, role_names, r);

    /* Build expanded roles string for variable */
    len = 0;
    roles = rlcf->policy->roles->elts;
    for (i = 0; i < rlcf->policy->roles->nelts; i++) {
        if (user_roles & ((uint64_t) 1 << roles[i].index)) {
            if (len > 0) {
                len++; /* comma */
            }
            len += roles[i].name.len;
        }
    }

    if (len > 0) {
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "rbac: failed to allocate expanded roles string");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->expanded_roles.data = p;
        for (i = 0; i < rlcf->policy->roles->nelts; i++) {
            if (user_roles & ((uint64_t) 1 << roles[i].index)) {
                if (p != ctx->expanded_roles.data) {
                    *p++ = ',';
                }
                p = ngx_cpymem(p, roles[i].name.data, roles[i].name.len);
            }
        }
        ctx->expanded_roles.len = p - ctx->expanded_roles.data;
    }

    /* Evaluate policy */
    result = ngx_rbac_evaluate(r, rlcf->policy, user_roles, ctx);

    /* Set request context */
    ngx_http_set_ctx(r, ctx, ngx_http_auth_rbac_module);

    if (result == NGX_RBAC_RESULT_DENIED) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "rbac: access denied, roles=\"%V\", method=%V, "
                      "uri=%V, policy=%V",
                      &ctx->raw_roles, &r->method_name,
                      &r->uri, &rlcf->policy->name);
        return rlcf->denied_code;
    }

    return NGX_DECLINED;
}


/* ---- Block directive handlers ---- */

static char *
ngx_http_auth_rbac_policy_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_rbac_main_conf_t *rmcf = conf;
    ngx_rbac_policy_t *policy, *policies;
    ngx_str_t *value;
    ngx_conf_t save;
    char *rv;
    ngx_uint_t i;

    value = cf->args->elts;

    policies = rmcf->policies->elts;
    for (i = 0; i < rmcf->policies->nelts; i++) {
        if (policies[i].name.len == value[1].len
            && ngx_strncmp(policies[i].name.data, value[1].data,
                           value[1].len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: duplicate policy \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    policy = ngx_array_push(rmcf->policies);
    if (policy == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(policy, sizeof(ngx_rbac_policy_t));

    policy->name = value[1];
    policy->default_allow = 0;

    policy->roles = ngx_array_create(cf->pool, 8, sizeof(ngx_rbac_role_t));
    if (policy->roles == NULL) {
        return NGX_CONF_ERROR;
    }

    policy->rules = ngx_array_create(cf->pool, 8, sizeof(ngx_rbac_rule_t));
    if (policy->rules == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Save current context */
    save = *cf;

    cf->handler = ngx_http_auth_rbac_policy_command;
    cf->handler_conf = policy;

    rv = ngx_conf_parse(cf, NULL);

    /* Restore original context */
    *cf = save;

    return rv;
}


static char *
ngx_http_auth_rbac_policy_command(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_rbac_policy_t *policy = cf->handler_conf;
    ngx_str_t *value;
    ngx_uint_t nargs;

    value = cf->args->elts;
    nargs = cf->args->nelts;

    /* role name; */
    /* role name > parent; */
    if (value[0].len == 4
        && ngx_strncmp(value[0].data, "role", 4) == 0)
    {
        ngx_rbac_role_t *role;

        if (nargs != 2 && nargs != 4) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: invalid role directive, "
                               "expected \"role name;\" or "
                               "\"role name > parent;\"");
            return NGX_CONF_ERROR;
        }

        if (policy->n_roles >= NGX_RBAC_MAX_ROLES) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: too many roles (max %d)",
                               NGX_RBAC_MAX_ROLES);
            return NGX_CONF_ERROR;
        }

        /* Check for duplicate role name */
        if (ngx_rbac_policy_find_role(policy, &value[1]) != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: duplicate role \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        role = ngx_array_push(policy->roles);
        if (role == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(role, sizeof(ngx_rbac_role_t));

        role->name = value[1];
        role->index = policy->n_roles++;
        role->parent_index = NGX_CONF_UNSET_UINT;
        role->effective_roles = (uint64_t) 1 << role->index;

        /* role name > parent; */
        if (nargs == 4) {
            ngx_rbac_role_t *parent;

            if (value[2].len != 1 || value[2].data[0] != '>') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "rbac: expected \">\" in role directive, "
                                   "got \"%V\"", &value[2]);
                return NGX_CONF_ERROR;
            }

            parent = ngx_rbac_policy_find_role(policy, &value[3]);
            if (parent == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "rbac: parent role \"%V\" not found",
                                   &value[3]);
                return NGX_CONF_ERROR;
            }

            role->parent_index = parent->index;
        }

        return NGX_CONF_OK;
    }

    /* grant role path; */
    /* grant role on methods path; */
    /* deny role path; */
    /* deny role on methods path; */
    if ((value[0].len == 5 && ngx_strncmp(value[0].data, "grant", 5) == 0)
        || (value[0].len == 4 && ngx_strncmp(value[0].data, "deny", 4) == 0))
    {
        ngx_rbac_rule_t *rule;
        ngx_str_t *path_str;
        ngx_str_t *role_name;
        ngx_rbac_role_t *role;
        ngx_uint_t is_deny;
        ngx_str_t methods_str;
        u_char *p;
        ngx_uint_t rule_text_len;
        ngx_uint_t i;

        is_deny = (value[0].data[0] == 'd') ? 1 : 0;

        if (nargs != 3 && nargs != 5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: invalid %V directive, "
                               "expected \"%V role path;\" or "
                               "\"%V role on methods path;\"",
                               &value[0], &value[0], &value[0]);
            return NGX_CONF_ERROR;
        }

        role_name = &value[1];

        if (nargs == 5) {
            if (value[2].len != 2
                || ngx_strncmp(value[2].data, "on", 2) != 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "rbac: expected \"on\" keyword, "
                                   "got \"%V\"", &value[2]);
                return NGX_CONF_ERROR;
            }

            methods_str = value[3];
            path_str = &value[4];
        } else {
            ngx_str_null(&methods_str);
            path_str = &value[2];
        }

        rule = ngx_array_push(policy->rules);
        if (rule == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(rule, sizeof(ngx_rbac_rule_t));

        rule->is_deny = is_deny;

        /*
         * Resolve role name to bitmask.
         *
         * role_mask holds only the named role's own bit (not hierarchy-
         * expanded).  Hierarchy is resolved on the user side: user_roles
         * includes inherited bits via effective_roles, so "grant editor
         * /path" matches an admin user whose user_roles contains the
         * editor bit through inheritance.  This means resolve_rules()
         * does not need to update role_mask after hierarchy resolution.
         */
        if (role_name->len == 1 && role_name->data[0] == '*') {
            rule->role_mask = NGX_RBAC_ROLE_WILDCARD;
        } else {
            role = ngx_rbac_policy_find_role(policy, role_name);
            if (role == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "rbac: undefined role \"%V\" in %V rule",
                                   role_name, &value[0]);
                return NGX_CONF_ERROR;
            }
            rule->role_mask = role->effective_roles;
        }

        /* Parse methods */
        rule->methods = ngx_rbac_policy_parse_methods(cf, &methods_str);
        if (rule->methods == 0) {
            return NGX_CONF_ERROR;
        }

        /* Parse path */
        if (ngx_rbac_policy_parse_path(cf, path_str, rule) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Build rule text for variables/logging */
        rule_text_len = value[0].len;
        for (i = 1; i < nargs; i++) {
            rule_text_len += 1 + value[i].len; /* space + arg */
        }

        p = ngx_pnalloc(cf->pool, rule_text_len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        rule->rule_text.data = p;
        p = ngx_cpymem(p, value[0].data, value[0].len);
        for (i = 1; i < nargs; i++) {
            *p++ = ' ';
            p = ngx_cpymem(p, value[i].data, value[i].len);
        }
        rule->rule_text.len = p - rule->rule_text.data;

        return NGX_CONF_OK;
    }

    /* default allow|deny; */
    if (value[0].len == 7
        && ngx_strncmp(value[0].data, "default", 7) == 0)
    {
        if (nargs != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: invalid default directive, "
                               "expected \"default allow|deny;\"");
            return NGX_CONF_ERROR;
        }

        if (value[1].len == 5
            && ngx_strncmp(value[1].data, "allow", 5) == 0)
        {
            policy->default_allow = 1;
        } else if (value[1].len == 4
                   && ngx_strncmp(value[1].data, "deny", 4) == 0)
        {
            policy->default_allow = 0;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "rbac: expected \"allow\" or \"deny\" "
                               "in default directive, got \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in rbac_policy block",
                       &value[0]);

    return NGX_CONF_ERROR;
}


/* ---- Location-level directive handlers ---- */

static char *
ngx_http_auth_rbac_set_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_rbac_loc_conf_t *rlcf = conf;
    ngx_http_auth_rbac_main_conf_t *rmcf;
    ngx_str_t *value;
    ngx_rbac_policy_t *policies;
    ngx_uint_t i;

    value = cf->args->elts;

    /* auth_rbac off; */
    if (value[1].len == 3
        && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        rlcf->policy = NULL;
        rlcf->explicit_off = 1;
        return NGX_CONF_OK;
    }

    /* Resolve policy by name */
    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_rbac_module);

    if (rmcf->policies == NULL || rmcf->policies->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "rbac: no policies defined");
        return NGX_CONF_ERROR;
    }

    policies = rmcf->policies->elts;

    for (i = 0; i < rmcf->policies->nelts; i++) {
        if (policies[i].name.len == value[1].len
            && ngx_strncmp(policies[i].name.data, value[1].data,
                           value[1].len) == 0)
        {
            rlcf->policy = &policies[i];
            rlcf->policy_name = value[1];
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "rbac: policy \"%V\" not found", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_auth_rbac_set_role(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_rbac_loc_conf_t *rlcf = conf;
    ngx_str_t *value;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    rlcf->role_variable = ngx_pcalloc(cf->pool,
                                      sizeof(ngx_http_complex_value_t));
    if (rlcf->role_variable == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = rlcf->role_variable;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_rbac_set_status_code(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char *p = conf;

    ngx_uint_t *np;
    ngx_str_t *value;
    ngx_int_t code;

    np = (ngx_uint_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    code = ngx_atoi(value[1].data, value[1].len);
    if (code == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "rbac: invalid status code \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (code < 400 || code > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "rbac: status code %i is out of range "
                           "(must be 400-599)", code);
        return NGX_CONF_ERROR;
    }

    *np = (ngx_uint_t) code;

    return NGX_CONF_OK;
}
