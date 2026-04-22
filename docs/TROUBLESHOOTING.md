# Troubleshooting

## 401 Unauthorized is returned

**Cause**: The role string is empty or cannot be retrieved.

**Check**:

- Is the `auth_rbac_role` directive configured?
- Does the specified variable (e.g., `$http_x_user_roles`) contain a value at request time?
- Can the role variable value be confirmed in the logs?

```nginx
# Debug: output role variable values to the log
log_format rbac_debug '$remote_addr [$time_local] '
                      'role="$rbac_role" result="$rbac_result"';
access_log /var/log/nginx/rbac_debug.log rbac_debug;
```

**Resolution**: Set the correct variable in `auth_rbac_role` and verify that the upstream authentication module (e.g., nginx-oidc) is properly setting the roles.

## 403 Forbidden is returned

**Cause**: One of the following:

- The role is not defined in the policy
- A deny rule matched first (deny-first evaluation)
- No grant rule matched and `default deny` is set

**Check**:

- Inspect the value of `$rbac_matched_rule` to identify which rule matched
- Check `$rbac_roles` to see the expanded role list after hierarchy resolution
- Verify that deny rules are not unintentionally blocking a wide scope

```nginx
# Debug: inspect matched rule
add_header X-RBAC-Matched $rbac_matched_rule always;
add_header X-RBAC-Roles $rbac_roles always;
add_header X-RBAC-Result $rbac_result always;
```

**Resolution**:

- Ensure the role name exactly matches the policy definition (case-sensitive)
- Review deny rules for overly broad path or role patterns
- If `default deny` is set, ensure grant rules cover all required paths

## JSON role parsing fails

**Cause**: The module was built without the jansson library, but `auth_rbac_role_separator json` is being used.

**Check**:

- Was jansson installed when the module was built?
- Is `NGX_RBAC_HAVE_JSON` defined?

**Resolution**: Install jansson and rebuild the module.

```bash
# Debian/Ubuntu
apt-get install libjansson-dev

# RHEL/CentOS/Fedora
dnf install jansson-devel
```

If jansson is not available, pass roles as a comma-separated string instead.

## Regex paths do not work

**Cause**: nginx was built without PCRE support.

**Check**:

- Run `nginx -V` and look for `--with-pcre` or PCRE-related options in the output

**Resolution**: Rebuild nginx with PCRE enabled. Alternatively, use prefix matching as a workaround.

## `$rbac_*` variables are empty

**Cause**: RBAC evaluation did not run in the current location.

**Check**:

- Is `auth_rbac off` set in this location?
- Is the `auth_rbac` directive configured?
- Is the variable being accessed in a subrequest? (RBAC skips subrequests)

**Resolution**: Ensure `auth_rbac` is properly configured in the location where the variables are referenced.

## Policy not found error

**Error message**: `rbac: policy "xxx" not found`

**Cause**: The policy name referenced by `auth_rbac` is not defined in any `rbac_policy` block.

**Check**:

- Is the `rbac_policy` block defined in the `http` context?
- Does the policy name spelling match exactly?

**Resolution**: Ensure the `rbac_policy` block is defined before the `auth_rbac` directive in the nginx configuration file.

---

## See Also

- [Installation Guide](INSTALL.md) — Build instructions and dependency setup
- [Directive Reference](DIRECTIVES.md) — Full specification of all directives
- [Configuration Examples](EXAMPLES.md) — Example configurations for various use cases
- [Troubleshooting](TROUBLESHOOTING.md) — Common issues and solutions
- [Security Guidelines](SECURITY.md) — Security best practices for production
