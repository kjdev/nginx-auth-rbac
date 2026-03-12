use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== error: invalid role directive (no args)
--- http_config
rbac_policy test {
  role;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: invalid role directive (too many args)
--- http_config
rbac_policy test {
  role admin extra extra2 extra3;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: duplicate role
--- http_config
rbac_policy test {
  role admin;
  role admin;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: invalid token in role hierarchy (expected >)
--- http_config
rbac_policy test {
  role viewer;
  role admin = viewer;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: parent role not found
--- http_config
rbac_policy test {
  role admin > nonexistent;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: grant with invalid arg count
--- http_config
rbac_policy test {
  role admin;
  grant admin;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: deny with invalid arg count
--- http_config
rbac_policy test {
  role admin;
  deny admin;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: expected "on" keyword in grant
--- http_config
rbac_policy test {
  role admin;
  grant admin with GET /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: undefined role in grant rule
--- http_config
rbac_policy test {
  role admin;
  grant editor /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: undefined role in deny rule
--- http_config
rbac_policy test {
  role admin;
  deny editor /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: unknown HTTP method in grant rule
--- http_config
rbac_policy test {
  role admin;
  grant admin on BADMETHOD /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: invalid regex path
--- http_config
rbac_policy test {
  role admin;
  grant admin ~[invalid;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: invalid default directive (no value)
--- http_config
rbac_policy test {
  role admin;
  grant admin /api;
  default;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: invalid default directive value
--- http_config
rbac_policy test {
  role admin;
  grant admin /api;
  default permit;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: unknown directive in rbac_policy block
--- http_config
rbac_policy test {
  role admin;
  allow admin /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: policy not found
--- http_config
rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  auth_rbac nonexistent;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: empty HTTP method list
--- http_config
rbac_policy test {
  role admin;
  grant admin on , /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: self-referencing role hierarchy cycle
--- http_config
rbac_policy test {
  role admin > admin;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die

=== error: duplicate policy name
--- http_config
rbac_policy test {
  role admin;
  grant admin /;
  default deny;
}
rbac_policy test {
  role editor;
  grant editor /;
  default deny;
}
--- config
location / {
  auth_rbac test;
  auth_rbac_role $http_x_user_roles;
  return 200;
}
--- must_die
