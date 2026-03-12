use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== variable: rbac_result is allowed
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Result $rbac_result;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200
--- response_headers
X-RBAC-Result: allowed

=== variable: rbac_role contains raw roles
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role editor;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin,editor";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Role $rbac_role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200
--- response_headers
X-RBAC-Role: admin,editor

=== variable: rbac_roles shows expanded roles with hierarchy
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  role admin > editor;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Roles $rbac_roles;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200
--- response_headers_like
X-RBAC-Roles: ^(?=.*admin)(?=.*editor)(?=.*viewer).+$

=== variable: rbac_roles without hierarchy shows single role
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role editor;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Roles $rbac_roles;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200
--- response_headers
X-RBAC-Roles: admin

=== variable: rbac_matched_rule shows matching rule
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Matched $rbac_matched_rule;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200
--- response_headers
X-RBAC-Matched: grant admin /api

=== variable: rbac_result is denied on deny rule match
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role viewer;
  deny viewer /secret;
  grant viewer /;
  default deny;
}
--- config
location / {
  set $role "viewer";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Result $rbac_result always;
  add_header X-RBAC-Role $rbac_role always;
  add_header X-RBAC-Matched $rbac_matched_rule always;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /secret/data
--- error_code: 403
--- response_headers
X-RBAC-Result: denied
X-RBAC-Role: viewer
X-RBAC-Matched: deny viewer /secret

=== variable: rbac_roles is set on denied response
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  deny editor /secret;
  grant editor /;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Roles $rbac_roles always;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /secret/data
--- error_code: 403
--- response_headers_like
X-RBAC-Roles: ^(?=.*editor)(?=.*viewer).+$

=== variable: rbac_result is denied on default deny (no rule matched)
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Result $rbac_result always;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /other/path
--- error_code: 403
--- response_headers
X-RBAC-Result: denied

=== variable: rbac_result is unauthorized on empty role
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "";
  auth_rbac test;
  auth_rbac_role $role;
  add_header X-RBAC-Result $rbac_result always;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401
--- response_headers
X-RBAC-Result: unauthorized

=== variable: rbac_result is unauthorized when role not configured
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  auth_rbac test;
  add_header X-RBAC-Result $rbac_result always;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401
--- response_headers
X-RBAC-Result: unauthorized
