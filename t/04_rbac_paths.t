use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== path exact: exact match succeeds
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin =/api/status;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/status
--- error_code: 200

=== path exact: exact match fails on subpath
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin =/api/status;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/status/detail
--- error_code: 403

=== path prefix: prefix match succeeds
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users/123
--- error_code: 200

=== path prefix: prefix match fails on different path
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /web/page
--- error_code: 403

=== path prefix: prefix /api also matches /api-v2 (no trailing slash)
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api-v2/users
--- error_code: 200

=== path prefix: prefix /api/ does not match /api-v2
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api/;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api-v2/users
--- error_code: 403

=== path prefix: trailing asterisk shorthand
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api/*;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200

=== path regex: regex match succeeds
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin ~^/api/v[0-9]+/;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/v2/users
--- error_code: 200

=== path regex: regex match fails
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin ~^/api/v[0-9]+/;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/latest/users
--- error_code: 403

=== path query: prefix match with query string
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users?id=123
--- error_code: 200

=== path query: exact match with query string
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin =/api/status;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/status?debug=1
--- error_code: 200

=== path query: exact match fails on different path with query string
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin =/api/status;
  default deny;
}
--- config
location / {
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/other?debug=1
--- error_code: 403
