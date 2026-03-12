use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== json: single role from JSON array
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role viewer;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role '["admin"]';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200

=== json: multiple roles from JSON array
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role editor;
  role viewer;
  grant editor /articles;
  default deny;
}
--- config
location / {
  set $role '["viewer","editor"]';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200

=== json: role not in policy denied
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role '["viewer"]';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 403

=== json: empty JSON array returns unauthorized
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role '[]';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401

=== json: invalid JSON falls back to unauthorized
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role 'not-json';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401
--- error_log
rbac: JSON parse failed

=== json: non-array JSON returns unauthorized
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role '{"role":"admin"}';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401
--- error_log
rbac: JSON role value is not an array

=== json: hierarchy works with JSON roles
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  role admin > editor;
  grant viewer /public;
  grant editor /articles;
  default deny;
}
--- config
location / {
  set $role '["admin"]';
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator json;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200
