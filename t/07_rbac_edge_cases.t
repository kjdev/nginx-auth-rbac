use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== edge: wildcard role grant allows all roles
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role viewer;
  grant * /public;
  default deny;
}
--- config
location / {
  set $role "viewer";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /public/page
--- error_code: 200

=== edge: empty role returns unauthorized
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401

=== edge: auth_rbac_role not configured returns unauthorized
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
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 401
--- error_log
rbac: auth_rbac_role not configured

=== edge: custom denied code
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "viewer";
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_denied 404;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 404

=== edge: custom unauthorized code
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
  auth_rbac_unauthorized 403;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 403

=== edge: unknown role ignored with warning
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "nonexistent";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 403
--- error_log
rbac: unknown role "nonexistent" ignored

=== edge: child location inherits server-level auth_rbac
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
set $role "admin";
auth_rbac test;
auth_rbac_role $role;

location / {
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200

=== edge: child location overrides with auth_rbac off
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  default deny;
}
--- config
set $role "admin";
auth_rbac test;
auth_rbac_role $role;

location / {
  auth_rbac off;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /anything
--- error_code: 200

=== edge: custom separator
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role editor;
  grant editor /articles;
  default deny;
}
--- config
location / {
  set $role "admin|editor";
  auth_rbac test;
  auth_rbac_role $role;
  auth_rbac_role_separator |;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200

=== edge: tab whitespace in role separator is trimmed
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role editor;
  grant editor /articles;
  default deny;
}
--- config
location / {
  set $role "admin,\teditor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200
