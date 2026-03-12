use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== grant basic: admin granted /api
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
  set $role "admin";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200

=== deny basic: viewer denied /api
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
  set $role "viewer";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 403

=== default allow: unmatched role with default allow
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  default allow;
}
--- config
location / {
  set $role "unknown";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /anything
--- error_code: 200

=== default deny: unmatched role with default deny
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  default deny;
}
--- config
location / {
  set $role "unknown";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 403

=== auth_rbac off: bypass RBAC
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  default deny;
}
--- config
location / {
  auth_rbac off;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /anything
--- error_code: 200

=== multiple roles: comma separated
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
  set $role "viewer,editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200
