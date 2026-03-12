use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== deny first: deny overrides grant
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  deny admin /api/internal;
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
GET /api/internal/secret
--- error_code: 403

=== deny first: grant still works for non-denied path
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  deny admin /api/internal;
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
GET /api/public
--- error_code: 200

=== deny first: wildcard deny blocks all
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  role viewer;
  grant admin /api;
  deny * /api/maintenance;
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
GET /api/maintenance
--- error_code: 403

=== deny first: method-constrained deny blocks matching method
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  deny admin on DELETE /api/protected;
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
DELETE /api/protected/resource
--- error_code: 403

=== deny first: method-constrained deny allows other methods
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role admin;
  grant admin /api;
  deny admin on DELETE /api/protected;
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
GET /api/protected/resource
--- error_code: 200
