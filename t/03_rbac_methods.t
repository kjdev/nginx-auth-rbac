use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== method: GET allowed with on GET
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /articles/1
--- error_code: 200

=== method: POST denied with on GET only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
POST /articles/1
--- error_code: 403

=== method: multiple methods allowed
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET,POST /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
POST /articles/new
--- error_code: 200

=== method: unknown method (MKCOL) denied with on GET
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
MKCOL /articles/1
--- error_code: 403

=== method: unknown method (MKCOL) allowed without method constraint
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
MKCOL /articles/1
--- error_code: 200

=== method: DELETE denied with GET,POST only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET,POST /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
DELETE /articles/1
--- error_code: 403

=== method: HEAD allowed with on HEAD
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on HEAD /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
HEAD /articles/1
--- error_code: 200

=== method: HEAD denied with on GET only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
HEAD /articles/1
--- error_code: 403

=== method: PUT allowed with on PUT
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on PUT /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
PUT /articles/1
--- error_code: 200

=== method: PUT denied with on GET only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
PUT /articles/1
--- error_code: 403

=== method: PATCH allowed with on PATCH
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on PATCH /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
PATCH /articles/1
--- error_code: 200

=== method: PATCH denied with on GET only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
PATCH /articles/1
--- error_code: 403

=== method: OPTIONS allowed with on OPTIONS
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on OPTIONS /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
OPTIONS /articles/1
--- error_code: 200

=== method: OPTIONS denied with on GET only
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role editor;
  grant editor on GET /articles;
  default deny;
}
--- config
location / {
  set $role "editor";
  auth_rbac test;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
OPTIONS /articles/1
--- error_code: 403
