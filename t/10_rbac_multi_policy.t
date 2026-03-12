use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== multi_policy: different policies for different locations
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy api_policy {
  role api_user;
  grant api_user /api;
  default deny;
}

rbac_policy admin_policy {
  role admin;
  grant admin /admin;
  default deny;
}
--- config
location /api {
  set $role "api_user";
  auth_rbac api_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}

location /admin {
  set $role "admin";
  auth_rbac admin_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /api/users
--- error_code: 200

=== multi_policy: admin_policy grants admin on /admin
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy api_policy {
  role api_user;
  grant api_user /api;
  default deny;
}

rbac_policy admin_policy {
  role admin;
  grant admin /admin;
  default deny;
}
--- config
location /api {
  set $role "api_user";
  auth_rbac api_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}

location /admin {
  set $role "admin";
  auth_rbac admin_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /admin/dashboard
--- error_code: 200

=== multi_policy: role isolation between policies
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy policy_a {
  role alpha;
  grant alpha /;
  default deny;
}

rbac_policy policy_b {
  role beta;
  grant beta /;
  default deny;
}
--- config
location / {
  set $role "alpha";
  auth_rbac policy_b;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /test
--- error_code: 403
--- error_log
rbac: unknown role "alpha" ignored

=== multi_policy: independent default settings (default allow)
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy strict_policy {
  role user;
  grant user /allowed;
  default deny;
}

rbac_policy open_policy {
  role user;
  deny user /secret;
  default allow;
}
--- config
location /public {
  set $role "user";
  auth_rbac open_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /public/page
--- error_code: 200

=== multi_policy: independent default settings (default deny)
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy strict_policy {
  role user;
  grant user /allowed;
  default deny;
}

rbac_policy open_policy {
  role user;
  deny user /secret;
  default allow;
}
--- config
location /restricted {
  set $role "user";
  auth_rbac strict_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /restricted/page
--- error_code: 403

=== multi_policy: same role name with different permissions across policies
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy blog_policy {
  role editor;
  grant editor /blog;
  default deny;
}

rbac_policy wiki_policy {
  role editor;
  grant editor /wiki;
  default deny;
}
--- config
location /blog {
  set $role "editor";
  auth_rbac blog_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /blog/post
--- error_code: 200

=== multi_policy: same role name allowed in matching policy
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy blog_policy {
  role editor;
  grant editor /blog;
  default deny;
}

rbac_policy wiki_policy {
  role editor;
  grant editor /wiki;
  default deny;
}
--- config
location /wiki {
  set $role "editor";
  auth_rbac wiki_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /wiki/page
--- error_code: 200

=== multi_policy: same role name no cross-policy grant
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy blog_policy {
  role editor;
  grant editor /blog;
  default deny;
}

rbac_policy wiki_policy {
  role editor;
  grant editor /wiki;
  default deny;
}
--- config
location /blog {
  set $role "editor";
  auth_rbac wiki_policy;
  auth_rbac_role $role;
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /blog/post
--- error_code: 403

=== multi_policy: server-level policy overridden by location
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy server_policy {
  role user;
  grant user /;
  default deny;
}

rbac_policy location_policy {
  role admin;
  grant admin /admin;
  default deny;
}
--- config
set $role "admin";
auth_rbac server_policy;
auth_rbac_role $role;

location /admin {
  auth_rbac location_policy;
  proxy_pass http://127.0.0.1:8080/;
}

location / {
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /admin/dashboard
--- error_code: 200

=== multi_policy: server-level policy applied to non-overridden location
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy server_policy {
  role user;
  grant user /;
  default deny;
}

rbac_policy location_policy {
  role admin;
  grant admin /admin;
  default deny;
}
--- config
set $role "admin";
auth_rbac server_policy;
auth_rbac_role $role;

location /admin {
  auth_rbac location_policy;
  proxy_pass http://127.0.0.1:8080/;
}

location / {
  proxy_pass http://127.0.0.1:8080/;
}
--- request
GET /public/page
--- error_code: 403
--- error_log
rbac: unknown role "admin" ignored
