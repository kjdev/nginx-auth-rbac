use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== hierarchy: admin inherits editor permissions
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  role admin > editor;
  grant editor /articles;
  grant viewer /public;
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
GET /articles/1
--- error_code: 200

=== hierarchy: admin inherits viewer permissions
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  role admin > editor;
  grant viewer /public;
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
GET /public/page
--- error_code: 200

=== hierarchy: viewer cannot access editor path
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  role admin > editor;
  grant editor /articles;
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
GET /articles/1
--- error_code: 403

=== hierarchy: editor can access viewer path
--- http_config
include $TEST_NGINX_CONF_DIR/backend.conf;

rbac_policy test {
  role viewer;
  role editor > viewer;
  grant viewer /public;
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
GET /public/page
--- error_code: 200
