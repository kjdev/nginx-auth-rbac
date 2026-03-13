# Installation Guide

## Requirements

- nginx 1.18.0 or later (with dynamic module support)
- C compiler (GCC / Clang)
- PCRE library (included in the nginx build)
- jansson library (optional, for JSON role parsing)

## Building

### Building as a Dynamic Module from nginx Source

```bash
# Download nginx source
wget https://nginx.org/download/nginx-x.y.z.tar.gz
tar xzf nginx-x.y.z.tar.gz
cd nginx-x.y.z

# Build as a dynamic module
./configure \
    --with-compat \
    --with-pcre \
    --add-dynamic-module=..
make modules

# The module file will be generated at
ls objs/ngx_http_auth_rbac_module.so
```

### Building with jansson Support

If jansson is installed, it will be detected automatically and JSON role parsing will be enabled.

```bash
# Debian/Ubuntu
apt-get install libjansson-dev

# RHEL/CentOS/Fedora
dnf install jansson-devel

# macOS
brew install jansson
```

## Installation

```bash
# Copy the module file to the nginx modules directory
# The path varies by distribution:
#   Debian/Ubuntu:       /usr/lib/nginx/modules/
#   RHEL/CentOS/Fedora:  /usr/lib64/nginx/modules/
cp objs/ngx_http_auth_rbac_module.so /usr/lib/nginx/modules/
```

Add to the top of `nginx.conf`:

```nginx
load_module /usr/lib/nginx/modules/ngx_http_auth_rbac_module.so;
```

## Verifying the Installation

```bash
nginx -t
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

---

## See Also

- [Directive Reference](DIRECTIVES.md) — Full specification of all directives
- [Configuration Examples](EXAMPLES.md) — Example configurations for various use cases
- [Troubleshooting](TROUBLESHOOTING.md) — Common issues and solutions
- [Security Guidelines](SECURITY.md) — Security best practices for production
