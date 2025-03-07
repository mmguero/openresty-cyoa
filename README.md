# OpenResty Web Platform with Various Authentication Methods

![Docker Image](https://github.com/mmguero/openresty-loaded/workflows/openresty-loaded-build-push-ghcr/badge.svg)

This setup uses [OpenResty](https://openresty.org/en/) with the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) authentication module and the [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc/) library to perform the following functions for an HTTP service:

* reverse proxy HTTP connections over HTTPS
* handle authentication via
    - HTTP basic
    - Active Directory/Lightweight Directory Access Protocol (LDAP)
    - Keycloak
    - no authentication

It can be used with [docker](https://docs.docker.com/get-docker/)/[docker-compose](https://docs.docker.com/compose/install/) or [podman](https://podman.io/)/[podman-compose](https://github.com/containers/podman-compose) to encapsulate the OpenResty runtime on the host. A pre-built container image can be found on GitHub's container registry as [oci.guero.org/openresty-loaded](https://github.com/mmguero/openresty-loaded/pkgs/container/openresty-loaded).

## System Requirements

* **Either**
    * [docker](https://docs.docker.com/get-docker/)/[docker compose](https://docs.docker.com/compose/)
    * [podman](https://podman.io/getting-started/installation)/[podman-compose](https://github.com/containers/podman-compose)

## Configuring LDAP Authentication

### auth_setup.sh

 [`auth_setup.sh`](scripts/auth_setup.sh) will generate the self-signed certificates for HTTPS access and create a sample `nginx_ldap.conf` file (see below) if it doesn't already exist. The username/password here really doesn't matter, since NGINX will be using LDAP authentication instead:

```
$ ./scripts/auth_setup.sh 
username: admin
admin password: 
admin password (again): 

openldap or winldap: winldap

(Re)generate self-signed certificates for HTTPS access [Y/n]? Y
```

### docker-compose.yml

The environment variables at the top of [`docker-compose.yml`](./docker-compose.yml) are used to configure authentication for the NGINX server:

* `NGINX_BASIC_AUTH`
    * if set to `true`, use TLS-encrypted HTTP basic authentication; if set to `false`, use Lightweight Directory Access Protocol (LDAP) authentication
* `NGINX_LDAP_TLS_STUNNEL`
    * NGINX LDAP (i.e., when `NGINX_BASIC_AUTH` is `false`) can support **LDAP**, **LDAPS** or **LDAP+StartTLS**. For **StartTLS**, set `NGINX_LDAP_TLS_STUNNEL` to `true` to issue the **StartTLS** command and use `stunnel` to tunnel the connection. See **Connection Security** below.
* `NGINX_LDAP_TLS_STUNNEL_CHECK_HOST`, `NGINX_LDAP_TLS_STUNNEL_CHECK_IP` and `NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL`
    * `stunnel` will require and verify certificates for **StartTLS** when one or more trusted CA certificate files are placed in the `./nginx/ca-trust` directory. For additional security, hostname or IP address checking of the associated CA certificate(s) can be enabled by providing these values.

#### Connection Security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (cleartext) (***not recommended***)

In addition to the `NGINX_BASIC_AUTH` environment variable being set to `false` in the `x-auth-variables` section near the top of the [`docker-compose.yml`](#DockerComposeYml) file, the `NGINX_LDAP_TLS_STUNNEL` and `NGINX_LDAP_TLS_STUNNEL` environment variables are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

* **StartTLS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `true` in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 
* **LDAPS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldaps://` and its port should be either the default LDAPS port (636) or the default LDAPS Global Catalog port (3269) in `nginx/nginx_ldap.conf` 
* **Unencrypted** (clear text) (***not recommended***)
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`docker-compose.yml`](#DockerComposeYml)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 

For encrypted connections (whether using **StartTLS** or **LDAPS**), the service will require and verify certificates when one or more trusted CA certificate files are placed in the `nginx/ca-trust/` directory. Otherwise, any certificate presented by the domain server will be accepted.

### nginx_ldap.conf

The [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) module serves as the interface between the [NGINX](https://nginx.org/) web server and a remote LDAP server. When you run [`auth_setup.sh`](scripts/auth_setup.sh) for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. 

```
# This is a sample configuration for the ldap_server section of nginx.conf.
# Yours will vary depending on how your Active Directory/LDAP server is configured.
# See https://github.com/mmguero-dev/nginx-auth-ldap#available-config-parameters for options.

ldap_server ad_server {
  url "ldap://ds.example.com:3268/DC=example,DC=com?sAMAccountName?sub?(objectClass=person)";

  binddn "bind_dn";
  binddn_passwd "bind_dn_password";

  referral off;

  group_attribute member;
  group_attribute_is_dn on;
  require group "CN=users,OU=groups,DC=example,DC=com";
  require valid_user;
  satisfy all;
}

auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
```

This file is bind mounted into the `nginx` container to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/mmguero-dev/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed access
* `referral` - setting this value to `off` (vs. `on`) can be useful when authenticating against read-only directory servers

Before starting NGINX, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section.

### nginx.conf

By default, NGINX is simply proxying a small `whoami` HTTP server useful for debugging connectivity to containers ([source](https://github.com/traefik/whoami) and [image](https://hub.docker.com/r/containous/whoami)). It's recommended that you test your configuration with this simple server first. Once you've got NGINX communicating with your LDAP server correctly, you can modify [`./nginx/nginx.conf`](./nginx/nginx.conf) to point to your HTTP server. For example, assuming an HTTP service accessible at `foobar` over port `80`, you could do something like:

```bash
$ sed -i "s/whoami/foobar/g" ./nginx/nginx.conf
```

Whatever your configuration, edit the `upstream` section in `nginx.conf` to match.
