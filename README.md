# OpenResty Web Platform with Various Authentication Methods

![Docker Image](https://github.com/mmguero/openresty-loaded/workflows/openresty-loaded-build-push-ghcr/badge.svg)

This setup uses [OpenResty](https://openresty.org/en/) with the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) authentication module and the [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc/) library to perform the following functions for an HTTP service:

* reverse proxy HTTP connections over HTTPS
* handle authentication via
    - HTTP Basic authentication
    - Active Directory/Lightweight Directory Access Protocol (LDAP)
    - Keycloak (or another OpenID Connect (OIDC) provider, probably)
    - No authentication

It can be used with [docker](https://docs.docker.com/get-docker/)/[docker compose](https://docs.docker.com/compose/) or [podman](https://podman.io/)/[podman-compose](https://github.com/containers/podman-compose) to encapsulate the OpenResty runtime on the host. A pre-built container image can be found on GitHub's container registry as [oci.guero.org/openresty-loaded](https://github.com/mmguero/openresty-loaded/pkgs/container/openresty-loaded).

### System Requirements

* **Either**
    * [docker](https://docs.docker.com/get-docker/)/[docker compose](https://docs.docker.com/compose/)
    * [podman](https://podman.io/getting-started/installation)/[podman-compose](https://github.com/containers/podman-compose)

## Getting Started

* review `docker-compose.yml` and make any changes needed for your personal application
* review `nginx.conf` to replace the example `whoami` upstream with your service, set the `location` directives as needed, and make whatever other changes you need
* run `./scripts/auth_setup.sh` to
    * specify username/password (only used for HTTP Basic authentication)
    * stub out `nginx/nginx_ldap.conf` for `winldap` or `openldap` (only used for LDAP authentication)
    * generate self-signed SSL certificates
* copy `.env.example` to `.env` and edit any variables needed as described in the comments of that file
* if using LDAP, edit `nginx/nginx_ldap.conf` as described below to populate the connection details for your LDAP server
* if you need to add any trusted CA certificate files that may be required by the LDAP or Keycloak services, place them in the `nginx/ca-trust/` directory

## LDAP Connection Security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (cleartext) (***not recommended***)

In addition to the `NGINX_AUTH_MODE` environment variable being set to `ldap` in `.env`, the environment variables beginning with `NGINX_LDAP_TLS_STUNNEL` are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

* **StartTLS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `true`
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 
* **LDAPS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `false`
    - `url` should begin with `ldaps://` and its port should be either the default LDAPS port (636) or the default LDAPS Global Catalog port (3269) in `nginx/nginx_ldap.conf` 
* **Unencrypted** (clear text) (***not recommended***)
    - `NGINX_LDAP_TLS_STUNNEL` set to `false`
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 

### nginx_ldap.conf

The [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) module serves as the interface between the [NGINX](https://nginx.org/) web server and a remote LDAP server. When you run `auth_setup.sh` for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. This file is bind mounted into the `nginx` container to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/mmguero-dev/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed access
* `referral` - setting this value to `off` (vs. `on`) can be useful when authenticating against read-only directory servers

Before starting NGINX, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section.
