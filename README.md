# OpenResty CYOA (Choose Your Own Authentication)

[![OpenResty Logo](./assets/openresty.png)](https://openresty.org/en/)
![Choose Your Own Authentication](./assets/cyoa.png)

![Docker Image](https://github.com/mmguero/openresty-cyoa/workflows/openresty-cyoa-build-push-ghcr/badge.svg)

OpenResty CYOA is an Alpine Linux-based container image for [OpenResty](https://openresty.org/en/) with several authentication methods available to use out of the box:

* HTTP Basic authentication (`NGINX_AUTH_MODE=basic`)
* Active Directory/Lightweight Directory Access Protocol (LDAP) via the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) plugin (`NGINX_AUTH_MODE=ldap`)
* Keycloak (or other OpenID Connect (OIDC) providers, probably) via [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc/) (`NGINX_AUTH_MODE=keycloak`)
* No authentication (`NGINX_AUTH_MODE=no_authentication`)

OpenResty CYOA will also act as a reverse proxy to serve HTTP connections over HTTPS (`NGINX_SSL=true`).

OpenResty CYOA can be used with [Docker](https://docs.docker.com/get-docker/)/[Docker Compose](https://docs.docker.com/compose/) or [Podman](https://podman.io/)/[podman-compose](https://github.com/containers/podman-compose). Pre-built container images for AMD64 and ARM64 can be found on GitHub's container registry as [oci.guero.org/openresty-cyoa](https://github.com/mmguero/openresty-cyoa/pkgs/container/openresty-cyoa).

## Getting Started

* Review `docker-compose.yml` and make any changes needed for your personal application (e.g., replace the `whoami` service with the service to be proxied behind OpenResty CYOA, configure [labels for Traefik](https://doc.traefik.io/traefik/user-guides/docker-compose/basic-example/), etc.).
* Copy `.env.example` to `.env` and edit any variables needed as described in the comments of that file.
* Review `nginx/nginx.conf` and replace the example `whoami` upstream with your service, set the `location` directives as needed, and make whatever other changes you need.
* Run `scripts/auth_setup.sh` to:
    * specify username/password (only used for HTTP Basic authentication)
    * stub out `nginx/nginx_ldap.conf` for `winldap` or `openldap` (only used for LDAP authentication)
    * generate self-signed SSL certificates
* If using LDAP, edit `nginx/nginx_ldap.conf` as described below to populate the connection details for your LDAP server.
    * Note that as an alternative to the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) integration, KeyCloak can also be configured to [federate one or more LDAP servers](https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap).
* If you need to add any trusted CA certificate files that may be required by the LDAP or Keycloak services, place them in the `nginx/ca-trust/` directory.

## LDAP Connection Security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (cleartext) (***not recommended***)

In addition to the `NGINX_AUTH_MODE` environment variable being set to `ldap` in `.env`, the environment variables beginning with `NGINX_LDAP_…` are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

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

The [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) module serves as the interface between [OpenResty](https://openresty.org/en/)'s [NGINX](https://nginx.org/) web server and a remote LDAP server. When you run `scripts/auth_setup.sh` for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. This file is bind mounted into the `openresty` container to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/mmguero-dev/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed access
* `referral` - setting this value to `off` (vs. `on`) can be useful when authenticating against read-only directory servers

Before starting NGINX, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section.

## KeyCloak

OpenResty CYOA can utilize Keycloak, an identity and access management (IAM) tool, to provide a more robust authentication and authorization experience, including single sign-on (SSO) functionality.

This README does not go into the details of the many capabilities Keycloak provides, including [identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker), [SSO protocols](https://www.keycloak.org/docs/latest/server_admin/index.html#sso-protocols), [federate one or more LDAP or Kerberos servers](https://www.keycloak.org/docs/latest/server_admin/index.html#_user-storage-federation), and more. Refer to the Keycloak [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) for information on these and other topics.

See the comments for the variables beginning with `KEYCLOAK_…` in `.env.example` for more information on how to configure OpenResty CYOA to use KeyCloak.

## Attribution

* [OpenResty](https://openresty.com/)® OpenResty Inc.
* [Keycloak](https://www.keycloak.org/)© Keycloak Authors