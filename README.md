# <a name="OpenRestyCYOA"></a>OpenResty CYOA (Choose Your Own Authentication)

[![OpenResty Logo](./assets/openresty.png)](https://openresty.org/en/)
![Choose Your Own Authentication](./assets/cyoa.png)

![Docker Image](https://github.com/mmguero/openresty-cyoa/workflows/openresty-cyoa-build-push-ghcr/badge.svg)

OpenResty CYOA is an Alpine Linux-based container image for [OpenResty](https://openresty.org/en/) with several authentication methods available to use out of the box:

* HTTP Basic authentication (`NGINX_AUTH_MODE=basic`)
* Active Directory/Lightweight Directory Access Protocol (LDAP) via the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) plugin (`NGINX_AUTH_MODE=ldap`)
* Keycloak (or other OpenID Connect (OIDC) providers, probably) via [lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc/) (`NGINX_AUTH_MODE=keycloak`)
* No authentication (`NGINX_AUTH_MODE=no_authentication`)

OpenResty CYOA will also act as a reverse proxy, and can terminate HTTP connections with TLS (`NGINX_SSL=true`). The following authentication/authorization-related HTTP headers will be passed by OpenResty CYOA to the service being proxied:

* `X-Forwarded-User` - the authenticated username
* `X-Forwarded-Groups` - comma-separated list of groups in which the user has [membership](#AuthKeycloakGroupsRoles), 
* `X-Forwarded-Roles` - comma-separated list of [roles](#AuthKeycloakRBAC) pertaining to the user

OpenResty CYOA can be used with [Docker](https://docs.docker.com/get-docker/)/[Docker Compose](https://docs.docker.com/compose/) or [Podman](https://podman.io/)/[podman-compose](https://github.com/containers/podman-compose). Pre-built container images for AMD64 and ARM64 can be found on GitHub's container registry as [ghcr.io/mmguero/openresty-cyoa](https://github.com/mmguero/openresty-cyoa/pkgs/container/openresty-cyoa).

## <a name="GettingStarted"></a>Getting Started

* Review [`docker-compose.yml`](./docker-compose.yml) and make any changes needed for your personal application (e.g., replace the `whoami` service with the service to be proxied behind OpenResty CYOA, configure [labels for Traefik](https://doc.traefik.io/traefik/user-guides/docker-compose/basic-example/), etc.).
* Copy [`.env.example`](./.env.example) to `.env` and edit any variables needed as described in the comments of that file.
* Review [`nginx/nginx.conf`](./nginx/nginx.conf) and replace the example `whoami` upstream with your service, set the `location` directives as needed, and make whatever other changes you need.
* Run [`scripts/auth_setup.sh`](scripts/auth_setup.sh) to:
    * specify username/password (only used for HTTP Basic authentication)
    * stub out `nginx/nginx_ldap.conf` for `winldap` or `openldap` (only used for LDAP authentication)
    * generate self-signed SSL certificates
* If using LDAP, edit `nginx/nginx_ldap.conf` as described below to populate the connection details for your LDAP server.
    * Note that as an alternative to the [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) integration, Keycloak can also be configured to [federate one or more LDAP servers](https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap).
* If you need to add any trusted CA certificate files that may be required by the LDAP or Keycloak services, place them in the `nginx/ca-trust/` directory.

## <a name="LDAPConnSec"></a>LDAP Connection Security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (cleartext) (***not recommended***)

In addition to the `NGINX_AUTH_MODE` environment variable being set to `ldap` in [`.env`](./.env.example), the environment variables beginning with `NGINX_LDAP_…` are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

* **StartTLS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `true`
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 
* **LDAPS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `false`
    - `url` should begin with `ldaps://` and its port should be either the default LDAPS port (636) or the default LDAPS Global Catalog port (3269) in `nginx/nginx_ldap.conf` 
* **Unencrypted** (clear text) (***not recommended***)
    - `NGINX_LDAP_TLS_STUNNEL` set to `false`
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 

### <a name="LDAPConf"></a>nginx_ldap.conf

The [nginx-auth-ldap](https://github.com/mmguero-dev/nginx-auth-ldap) module serves as the interface between [OpenResty](https://openresty.org/en/)'s [NGINX](https://nginx.org/) web server and a remote LDAP server. When you run [`scripts/auth_setup.sh`](scripts/auth_setup.sh) for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. This file is bind mounted into the `openresty` container to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/mmguero-dev/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed access
* `referral` - setting this value to `off` (vs. `on`) can be useful when authenticating against read-only directory servers

Before starting NGINX, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section.

## <a name="Keycloak"></a>Keycloak

OpenResty CYOA can utilize Keycloak, an identity and access management (IAM) tool, to provide a more robust authentication and authorization experience, including single sign-on (SSO) functionality.

This README does not go into the details of the many capabilities Keycloak provides, including [identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker), [SSO protocols](https://www.keycloak.org/docs/latest/server_admin/index.html#sso-protocols), [federate one or more LDAP or Kerberos servers](https://www.keycloak.org/docs/latest/server_admin/index.html#_user-storage-federation), and more. Refer to the Keycloak [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) for information on these and other topics.

See the comments for the variables beginning with `KEYCLOAK_…` in [`.env.example`](./.env.example) for more information on how to configure OpenResty CYOA to use Keycloak.

### <a name="AuthKeycloakGroupsRoles"></a>Groups and roles

OpenResty CYOA can use Keycloak's realm roles to implement [role-based access controls](#AuthKeycloakRBAC). It can also use realm roles or user groups as the basis for [system-wide authentication requirements](#AuthKeycloakReqGroupsRoles).

Groups can be managed in Keycloak by selecting the appropriate realm from the drop down at the top of the navigation panel and selecting **Groups** under **Manage**.

Users can be joined to groups by clicking on a username on the Keycloak **Users** page, selecting the **Groups** tab, then clicking **Join Group**.

Realm roles can be managed in Keycloak by selecting the appropriate realm from the drop down at the top of the navigation panel and selecting **Realm roles** under **Manage**.

Users can be assigned realm roles by clicking on a username on the Keycloak **Users** page, selecting the **Role mapping** tab, then clicking **Assign role**. Select **Filter by realm roles**, then check the box next to the desired role(s), then click **Assign**, after which the **User role mapping successfully updated** confirmation will appear.

For a discussion of roles vs. groups, see [**Assigning permissions using roles and groups**](https://www.keycloak.org/docs/latest/server_admin/index.html#assigning-permissions-using-roles-and-groups) in the Keycloak Server Administration Guide.

### <a name="AuthKeycloakRBAC"></a>Role-based access control

Role-based access control is only available when the authentication method is `keycloak`. With other authentication methods such as HTTP basic or LDAP, or when role-based access control is disabled, all users effectively have the same privileges.

`.env` contains the environment variables that enable or disable RBAC and define the names of the "back-end" Keycloak realm roles which can in turn be mapped to roles used internally by your services' several components.

These environment variables are divided into two sections:

* General access roles
    * `ROLE_ADMIN` - Unrestricted administrator access
    * `ROLE_READ_ACCESS` - Read-only access across all services
    * `ROLE_READ_WRITE_ACCESS` - Read/write access across all services, excluding some administrator functions
* Fine-grained roles can be added to `.env` and to `nginx/nginx_envs.conf`

Note that is is **up to you** to implement your services to respect these roles provided by OpenResty CYOA via the `X-Forwarded-Roles` HTTP header. Alternatively, Path-based role-based access controls can be defined in `nginx/lua/nginx_auth_helpers.lua` in the `path_role_envs` function, and the `uri_role_mappings` function can be used to map general access roles to fine-grained roles.

With role-based access control enabled, realm roles must exist that correspond to the names defined by these `ROLE_…` environment variables, and users must be [assigned those realm roles](#AuthKeycloakGroupsRoles) in order to use the features to which they correspond. Users attempting to access features for which they are authorized will be presented with a ["forbidden"](https://en.wikipedia.org/wiki/HTTP_403) error message.

### <a name="AuthKeycloakReqGroupsRoles"></a>System-wide required user groups and realm roles

As a simpler alternative to [role-based access control](#AuthRBAC), OpenResty CYOA can be configured to require Keycloak-authenticated users to belong to groups and assigned realm roles, respectively. The values for these groups and/or roles are specified with `NGINX_REQUIRE_GROUP` and `NGINX_REQUIRE_ROLE` in `.env`. An empty value for either of these settings means no restriction of that type is applied. Multiple values may be specified with a comma-separated list. These requirements are cumulative: users must match **all** of the items specified. Note that LDAP authentication can also require group membership, but that is specified in `nginx_ldap.conf` by setting `require group` rather than in `.env`.

### <a name="AuthKeycloakGroupsAndRolesConfig"></a>Configuring Keycloak to pass groups and roles to OpenResty CYOA

Keycloak does not include group or realm role information in authentication tokens by default; clients must be configured to include this information in order for users to log in with group and/or role restrictions set. This can be done by navigating to the Keycloak **Clients** page, selecting the desired client, then clicking the **Client scopes** tab. Click on the name of the assigned client scope beginning with the client ID and ending in **-dedicated**, which will also have a description of "Dedicated scope and mappers for this client." Once on this **Clients** > **Client details** > **Dedicated scopes** screen, click the down arrow on the **Add mapper** button and select **By configuration**.

To include group information in the Keycloak token for this client, select **Group Membership** from the **Configure a new mapper** list. The important information to provide for this Group Membership mapper before clicking **Save** is:

* **Mapper type**: Group Membership
* **Name**: *provide any name for this mapper*
* **Token Claim Name**: `groups`
* **Full group path**: If set to **On**, users will need to include the full path for the group name(s) in `NGINX_REQUIRE_GROUP` (e.g., `/top/level1/foobar_group`); if set to **Off**, just specify the group name (e.g., `foobar_group`)
* **Add to ID token**: On
* **Add to access token**: On
* **Add to token introspection**: On

To include user realm role information in the Keycloak token for this client, once again click the down arrow on the **Add mapper** button and select **Byte configuration**. Select **User Realm Role** from the **Configure a new mapper** list. The important information to provide for this User Realm Role mapper before clicking **Save** is:

* **Mapper type**: User Realm Role
* **Name**: *provide any name for this mapper*
* **Multivalued**: On
* **Token Claim Name**: `realm_access.roles`
* **Claim JSON Type**: String
* **Add to ID token**: On
* **Add to access token**: On
* **Add to token introspection**: On

Once the mapper(s) have been created, the list of mappers on the **Clients** > **Client details** > **Dedicated scopes** page will look something like this:

## Attribution

* [OpenResty](https://openresty.com/)® OpenResty Inc.
* [Keycloak](https://www.keycloak.org/)© Keycloak Authors