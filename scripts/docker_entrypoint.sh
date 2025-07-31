#!/bin/bash
set -e

NGINX_CONF_DIR=/etc/nginx
NGINX_CONF=${NGINX_CONF_DIR}/nginx.conf
NGINX_TEMPLATES_DIR=${NGINX_CONF_DIR}/templates
NGINX_CONFD_DIR=${NGINX_CONF_DIR}/conf.d

# set up for HTTPS/HTTP and auth modes (basic, none, keycloak, LDAP/LDAPS/LDAP+StartTLS)

# "include" file that indicates the locations of the PEM files
NGINX_SSL_ON_CONF=${NGINX_CONF_DIR}/nginx_ssl_on_config.conf

# "include" symlink name which, at runtime, will point to either the ON or OFF file
NGINX_SSL_LINK=${NGINX_CONF_DIR}/nginx_ssl_config.conf

# a blank file just to use as an "include" placeholder for when .conf files aren't used
NGINX_BLANK_CONF=${NGINX_CONF_DIR}/nginx_blank.conf

# "include" file for resolver directive
NGINX_RESOLVER_CONF=${NGINX_CONF_DIR}/nginx_system_resolver.conf

# "include" file for auth_basic, prompt, and htpasswd
NGINX_BASIC_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_basic.conf

# "include" file for auth_ldap, prompt, and "auth_ldap_servers" name
NGINX_LDAP_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_ldap.conf

# "include" file for KeyCloak authentication
NGINX_KEYCLOAK_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_keycloak.conf
# experimental HTTP Basic Auth translation layer handling OAuth2 token exchange transparently
NGINX_KEYCLOAK_AUTH_BASIC_TRANSLATE_CONF=${NGINX_CONF_DIR}/nginx_auth_keycloak_basic.conf

# "include" file for fully disabling authentication
NGINX_NO_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_disabled.conf

# volume-mounted user configuration containing "ldap_server ad_server" section with URL, binddn, etc.
NGINX_LDAP_USER_CONF=${NGINX_CONF_DIR}/nginx_ldap.conf

# runtime "include" file for auth method (link to NGINX_BASIC_AUTH_CONF, NGINX_LDAP_AUTH_CONF, NGINX_KEYCLOAK_AUTH_CONF, or NGINX_NO_AUTH_CONF)
NGINX_RUNTIME_AUTH_LINK=${NGINX_CONF_DIR}/nginx_auth_rt.conf

# runtime "include" file for a location where we basically force basic auth (symlink for keycloak to translate basic -> token)
NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK=${NGINX_CONF_DIR}/nginx_auth_basic_translate_rt.conf

# runtime "include" file for ldap config (link to either NGINX_BLANK_CONF or (possibly modified) NGINX_LDAP_USER_CONF)
NGINX_RUNTIME_LDAP_LINK=${NGINX_CONF_DIR}/nginx_ldap_rt.conf

# logging
NGINX_LOGGING_CONF=${NGINX_CONF_DIR}/nginx_logging.conf

# config file for stunnel if using stunnel to issue LDAP StartTLS function
STUNNEL_CONF=/etc/stunnel/stunnel.conf

CA_TRUST_HOST_DIR=/var/local/ca-trust
CA_TRUST_RUN_DIR=/var/run/ca-trust

# copy trusted CA certs to runtime directory and c_rehash them to create symlinks
STUNNEL_CA_PATH_LINE=""
STUNNEL_VERIFY_LINE=""
STUNNEL_CHECK_HOST_LINE=""
STUNNEL_CHECK_IP_LINE=""
NGINX_LDAP_CA_PATH_LINE=""
NGINX_LDAP_CHECK_REMOTE_CERT_LINE=""
mkdir -p "$CA_TRUST_RUN_DIR"
# attempt to make sure trusted CA certs dir is readable by unprivileged nginx worker
chmod 755 "$CA_TRUST_RUN_DIR" || true
CA_FILES=$(shopt -s nullglob dotglob; echo "$CA_TRUST_HOST_DIR"/*)
if (( ${#CA_FILES} )) ; then
  rm -f "$CA_TRUST_RUN_DIR"/*
  pushd "$CA_TRUST_RUN_DIR" >/dev/null 2>&1
  if cp "$CA_TRUST_HOST_DIR"/* ./ ; then

    # attempt to make sure trusted CA certs are readable by unprivileged nginx worker
    chmod 644 * || true

    # create hash symlinks
    c_rehash -compat .

    # variables for stunnel config
    STUNNEL_CA_PATH_LINE="CApath = $CA_TRUST_RUN_DIR"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL ]] && STUNNEL_VERIFY_LINE="verify = $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL" || STUNNEL_VERIFY_LINE="verify = 2"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST ]] && STUNNEL_CHECK_HOST_LINE="checkHost = $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_IP ]] && STUNNEL_CHECK_IP_LINE="checkIP = $NGINX_LDAP_TLS_STUNNEL_CHECK_IP"

    # variables for nginx config
    NGINX_LDAP_CA_PATH_LINE="  ssl_ca_dir $CA_TRUST_RUN_DIR;"
    ( [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST ]] || [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_IP ]] ) && NGINX_LDAP_CHECK_REMOTE_CERT_LINE="  ssl_check_cert on;" || NGINX_LDAP_CHECK_REMOTE_CERT_LINE="  ssl_check_cert off;"
  fi
  popd >/dev/null 2>&1
fi

if [[ -z $NGINX_SSL ]] || [[ "$NGINX_SSL" != "false" ]]; then
  # doing encrypted HTTPS
  ln -sf "$NGINX_SSL_ON_CONF" "$NGINX_SSL_LINK"
  SSL_FLAG=" ssl"

  # generate dhparam.pem if missing
  if [[ ! -f ${NGINX_CONF_DIR}/dhparam/dhparam.pem ]]; then
    mkdir -p ${NGINX_CONF_DIR}/dhparam
    echo "Generating DH parameters" >&2 && \
      ( openssl dhparam -out ${NGINX_CONF_DIR}/dhparam/dhparam.pem 2048 >/dev/null 2>&1 || \
        echo "Failed to generate DH parameters" >&2 )
    if [[ -f ${NGINX_CONF_DIR}/dhparam/dhparam.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/dhparam/dhparam.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/dhparam/dhparam.pem
      chmod 600 ${NGINX_CONF_DIR}/dhparam/dhparam.pem
    fi
  fi

  # generate self-signed TLS certificate if missing
  if [[ ! -f ${NGINX_CONF_DIR}/certs/cert.pem ]] && [[ ! -f ${NGINX_CONF_DIR}/certs/key.pem ]]; then
    mkdir -p ${NGINX_CONF_DIR}/certs
    echo "Generating self-signed certificate" >&2 && \
      ( openssl req -subj /CN=localhost -x509 -newkey rsa:4096 -nodes -keyout ${NGINX_CONF_DIR}/certs/key.pem -out ${NGINX_CONF_DIR}/certs/cert.pem -days 3650 || \
        echo "Failed to generate self-signed certificate" >&2 )
    if [[ -f ${NGINX_CONF_DIR}/certs/cert.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/certs/cert.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/certs/cert.pem
      chmod 644 ${NGINX_CONF_DIR}/certs/cert.pem
    fi
    if [[ -f ${NGINX_CONF_DIR}/certs/key.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/certs/key.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/certs/key.pem
      chmod 600 ${NGINX_CONF_DIR}/certs/key.pem
    fi
  fi

else
  # doing unencrypted HTTP (not recommended unless behind another reverse proxy that's providing it)
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_SSL_LINK"
  SSL_FLAG=""
fi
# generate listen_####.conf files with appropriate SSL flag (since the NGINX
#   listen directive doesn't allow using variables)
if [[ -f "${NGINX_CONF}" ]]; then
  LISTEN_PORT_CONF_PATTERN="^\s*include\s+(${NGINX_CONF_DIR}/listen_([0-9]+)\.conf)\s*;\s*$"
  while IFS= read -r LINE; do
    if [[ "${LINE}" =~ ${LISTEN_PORT_CONF_PATTERN} ]]; then
      IFILE=${BASH_REMATCH[1]}
      PORT=${BASH_REMATCH[2]}
      [[ ! -f "${IFILE}" ]] && echo "listen ${PORT}${SSL_FLAG};" > "${IFILE}"
    fi
  done < "${NGINX_CONF}"
fi

# set logging level for error.log
echo "error_log /var/log/nginx/error.log ${NGINX_ERROR_LOG_LEVEL:-error};" > "${NGINX_LOGGING_CONF}"

# NGINX_AUTH_MODE basic|ldap|keycloak|no_authentication
if [[ -z $NGINX_AUTH_MODE ]] || [[ "$NGINX_AUTH_MODE" == "basic" ]] || [[ "$NGINX_AUTH_MODE" == "true" ]]; then
  # doing HTTP basic auth

  # point auth to nginx_auth_basic.conf
  ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK"

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

elif [[ "$NGINX_AUTH_MODE" == "no_authentication" ]] || [[ "$NGINX_AUTH_MODE" == "none" ]] || [[ "$NGINX_AUTH_MODE" == "no" ]]; then
  # completely disabling authentication (not recommended)

  # point auth to nginx_auth_disabled.conf
  ln -sf "$NGINX_NO_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_NO_AUTH_CONF" "$NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK"

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

elif [[ "$NGINX_AUTH_MODE" == "keycloak" ]]; then
  # Keycloak authentication

  # point auth to keycloak
  ln -sf "$NGINX_KEYCLOAK_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"

  if [[ "${NGINX_KEYCLOAK_BASIC_AUTH:-false}" == "true" ]]; then
    # experimental
    ln -sf "$NGINX_KEYCLOAK_AUTH_BASIC_TRANSLATE_CONF" "$NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK"
  else
    ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK"
  fi

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

elif [[ "$NGINX_AUTH_MODE" == "ldap" ]] || [[ "$NGINX_AUTH_MODE" == "false" ]]; then
  # ldap authentication

  # point nginx_auth_rt.conf to nginx_auth_ldap.conf
  ln -sf "$NGINX_LDAP_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_LDAP_AUTH_CONF" "$NGINX_RUNTIME_AUTH_BASIC_TRANSLATE_LINK"

  # parse URL information out of user ldap configuration
  # example:
  #   url "ldap://localhost:3268/DC=ds,DC=example,DC=com?sAMAccountName?sub?(objectClass=person)";
  #             "url"    quote protocol h/p    uri
  #             ↓        ↓     ↓        ↓      ↓
  PATTERN='^(\s*url\s+)([''"]?)(\w+)://([^/]+)(/.*)$'

  unset HEADER
  unset OPEN_QUOTE
  unset PROTOCOL
  unset REMOTE_HOST
  unset REMOTE_PORT
  unset URI_TO_END

  URL_LINE_NUM=0
  READ_LINE_NUM=0
  while IFS= read -r LINE; do
    READ_LINE_NUM=$((READ_LINE_NUM+1))
    if [[ $LINE =~ $PATTERN ]]; then
      URL_LINE_NUM=$READ_LINE_NUM
      HEADER=${BASH_REMATCH[1]}
      OPEN_QUOTE=${BASH_REMATCH[2]}
      PROTOCOL=${BASH_REMATCH[3]}
      REMOTE=${BASH_REMATCH[4]}
      REMOTE_ARR=(${REMOTE//:/ })
      [[ -n ${REMOTE_ARR[0]} ]] && REMOTE_HOST=${REMOTE_ARR[0]}
      [[ -n ${REMOTE_ARR[1]} ]] && REMOTE_PORT=${REMOTE_ARR[1]} || REMOTE_PORT=3268
      URI_TO_END=${BASH_REMATCH[5]}
      break
    fi
  done < "$NGINX_LDAP_USER_CONF"

  if [[ "$NGINX_LDAP_TLS_STUNNEL" == "true" ]]; then
    # user provided LDAP configuration, but we need to tweak it and set up stunnel to issue StartTLS

    if [[ -z $REMOTE_HOST ]]; then
      # missing LDAP info needed to configure tunnel, abort
      exit 1
    fi

    # pick a random local port to listen on for the client side of the tunnel
    read PORT_LOWER POWER_UPPER < /proc/sys/net/ipv4/ip_local_port_range
    LOCAL_PORT=$(shuf -i $PORT_LOWER-$POWER_UPPER -n 1)

    # create PEM key for stunnel (this key doesn't matter as we're only using stunnel in client mode)
    pushd /tmp >/dev/null 2>&1
    openssl genrsa -out key.pem 2048
    openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=$(hostname)/O=OpenResty/C=US"
    cat key.pem cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
    rm -f key.pem cert.pem
    popd >/dev/null 2>&1

    # configure stunnel
    cat <<EOF > "$STUNNEL_CONF"
setuid = nginx
setgid = nginx
pid = /tmp/stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = yes
foreground = yes
cert = /etc/stunnel/stunnel.pem
$STUNNEL_CA_PATH_LINE
$STUNNEL_VERIFY_LINE
$STUNNEL_CHECK_HOST_LINE
$STUNNEL_CHECK_IP_LINE

[stunnel.ldap_start_tls]
accept = localhost:$LOCAL_PORT
connect = $REMOTE_HOST:$REMOTE_PORT
protocol = ldap
EOF

    # rewrite modified copy of user ldap configuration to point to local end of tunnel instead of remote
    rm -f "$NGINX_RUNTIME_LDAP_LINK"
    touch "$NGINX_RUNTIME_LDAP_LINK"
    chmod 600 "$NGINX_RUNTIME_LDAP_LINK"
    READ_LINE_NUM=0
    while IFS= read -r LINE; do
      READ_LINE_NUM=$((READ_LINE_NUM+1))
      if (( $URL_LINE_NUM == $READ_LINE_NUM )); then
        echo "${HEADER}${OPEN_QUOTE}ldap://localhost:${LOCAL_PORT}${URI_TO_END}" >> "$NGINX_RUNTIME_LDAP_LINK"
      else
        echo "$LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      fi
    done < "$NGINX_LDAP_USER_CONF"

  else
    # we're doing either LDAP or LDAPS, but not StartTLS, so we don't need to use stunnel.
    # however, we do want to set SSL CA trust stuff if specified, so do that
    rm -f "$NGINX_RUNTIME_LDAP_LINK"
    touch "$NGINX_RUNTIME_LDAP_LINK"
    chmod 600 "$NGINX_RUNTIME_LDAP_LINK"
    READ_LINE_NUM=0
    while IFS= read -r LINE; do
      READ_LINE_NUM=$((READ_LINE_NUM+1))
      echo "$LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      if (( $URL_LINE_NUM == $READ_LINE_NUM )); then
        echo "$NGINX_LDAP_CHECK_REMOTE_CERT_LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
        echo "$NGINX_LDAP_CA_PATH_LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      fi
    done < "$NGINX_LDAP_USER_CONF"

  fi # stunnel/starttls vs. ldap/ldaps

fi # basic vs. ldap

# if the runtime htpasswd file doesn't exist but the "preseed" does, copy the preseed over for runtime
if [[ ! -f ${NGINX_CONF_DIR}/auth/htpasswd ]] && [[ -f /tmp/auth/default/htpasswd ]]; then
  cp /tmp/auth/default/htpasswd ${NGINX_CONF_DIR}/auth/htpasswd
  [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/auth/htpasswd
  [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/auth/htpasswd
  rm -rf /tmp/auth/* || true
fi

# now process the environment variable substitutions
for TEMPLATE in "$NGINX_TEMPLATES_DIR"/*.conf.template; do
  DOLLAR=$ envsubst < "$TEMPLATE" > "$NGINX_CONFD_DIR/$(basename "$TEMPLATE"| sed 's/\.template$//')"
done

if [[ -z "${NGINX_RESOLVER_OVERRIDE:-}" ]]; then
  # put the DNS resolver (nameserver from /etc/resolv.conf) into NGINX_RESOLVER_CONF
  DNS_SERVER="$(grep -i '^nameserver' /etc/resolv.conf | head -n1 | cut -d ' ' -f2)"
else
  DNS_SERVER=${NGINX_RESOLVER_OVERRIDE}
fi
[[ -z "${DNS_SERVER:-}" ]] && DNS_SERVER="127.0.0.11"
export DNS_SERVER
echo -n "resolver ${DNS_SERVER}" > "${NGINX_RESOLVER_CONF}"
[[ "${NGINX_RESOLVER_IPV4_OFF:-false}" == "true" ]] && echo -n " ipv4=off" >> "${NGINX_RESOLVER_CONF}"
[[ "${NGINX_RESOLVER_IPV6_OFF:-false}" == "true" ]] && echo -n " ipv6=off" >> "${NGINX_RESOLVER_CONF}"
echo ";" >> "${NGINX_RESOLVER_CONF}"

set -e

# some cleanup, if necessary
rm -rf /var/log/nginx/* || true

# start supervisor (which will spawn nginx, stunnel, etc.) or whatever the default command is
exec "$@"
