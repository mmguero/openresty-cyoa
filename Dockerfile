FROM alpine:3.22

LABEL maintainer="mero.mero.guero@gmail.com"
LABEL org.opencontainers.image.authors='mero.mero.guero@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/mmguero/openresty-cyoa'
LABEL org.opencontainers.image.source='https://github.com/mmguero/openresty-cyoa'
LABEL org.opencontainers.image.title='ghcr.io/mmguero/openresty-cyoa'
LABEL org.opencontainers.image.description='Dockerized OpenResty with basic, LDAP, and Keycloak Authentication'

ARG DEFAULT_UID=101
ARG DEFAULT_GID=101
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "nginx"
ENV PGROUP "nginx"
# not dropping privileges globally so nginx and stunnel can bind privileged ports internally.
# nginx itself will drop privileges to "nginx" user for worker processes
ENV PUSER_PRIV_DROP false
USER root

ENV TERM xterm

USER root

# encryption method: HTTPS ('true') vs. unencrypted HTTP ('false')
ARG NGINX_SSL=true

# authentication method: basic|ldap|keycloak|no_authentication
ARG NGINX_AUTH_MODE=basic

# NGINX LDAP (NGINX_AUTH_MODE=ldap) can support LDAP, LDAPS, or LDAP+StartTLS.
#   For StartTLS, set NGINX_LDAP_TLS_STUNNEL=true to issue the StartTLS command
#   and use stunnel to tunnel the connection.
ARG NGINX_LDAP_TLS_STUNNEL=false

# stunnel will require and verify certificates for StartTLS when one or more
# trusted CA certificate files are placed in the ./nginx/ca-trust directory.
# For additional security, hostname or IP address checking of the associated
# CA certificate(s) can be enabled by providing these values.
# see https://www.stunnel.org/howto.html
#     https://www.openssl.org/docs/man1.1.1/man3/X509_check_host.html
ARG NGINX_LDAP_TLS_STUNNEL_CHECK_HOST=
ARG NGINX_LDAP_TLS_STUNNEL_CHECK_IP=
ARG NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL=2

ENV NGINX_SSL $NGINX_SSL
ENV NGINX_AUTH_MODE $NGINX_AUTH_MODE
ENV NGINX_LDAP_TLS_STUNNEL $NGINX_LDAP_TLS_STUNNEL
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_HOST $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_IP $NGINX_LDAP_TLS_STUNNEL_CHECK_IP
ENV NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL

ENV OPENRESTY_VERSION=1.27.1.1
ENV NGINX_AUTH_LDAP_BRANCH=master

ADD --chmod=644 https://openresty.org/download/openresty-$OPENRESTY_VERSION.tar.gz /openresty.tar.gz
ADD --chmod=644 https://codeload.github.com/mmguero-dev/nginx-auth-ldap/tar.gz/$NGINX_AUTH_LDAP_BRANCH /nginx-auth-ldap.tar.gz
ADD --chmod=755 https://raw.githubusercontent.com/mmguero/docker/master/shared/docker-uid-gid-setup.sh /usr/local/bin/docker-uid-gid-setup.sh

RUN set -x ; \
    CONFIG="\
    --prefix=/usr/local/openresty \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=${PUSER} \
    --group=${PGROUP} \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-http_xslt_module=dynamic \
    --with-http_image_filter_module=dynamic \
    --with-http_geoip_module=dynamic \
    --with-http_perl_module=dynamic \
    --with-luajit \
    --with-threads \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-stream_realip_module \
    --with-stream_geoip_module=dynamic \
    --with-http_slice_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-pcre-jit \
    --with-compat \
    --with-file-aio \
    --with-http_v2_module \
    --add-module=/usr/src/nginx-auth-ldap \
  " ; \
  apk update --no-cache; \
  apk upgrade --no-cache; \
  apk add --no-cache curl rsync shadow openssl; \
  addgroup -g ${DEFAULT_GID} -S ${PGROUP} ; \
  adduser -S -D -H -u ${DEFAULT_UID} -h /var/cache/nginx -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
  addgroup ${PUSER} shadow ; \
  mkdir -p /var/cache/nginx ; \
  chown ${PUSER}:${PGROUP} /var/cache/nginx ; \
  apk add --no-cache --virtual .nginx-build-deps \
    autoconf \
    automake \
    cmake \
    g++ \
    gcc \
    gd-dev \
    geoip-dev \
    git \
    gnupg \
    libbsd-dev \
    libc-dev \
    libtool \
    libxslt-dev \
    linux-headers \
    luajit-dev \
    make \
    openldap-dev \
    openssl-dev \
    pcre-dev \
    perl-dev \
    tar \
    zlib-dev \
    ; \
    \
  mkdir -p /usr/src/nginx-auth-ldap /www /www/logs/nginx /var/log/nginx ; \
  tar -zxC /usr/src -f /openresty.tar.gz ; \
  tar -zxC /usr/src/nginx-auth-ldap --strip=1 -f /nginx-auth-ldap.tar.gz ; \
  cd /usr/src/openresty-$OPENRESTY_VERSION ; \
  ./configure $CONFIG ; \
  make -j$(getconf _NPROCESSORS_ONLN) ; \
  make install ; \
  rm -rf /etc/nginx/html/ ; \
  mkdir -p /etc/nginx/conf.d/ /etc/nginx/templates/ /etc/nginx/auth/ /usr/share/nginx/html/ ; \
  ln -s /usr/local/openresty/bin/openresty /usr/sbin/nginx ; \
  ln -s ../../usr/lib/nginx/modules /etc/nginx/modules ; \
  strip /usr/sbin/nginx* ; \
  strip /usr/lib/nginx/modules/*.so ; \
  rm -rf /usr/src/openresty-$OPENRESTY_VERSION ; \
  \
  # Bring in gettext so we can get `envsubst`, then throw
  # the rest away. To do this, we need to install `gettext`
  # then move `envsubst` out of the way so `gettext` can
  # be deleted completely, then move `envsubst` back.
  apk add --no-cache --virtual .gettext gettext ; \
  mv /usr/bin/envsubst /tmp/ ; \
  \
  runDeps="$( \
    scanelf --needed --nobanner /usr/sbin/nginx /usr/lib/nginx/modules/*.so /tmp/envsubst \
      | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
      | sort -u \
      | xargs -r apk info --installed \
      | sort -u \
  )" ; \
  apk add --no-cache --virtual .nginx-rundeps $runDeps \
    apache2-utils \
    bash \
    ca-certificates \
    gd \
    jq \
    libbsd \
    libgd \
    luajit \
    openldap \
    shadow \
    stunnel \
    supervisor \
    tini \
    tzdata \
    wget; \
  update-ca-certificates; \
  /usr/local/openresty/bin/opm install ledgetech/lua-resty-http ; \
  /usr/local/openresty/bin/opm install bungle/lua-resty-session=3.10 ; \
  /usr/local/openresty/bin/opm install cdbattags/lua-resty-jwt ; \
  /usr/local/openresty/bin/opm install zmartzone/lua-resty-openidc ; \
  apk del .nginx-build-deps ; \
  apk del .gettext ; \
  mv /tmp/envsubst /usr/local/bin/ ; \
  rm -rf /usr/src/* /var/tmp/* /var/cache/apk/* /openresty.tar.gz /nginx-auth-ldap.tar.gz; \
  touch /etc/nginx/nginx_ldap.conf /etc/nginx/nginx_blank.conf && \
  find /usr/share/nginx/html/ -type d -exec chmod 755 "{}" \; && \
  find /usr/share/nginx/html/ -type f -exec chmod 644 "{}" \;

ADD --chmod=755 scripts/*.sh /usr/local/bin/
ADD --chmod=644 nginx/templates/* /etc/nginx/templates/
ADD --chmod=644 nginx/lua/*.lua /usr/local/openresty/lualib/
ADD --chmod=644 nginx/*.conf /etc/nginx/
ADD --chmod=644 supervisord.conf /etc/

EXPOSE 80
EXPOSE 443

VOLUME ["/etc/nginx/certs", "/etc/nginx/dhparam"]

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/docker_entrypoint.sh"]

CMD ["supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]
