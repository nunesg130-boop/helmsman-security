# Same pinned base image as Helmsman (node 24.19.0, alpine 3.23).
FROM node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995

# openssl generates the API certificate on first start; curl runs the healthcheck.
RUN apk add --no-cache openssl curl \
    && addgroup -S -g 10001 helmsec \
    && adduser -S -D -H -u 10001 -G helmsec helmsec \
    && mkdir -p /app /data \
    && chown 10001:10001 /data && chmod 0700 /data

WORKDIR /app
COPY --chown=0:0 package.json ./package.json
COPY --chown=0:0 src ./src
COPY --chown=0:0 LICENSE* README.md ./
RUN find /app -type d -exec chmod 0555 {} + && find /app -type f -exec chmod 0444 {} +

ENV NODE_ENV=production \
    NODE_OPTIONS="--disable-proto=throw --no-warnings=ExperimentalWarning" \
    HS_CONFIG=/data/config.json \
    HS_DATA_DIR=/data \
    HS_MASTER_KEY=/run/secrets/master.key

USER 10001:10001
EXPOSE 8443 8081
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/api/v1/health | grep -qE "^(200|401)$"

STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "src/main.mjs"]
