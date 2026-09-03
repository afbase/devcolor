# The lab application (Express + SQLite + Prometheus metrics).
FROM node:20-bookworm-slim

# Build tools so better-sqlite3 can compile if a prebuilt binary isn't available
# for this platform (removed after install). openssl stays — the entrypoint uses
# it to generate a self-signed TLS fallback when no mkcert cert is mounted.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
# `npm ci` installs exactly the locked versions (A03). --ignore-scripts first,
# then rebuild the one native module we actually need.
RUN npm ci --ignore-scripts && npm rebuild better-sqlite3 \
  && apt-get purge -y python3 make g++ && apt-get autoremove -y

COPY . .
RUN chmod +x docker-entrypoint.sh

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    LAB_DB=/data/lab.db \
    TLS_CERT=/certs/localhost.pem \
    TLS_KEY=/certs/localhost-key.pem
RUN mkdir -p /data
EXPOSE 3000
# The app speaks HTTPS in the container, so the health check does too (and
# accepts the self-signed fallback via rejectUnauthorized:false).
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD node -e "require('node:https').get({host:'127.0.0.1',port:3000,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["./docker-entrypoint.sh"]
