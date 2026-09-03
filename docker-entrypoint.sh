#!/bin/sh
# Ensure the app always has a TLS cert so the whole stack speaks HTTPS.
# If the host mounted an mkcert cert at /certs, use it (browser-trusted).
# Otherwise generate a throwaway self-signed cert (functional; browser will warn
# until you run `npm run tls:setup` on the host).
set -e
: "${TLS_CERT:=/certs/localhost.pem}"
: "${TLS_KEY:=/certs/localhost-key.pem}"

if [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
  echo "TLS: using mounted certificate ($TLS_CERT)"
else
  echo "TLS: no mounted cert — generating a self-signed fallback (run 'npm run tls:setup' on the host for a trusted one)"
  mkdir -p /tmp/certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /tmp/certs/localhost-key.pem -out /tmp/certs/localhost.pem \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:lab,IP:127.0.0.1" >/dev/null 2>&1
  export TLS_CERT=/tmp/certs/localhost.pem
  export TLS_KEY=/tmp/certs/localhost-key.pem
fi

exec node app/server.js
