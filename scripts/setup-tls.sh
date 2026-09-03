#!/usr/bin/env bash
# Provision a locally-trusted HTTPS certificate for the lab using mkcert.
#
# mkcert is NOT Let's Encrypt — Let's Encrypt cannot issue for localhost. mkcert
# installs a local CA into your system (and browser) trust store and signs a
# localhost certificate with it, so https://localhost:3000 is trusted with no
# warning. Re-run any time; it's idempotent.
set -euo pipefail

if ! command -v mkcert >/dev/null 2>&1; then
  cat <<'MSG'
mkcert is not installed. Install it first:
  macOS:    brew install mkcert nss
  Linux:    see https://github.com/FiloSottile/mkcert#installation
  Windows:  choco install mkcert   (or scoop install mkcert)
Then re-run: npm run tls:setup
MSG
  exit 1
fi

cd "$(dirname "$0")/.."
mkdir -p certs
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1

echo
echo "Wrote certs/localhost.pem and certs/localhost-key.pem (git-ignored)."
echo "Now run:  docker compose up --build   →   https://localhost:3000"
