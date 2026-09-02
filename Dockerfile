# The lab application (Express + SQLite + Prometheus metrics).
FROM node:20-bookworm-slim

# Build tools so better-sqlite3 can compile if a prebuilt binary isn't available
# for this platform. Removed after install to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
# `npm ci` installs exactly the locked versions (A03). --ignore-scripts first,
# then rebuild the one native module we actually need.
RUN npm ci --ignore-scripts && npm rebuild better-sqlite3 \
  && apt-get purge -y python3 make g++ && apt-get autoremove -y

COPY . .

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    LAB_DB=/data/lab.db
RUN mkdir -p /data
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "app/server.js"]
