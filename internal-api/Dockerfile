# The network-internal service the SSRF lab reaches. Never published to the host.
FROM node:20-bookworm-slim
WORKDIR /svc
COPY server.js package.json ./
ENV PORT=8081
EXPOSE 8081
CMD ["node", "server.js"]
