# Adipay container for Fly.io. Node 22 (the gateway needs >=20 and uses the
# built-in node:sqlite module, which is stable in Node 22). Builds the TS in
# packages/common, then runs the payment API, which serves the REST API,
# checkout and the owner admin at /admin on $PORT (8080 on Fly).
FROM node:22-slim

WORKDIR /app

# Install dependencies first (better layer caching).
COPY package*.json ./
# Workspace package manifests, so npm can resolve the monorepo workspaces.
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts
COPY tsconfig*.json ./

RUN npm install --no-audit --no-fund

# Compile the shared TypeScript package.
RUN npm run build

# The SQLite file lives on the mounted volume (/data) via SQLITE_DB_PATH.
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["node", "apps/payment-api/src/index.js"]
