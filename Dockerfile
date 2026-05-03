# AirLock Scanner — Cloud Run
# Multi-stage build for smaller image
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (including dev for build tools if needed)
COPY packages/scanner/package.json packages/scanner/package-lock.json* ./
RUN npm ci

# Copy scanner source
COPY packages/scanner/src/ ./src/
COPY packages/scanner/policies/ ./policies/

# Production image
FROM node:20-alpine

WORKDIR /app

# Copy installed deps from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/src ./src
COPY --from=builder /app/policies ./policies

# Environment
ENV NODE_ENV=production
ENV PORT=8080
ENV AIRLOCK_DB_PATH=/tmp/airlock.db

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

EXPOSE 8080

# Server entry point
CMD ["node", "src/server.js"]