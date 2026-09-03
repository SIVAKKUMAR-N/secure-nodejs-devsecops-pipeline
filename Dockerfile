# ---------- Dependencies ----------
FROM node:22-bookworm-slim AS deps

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev \
    && npm cache clean --force

# ---------- Production ----------
FROM node:22-bookworm-slim

WORKDIR /app

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy application
COPY . .

# Create non-root user
RUN groupadd --system appgroup \
    && useradd --system --gid appgroup appuser \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]