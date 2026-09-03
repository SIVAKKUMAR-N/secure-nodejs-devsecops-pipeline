# ---------- Dependencies ----------
FROM node:22-alpine AS deps

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev \
    && npm cache clean --force

# ---------- Production ----------
FROM node:22-alpine

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules

COPY . .

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]