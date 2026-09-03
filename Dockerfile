# ---------- Dependencies ----------
FROM node:22.23.2-alpine3.24 AS deps

WORKDIR /app

COPY package*.json ./

RUN npm ci --omit=dev \
    && npm cache clean --force

# ---------- Production ----------
FROM node:22.23.2-alpine3.24

# Update OpenSSL packages to patched versions
RUN apk update && apk upgrade --no-cache

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules

COPY . .

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]