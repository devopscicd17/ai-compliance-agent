# ─────────────────────────────────────────────────────────────
#  AWS Compliance Agent — Production Dockerfile
#  Builds a minimal, non-root container that runs on:
#    AWS ECS/Fargate · AWS App Runner · EKS · Azure Container Apps ·
#    Google Cloud Run/GKE · DigitalOcean App Platform · any K8s cluster
# ─────────────────────────────────────────────────────────────

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

FROM node:20-alpine AS runtime
RUN apk add --no-cache dumb-init tini
WORKDIR /app

# Non-root user for security (CIS Docker Benchmark 4.1)
RUN addgroup -S agent && adduser -S agent -G agent

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY config ./config
RUN mkdir -p /app/reports && chown -R agent:agent /app

USER agent
ENV NODE_ENV=production \
    REPORT_OUTPUT_DIR=/app/reports \
    ENABLE_HTTP_SERVER=true \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["node", "src/agent.js", "--mode=watch"]
