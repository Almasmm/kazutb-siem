FROM node:24-alpine AS build

WORKDIR /app
ARG KCSP_WEB_MODE=oidc
ARG KCSP_WEB_TENANT=university-kulazhanov
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN VITE_AUTH_MODE="$KCSP_WEB_MODE" \
    VITE_TENANT_ID="$KCSP_WEB_TENANT" \
    npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine AS runtime

USER root
RUN apk upgrade --no-cache
USER 101

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
