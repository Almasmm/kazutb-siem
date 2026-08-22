FROM node:24-alpine AS build

WORKDIR /app
ARG VITE_AUTH_MODE=oidc
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_API_TOKEN=
ARG VITE_TENANT_ID=university-kulazhanov
ARG VITE_OIDC_AUTHORITY=
ARG VITE_OIDC_CLIENT_ID=
ARG VITE_OIDC_SCOPE="openid profile email offline_access"
ENV VITE_AUTH_MODE=$VITE_AUTH_MODE \
    VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_API_TOKEN=$VITE_API_TOKEN \
    VITE_TENANT_ID=$VITE_TENANT_ID \
    VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY \
    VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID \
    VITE_OIDC_SCOPE=$VITE_OIDC_SCOPE
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
