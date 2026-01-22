# Build Stage
FROM node:20-alpine AS build

WORKDIR /app

# Install specific dependencies to keep build fast
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .

# Pass environment variables at build time (required for Vite to bake into JS bundle)
ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_ENTRA_TENANT_ID
ARG VITE_ENTRA_WEB_CLIENT_ID
ARG VITE_ENTRA_API_CLIENT_ID

ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_ENTRA_TENANT_ID=$VITE_ENTRA_TENANT_ID
ENV VITE_ENTRA_WEB_CLIENT_ID=$VITE_ENTRA_WEB_CLIENT_ID
ENV VITE_ENTRA_API_CLIENT_ID=$VITE_ENTRA_API_CLIENT_ID

RUN npm run build

# Production Stage
FROM nginx:alpine

# Copy build artifacts
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config
# Copy custom nginx config template
COPY nginx.conf /etc/nginx/templates/default.conf.template

# Fix: Set worker_processes to 1 directly in the config file to avoid duplicate directive error
RUN sed -i 's/worker_processes .*/worker_processes 1;/g' /etc/nginx/nginx.conf

ENV PORT=80

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
