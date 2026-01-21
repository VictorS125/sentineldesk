# Build Stage
FROM node:18-alpine as build

WORKDIR /app

# Install specific dependencies to keep build fast
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .

# Pass API URL at build time (can be overridden)
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# Production Stage
FROM nginx:alpine

# Copy build artifacts
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
