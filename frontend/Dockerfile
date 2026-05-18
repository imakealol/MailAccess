# --- Base Stage ---
FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install

# --- Development Stage ---
FROM base AS dev
COPY . .
# Start Vite dev server with HMR enabled
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# --- Build Stage ---
FROM base AS build
COPY . .
RUN npm run build

# --- Production Stage ---
FROM nginx:alpine AS prod
# Copy built files from the build stage
COPY --from=build /app/dist /usr/share/nginx/html
# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
