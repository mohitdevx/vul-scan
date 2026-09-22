FROM node:22-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@11.8.0 --activate

COPY package.json ./
RUN pnpm install --ignore-scripts

COPY . .
RUN pnpm run build

FROM nginx:alpine AS runner

COPY --from=builder /app/dist /usr/share/nginx/html

# Setup SPA routing & API reverse proxy
RUN echo $'server {\n\
    listen 80;\n\
\n\
    location /api/ {\n\
        proxy_pass http://backend:4000/api/;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header Upgrade $http_upgrade;\n\
        proxy_set_header Connection "upgrade";\n\
        proxy_set_header Host $host;\n\
        proxy_cache_bypass $http_upgrade;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
        proxy_set_header X-Forwarded-Proto $scheme;\n\
    }\n\
\n\
    location / {\n\
        root /usr/share/nginx/html;\n\
        index index.html index.htm;\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
