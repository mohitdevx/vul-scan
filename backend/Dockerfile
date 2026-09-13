FROM node:22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git
RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json ./
COPY prisma ./prisma
RUN pnpm install
RUN pnpm prisma generate

COPY tsconfig.json ./
COPY src ./src
RUN pnpm run build

FROM node:22-alpine AS runner

WORKDIR /app

RUN apk add --no-cache git
RUN corepack enable && corepack prepare pnpm@latest --activate

ENV NODE_ENV=production
ENV PORT=4000

COPY package.json ./
COPY prisma ./prisma
RUN pnpm install --prod
RUN pnpm prisma generate

COPY --from=builder /app/dist ./dist

EXPOSE 4000

CMD ["node", "dist/index.js"]
