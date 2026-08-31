FROM node:22-alpine

WORKDIR /app
COPY server.mjs ./server.mjs

ENV PORT=8080
USER node
CMD ["node", "server.mjs"]
