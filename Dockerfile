FROM node:22-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# Set permissions
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000

ENV PORT=3000 \
    NODE_ENV=production

CMD ["node", "server.js"]
