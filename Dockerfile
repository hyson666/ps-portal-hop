FROM node:24-alpine

LABEL org.opencontainers.image.title="PS Portal Hop"
LABEL org.opencontainers.image.description="Tiny, safe-by-default HTTP CONNECT proxy for PS Portal"
LABEL org.opencontainers.image.source="https://github.com/hyson666/ps-portal-hop"

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --chown=node:node proxy.js ./

USER node
EXPOSE 8050/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const net=require('node:net');const s=net.connect(Number(process.env.PORT||8050),'127.0.0.1',()=>{s.end();process.exit(0)});s.setTimeout(2000,()=>process.exit(1));s.on('error',()=>process.exit(1))"

CMD ["node", "proxy.js"]
