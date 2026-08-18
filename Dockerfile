FROM node:22-slim

WORKDIR /app
COPY package.json package-lock.json README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY src/cleanmail ./src/cleanmail

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["node", "src/cleanmail/cli.js"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
