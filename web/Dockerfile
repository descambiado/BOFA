FROM node:18-alpine

WORKDIR /app

# Copiar archivos de dependencias y configuraciones TS
COPY package*.json ./
COPY tsconfig.json tsconfig.node.json ./

RUN npm install

# Copiar el resto del código
COPY . .

RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "3000"]