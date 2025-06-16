
FROM python:3.11-alpine

WORKDIR /app

# Instalar dependencias del sistema
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers

# Copiar archivos de dependencias
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Configurar el comando por defecto
CMD ["python", "bofa_cli.py"]
