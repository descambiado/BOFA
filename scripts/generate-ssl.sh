
#!/bin/bash

echo "🔐 Generando certificados SSL para BOFA..."

# Crear directorio SSL si no existe
mkdir -p nginx/ssl

# Generar certificado autofirmado
openssl req -x509 -newkey rsa:4096 \
    -keyout nginx/ssl/bofa.local.key \
    -out nginx/ssl/bofa.local.crt \
    -days 365 -nodes \
    -subj "/C=ES/ST=Madrid/L=Madrid/O=BOFA/CN=localhost"

# Configurar permisos
chmod 600 nginx/ssl/bofa.local.key
chmod 644 nginx/ssl/bofa.local.crt

echo "✅ Certificados generados correctamente:"
echo "   - nginx/ssl/bofa.local.crt"
echo "   - nginx/ssl/bofa.local.key"
echo ""
echo "🔄 Reconstruye el contenedor nginx:"
echo "   docker-compose up --build nginx"
