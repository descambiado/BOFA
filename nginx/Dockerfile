
FROM nginx:alpine

# Copiar configuración personalizada
COPY default.conf /etc/nginx/conf.d/default.conf

# Copiar archivos de autenticación
COPY .htpasswd /etc/nginx/.htpasswd

# Copiar certificados SSL
COPY ssl/ /etc/nginx/ssl/

# Crear directorio SSL y configurar permisos
RUN chmod 600 /etc/nginx/ssl/bofa.local.key && \
    chmod 644 /etc/nginx/ssl/bofa.local.crt

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
