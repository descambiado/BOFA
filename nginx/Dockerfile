
FROM nginx:alpine

# Copiar configuración personalizada
COPY default.conf /etc/nginx/conf.d/default.conf

# Copiar archivos de autenticación
COPY .htpasswd /etc/nginx/.htpasswd

# Copy locally generated TLS material. The repository intentionally contains
# only ssl/.gitkeep; generate certificates locally before building this image.
COPY ssl/ /etc/nginx/ssl/

RUN test -s /etc/nginx/ssl/bofa.local.key && \
    test -s /etc/nginx/ssl/bofa.local.crt && \
    chmod 600 /etc/nginx/ssl/bofa.local.key && \
    chmod 644 /etc/nginx/ssl/bofa.local.crt

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
