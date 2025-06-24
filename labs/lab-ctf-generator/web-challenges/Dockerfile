
FROM php:7.4-apache

# Install required packages
RUN apt-get update && apt-get install -y \
    mysql-client \
    && docker-php-ext-install mysqli pdo pdo_mysql

# Copy web challenges
COPY challenges/ /var/www/html/
COPY apache-config.conf /etc/apache2/sites-available/000-default.conf

# Set permissions
RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 755 /var/www/html/

EXPOSE 80 443
