FROM php:8.1-apache

# Installer les extensions nécessaires
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libssh2-1-dev \
    libssl-dev \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# Activer les modules Apache
RUN a2enmod rewrite ssl

# Copier les fichiers de configuration et le code
COPY ./web /var/www/html
COPY ./web/certs/projet3.local.crt /etc/ssl/certs/
COPY ./web/private/projet3.local.key /etc/ssl/private/

# Définir le répertoire de travail
WORKDIR /var/www/html

# Exposer les ports nécessaires
EXPOSE 80
EXPOSE 443

# Démarrer Apache
CMD ["apache2-foreground"]

