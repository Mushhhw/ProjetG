FROM php:8.1-apache

# Installer les extensions PHP nécessaires
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

# Installer l'extension SSH2
RUN pecl install ssh2-1.3.1 \
    && docker-php-ext-enable ssh2

# Activer les modules Apache nécessaires
RUN a2enmod rewrite ssl

# Copier la configuration Apache personnalisée
COPY apache-config.conf /etc/apache2/sites-available/000-default.conf

# Copier les certificats SSL
COPY web/certs/projet3.local.crt /etc/ssl/certs/projet3.local.crt
COPY web/private/projet3.local.key /etc/ssl/private/projet3.local.key

# Copier les fichiers HTML
COPY html /var/www/html

# Définir le répertoire de travail
WORKDIR /var/www/html

# Exposer les ports
EXPOSE 80
EXPOSE 443

# Démarrer Apache en premier plan
CMD ["apache2-foreground"]
