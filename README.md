# ProjetG

## Description
ProjetG est un projet web containerisé utilisant **Docker Compose** pour orchestrer un serveur web PHP avec Apache et une base de données MariaDB. Ce projet inclut une structure basique pour gérer des utilisateurs et explorer une application web simple avec des certificats SSL.

---

## Structure du projet

```
ProjetG/
├── Dockerfile                # Dockerfile principal pour la configuration
├── requirements.txt          # Dépendances Python (optionnel)
├── app.py                    # Application principale (optionnel)
├── projet/
│   ├── db-init/              # Scripts pour initialiser la base de données
│   │   └── init.sql          # Script SQL pour créer les tables et les données de base
│   ├── docker-compose.yml    # Fichier Docker Compose pour orchestrer les services
│   └── web/                  # Dossier contenant l'application web
│       ├── Dockerfile        # Configuration Docker pour le serveur web
│       ├── html/             # Fichiers front-end (HTML, PHP, etc.)
│       ├── certs/            # Certificats SSL
│       ├── private/          # Clés privées SSL
│       └── apache-config.conf # Configuration Apache
└── LICENSE                   # Licence du projet
```

---

## Prérequis

1. **Docker** (v20.10 ou supérieur)
2. **Docker Compose** (v2.0 ou supérieur)
3. Accès réseau pour télécharger les dépendances et les images Docker

---

## Installation

1. **Cloner le dépôt :**
   ```bash
   git clone https://github.com/Mushhhw/ProjetG.git
   cd ProjetG/projet
   ```

2. **Construire et démarrer les conteneurs :**
   ```bash
   docker-compose up -d --build
   ```

3. **Accéder à l'application :**
   - Ouvrez un navigateur et accédez à `http://localhost:8081`.
   - Si vous utilisez HTTPS : `https://localhost:8443`.

---

## Fonctionnalités principales

1. **Base de données MariaDB** :
   - Initialisée avec des données via `db-init/init.sql`.

2. **Serveur web PHP** :
   - Supporte les applications PHP avec Apache.
   - Inclut les certificats SSL pour les connexions sécurisées.

3. **Orchestration avec Docker Compose** :
   - Service `web` pour le serveur web.
   - Service `db` pour la base de données.

## Licence
Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
