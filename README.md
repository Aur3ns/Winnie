<h1 align="center">Project Winnie</h1>

### Honeypot SSH avec Téléchargement d'URL

### 🛠 Prérequis

- **Installer Python :** Assure-toi d'avoir [Python](https://www.python.org/downloads/) installé sur ton système.
  
- **Installer PostgreSQL :** Télécharge et installe PostgreSQL depuis [le site officiel de PostgreSQL](https://www.postgresql.org/download/).
  
- **Installer les dépendances Python :**
  - Dans le répertoire du script, exécute la commande suivante pour installer les dépendances nécessaires :

    ```bash
    pip install paramiko requests aiopg uvicorn rapidjson
    ```

###  Configuration de PostgreSQL

1. **Créer une base de données PostgreSQL** :
   - Utilise psql ou pgAdmin pour exécuter ces commandes SQL et créer la base de données et l'utilisateur :

     ```sql
     CREATE DATABASE mydatabase;
     CREATE USER user WITH PASSWORD 'password';
     ALTER ROLE user SET client_encoding TO 'utf8';
     ALTER ROLE user SET default_transaction_isolation TO 'read committed';
     ALTER ROLE user SET timezone TO 'UTC';
     GRANT ALL PRIVILEGES ON DATABASE mydatabase TO user;
     ```

2. **Mettre à jour les informations de connexion dans le script** :
   - Ouvre le script Python et mets à jour la variable `PG_CONFIG` :

     ```python
     PG_CONFIG = "host=localhost port=5432 dbname=mydatabase user=user password=password"
     ```

### Configuration de Redis

- **Installer et configurer Redis (si nécessaire)** : Télécharge et installe Redis depuis le site officiel de Redis. Démarre le serveur Redis.

### Gestion des clés SSH

- **Générer une paire de clés SSH** : Génère une paire de clés avec la commande :

    ```bash
    ssh-keygen -t rsa -f server.key
    ```

### Build

- **Construire l'image Docker** :

    ```bash
    docker build -t winnie .
    ```

### 🚀 Run

- **Lancer le conteneur Docker** :

    ```bash
    docker run -v ${PWD}:/usr/src/app -p 2222:2222 basic_honeypot
    ```

### Configuration de l'environnement

- **Configurer les variables d'environnement pour Redis (si nécessaire)** : Dans le terminal, exécute les commandes suivantes :

    ```bash
    export REDIS_HOST=127.0.0.1
    export REDIS_PORT=6379
    export REDIS_PASSWORD=ton_mot_de_passe_redis
    ```

  Ou dans PowerShell sur Windows :

    ```powershell
    $env:REDIS_HOST="127.0.0.1"
    $env:REDIS_PORT="6379"
    $env:REDIS_PASSWORD="ton_mot_de_passe_redis"
    ```

### Exécution du script

- **Exécuter le script** : Dans le terminal, place-toi dans le répertoire du script et lance-le :

    ```bash
    python nom_du_script.py
    ```

- **Vérifier le fonctionnement** : Consulte les journaux (`combined_honeypot.log`) pour des informations sur les connexions et les activités.

- **Tester avec un client SSH** : Utilise un client SSH pour te connecter au serveur avec l'adresse IP et le port spécifiés dans le script.

- **Envoyer des URL à télécharger** : Ajoute des URL à la file d'attente Redis pour tester la fonction de téléchargement d'URL.

- **Arrêter le script** : Utilise `Ctrl + C` dans le terminal où il est en cours d'exécution.
