# Protec Contrôle - Application VGP

Application web de gestion des Vérifications Générales Périodiques (VGP) pour les appareils de levage, conforme au document INRS ED 6339.

## Lancement local

```bash
npm install
npm start
```

Ouvrir **http://localhost:3000**

## Comptes de test

| Rôle  | Email             | Mot de passe |
|-------|-------------------|--------------|
| Admin | test@protec.com   | Test@2024!   |
| User  | user@protec.com   | Test@2024!   |

---

## Déploiement sur Railway

### 1. Préparer le repo Git

```bash
git init
git add .
git commit -m "Initial commit"
```

Pousser sur GitHub (ou GitLab).

### 2. Créer le projet Railway

1. Aller sur [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**
2. Sélectionner le repo
3. Railway détecte automatiquement Node.js et lance `npm install` + `npm start`

### 3. Ajouter un volume (persistance de la BDD)

**Important** : sans volume, la base SQLite est perdue à chaque redéploiement.

1. Dans le service → **Add Volume**
2. Mount Path : `/data`
3. Puis dans **Variables**, ajouter :

```
DATABASE_PATH=/data/protec.db
UPLOAD_DIR=/data/uploads
JWT_SECRET=votre-secret-securise-ici
```

### 4. Variables d'environnement

| Variable        | Requis | Description                              | Défaut                  |
|-----------------|--------|------------------------------------------|-------------------------|
| `PORT`          | Non    | Port du serveur (géré auto par Railway)  | `3000`                  |
| `JWT_SECRET`    | **Oui**| Clé secrète pour les tokens JWT          | *(valeur par défaut)*   |
| `DATABASE_PATH` | **Oui**| Chemin de la base SQLite sur le volume   | `./protec.db`           |
| `UPLOAD_DIR`    | Non    | Dossier des fichiers uploadés            | `./uploads`             |

### 5. Générer un domaine

Dans le service → **Settings** → **Networking** → **Generate Domain**

L'application sera accessible sur `https://votre-app.up.railway.app`

### Résumé rapide

```
Railway New Project → GitHub repo
  ↓
Add Volume → mount /data
  ↓
Variables :
  DATABASE_PATH = /data/protec.db
  UPLOAD_DIR    = /data/uploads
  JWT_SECRET    = un-vrai-secret
  ↓
Generate Domain → c'est en ligne !
```

---

## Fonctionnalités

- **Authentification sécurisée** : JWT, mots de passe hashés (bcrypt), règles de complexité
- **Dashboard** : 4 tuiles cliquables (À planifier, À faire, En cours, Terminé)
- **Gestion des clients** : CRUD, recherche en direct par entreprise
- **Gestion des machines** : par client, avec types d'équipements INRS
- **Formulaire de contrôle complet** basé sur INRS ED 6339 :
  - Examen d'adéquation (Art. 5-I)
  - Examen de montage (Art. 5-II)
  - État de conservation (Art. 9) — 8 points de contrôle
  - Essais de fonctionnement (Art. 6)
  - Épreuves statique/dynamique (Art. 10-11)
  - Conclusion avec avis général
- **Historique des contrôles** par machine
- **Rapport VGP** visualisable et imprimable (PDF via navigateur)
- **Profil utilisateur** : nom, prénom, signature électronique (dessin canvas)
- **Administration** : invitation et suppression d'utilisateurs (admin uniquement)
- **Responsive** : sidebar, mobile-friendly
- **Health check** : `GET /api/health`
- **Données de démo** : 3 clients, 7 machines, 10 contrôles pré-remplis

## Stack technique

- **Backend** : Node.js + Express + SQLite (better-sqlite3)
- **Frontend** : React 18 (CDN) + Babel + Font Awesome
- **Auth** : JWT + bcryptjs
- **Upload** : Multer

## Structure

```
protec-controle/
├── package.json
├── railway.json       # Config Railway (healthcheck, deploy)
├── .gitignore
├── server.js          # Backend complet (API REST, BDD, auth)
└── public/
    └── index.html     # Frontend SPA React
```
