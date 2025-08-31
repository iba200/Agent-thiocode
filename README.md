# 🤖 Agent IA de Développement Sécurisé v2.0

Un agent IA intelligent et sécurisé pour l'assistance au développement, utilisant Gemini Flash 2 et Flask. Conçu pour éviter tous les problèmes des agents existants comme Copilot, Cursor, et Tabnine.

## 🎯 Problèmes Résolus des Autres Agents

### ❌ Problèmes des agents existants :
- **Hallucinations** : Suggestions de bibliothèques inexistantes
- **Code non-testé** : Syntaxe incorrecte et erreurs de runtime
- **Manque de contexte** : Suggestions hors sujet
- **Sécurité faible** : Pas de validation des suggestions dangereuses
- **Pas de persistance** : Perte du contexte entre sessions
- **Accès non contrôlé** : Pas d'authentification ni de rôles

### ✅ Solutions implémentées :
- **Validation AST** : Vérification syntaxique systématique
- **Analyse contextuelle** : Compréhension du projet complet
- **Sécurité avancée** : Détection de code dangereux
- **Authentification** : Contrôle d'accès par clé API
- **Rôles utilisateur** : Permissions granulaires
- **Monitoring** : Surveillance en temps réel
- **Persistance** : Sauvegarde du contexte et historique

## 🚀 Installation Rapide

```bash
# 1. Cloner et configurer
git clone <votre-repo>
cd ai-dev-agent

# 2. Exécuter le script de setup
chmod +x setup.sh
./setup.sh

# 3. Configurer votre clé API Gemini
nano .env  # Ajouter GEMINI_API_KEY=votre-cle-ici

# 4. Initialiser la base de données
python migrate.py

# 5. Démarrer l'agent
./start.sh
```

## 🔧 Configuration Détaillée

### Variables d'Environnement (.env)

```bash
# API Keys (OBLIGATOIRE)
GEMINI_API_KEY=your-gemini-api-key-here

# Flask Configuration
FLASK_SECRET_KEY=votre-cle-secrete-flask
FLASK_ENV=production
FLASK_DEBUG=False

# JWT Configuration
JWT_SECRET=votre-cle-jwt-secrete

# Database
DATABASE_PATH=./data/agent_db.sqlite

# Server
HOST=0.0.0.0
PORT=5000

# Security
MAX_REQUESTS_PER_HOUR=1000
MAX_CONTENT_LENGTH=16777216  # 16MB

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/agent.log
```

### Obtenir une Clé API Gemini

1. Visitez [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Connectez-vous avec votre compte Google
3. Créez une nouvelle clé API
4. Copiez la clé dans votre fichier `.env`

## 🏗️ Architecture du Système

```
📦 Agent IA de Développement
├── 🧠 SmartCodeAgent (IA Principal)
│   ├── Analyse AST avancée
│   ├── Validation de sécurité
│   ├── Génération de prompts intelligents
│   └── Suggestions contextuelles
├── 🔒 SecurityManager (Sécurité)
│   ├── Authentification par clé API
│   ├── Contrôle d'accès par rôles
│   ├── Rate limiting
│   └── Monitoring des menaces
├── 🗄️ DatabaseManager (Persistance)
│   ├── Gestion des utilisateurs
│   ├── Sessions et contexte
│   ├── Historique des interactions
│   └── Logs de sécurité
└── 🌐 Flask API (Interface REST)
    ├──