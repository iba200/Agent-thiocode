# 🤖 Agent IA de Développement - Guide Complet

## 📋 Vue d'ensemble

L'Agent IA de Développement est une solution complète et sécurisée qui utilise Gemini Flash 2 pour aider les développeurs dans leurs projets. Il résout les problèmes courants des agents existants (Copilot, Cursor, Tabnine) en apportant :

### ✅ **Avantages par rapport aux autres agents**

| Problème des autres agents | Notre solution |
|----------------------------|----------------|
| Hallucinations de code | Validation AST systématique |
| Suggestions hors contexte | Analyse du projet complète |
| Pas de contrôle de sécurité | Validation de sécurité avancée |
| Pas d'authentification | Système complet avec rôles |
| Pas de mémoire de session | Contexte persistant |
| Interface limitée | Interface web complète |

## 🚀 Installation Rapide

### Méthode 1: Installation automatique
```bash
# Télécharger tous les fichiers
# Puis exécuter :
chmod +x install.sh
./install.sh
```

### Méthode 2: Installation manuelle
```bash
# 1. Créer l'environnement
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer l'environnement
cp .env.example .env
# Éditer .env et ajouter GEMINI_API_KEY

# 4. Démarrer l'agent
python agent.py
```

## 🔑 Configuration

### Variables d'environnement requises (.env)
```bash
# REQUIS
GEMINI_API_KEY=your-gemini-api-key-here

# Optionnel (valeurs par défaut fournies)
FLASK_SECRET_KEY=auto-generated
JWT_SECRET=auto-generated
DATABASE_PATH=./data/agent_db.sqlite
HOST=0.0.0.0
PORT=5000
CORS_ORIGINS=http://localhost:3000
```

### Obtenir une clé API Gemini
1. Aller sur [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Créer une nouvelle clé API
3. Copier la clé dans le fichier `.env`

## 🏗️ Architecture du Système

```
Agent IA de Développement/
├── 🧠 Core/
│   ├── agent.py              # Agent principal avec Gemini
│   ├── config.py             # Configuration centralisée
│   └── utils.py              # Utilitaires de sécurité
├── 🔐 Sécurité/
│   ├── Authentification API  # Clés API sécurisées
│   ├── Contrôle d'accès      # Rôles utilisateur
│   ├── Validation de code    # Anti-patterns dangereux
│   └── Rate limiting         # Protection contre abus
├── 💾 Base de données/
│   ├── Utilisateurs          # Gestion des comptes
│   ├── Sessions              # Contexte persistant
│   ├── Historique            # Suivi des interactions
│   └── Logs de sécurité      # Monitoring
├── 🌐 Interfaces/
│   ├── API REST             # Endpoints sécurisés
│   ├── Interface Web        # GUI moderne
│   ├── CLI                  # Ligne de commande
│   └── Client Python       # Intégration programmatique
└── 🚀 Déploiement/
    ├── Docker               # Containerisation
    ├── Tests automatisés    # Qualité du code
    └── Scripts de prod      # Déploiement facile
```

## 🔗 API REST - Endpoints

### Authentification
- `GET /api/v1/health` - État de l'API (public)
- `POST /api/v1/auth/register` - Créer un compte

### Développement (Auth requise)
- `POST /api/v1/suggest` - Suggestions de code
- `POST /api/v1/validate-code` - Validation de code
- `POST /api/v1/analyze-project` - Analyse de projet
- `GET/POST/DELETE /api/v1/session` - Gestion des sessions
- `GET /api/v1/history` - Historique utilisateur

### Administration (Admin uniquement)
- `GET /api/v1/admin/users` - Liste des utilisateurs
- `GET /api/v1/admin/security-logs` - Logs de sécurité
- `GET /api/v1/admin/stats` - Statistiques système

## 👥 Rôles Utilisateur

### 👀 Viewer
- Lecture seule du code
- Validation basique
- Pas de suggestions de modification

### 👨‍💻 Developer (par défaut)
- Suggestions de code complètes
- Validation avancée
- Analyse de projet
- Historique personnel

### 👨‍💼 Admin
- Toutes les fonctions Developer
- Gestion des utilisateurs
- Logs de sécurité
- Statistiques système

## 🛡️ Sécurité Avancée

### Authentification
```python
# Utilisation avec clé API
headers = {
    'X-API-Key': 'votre_cle_api_ici',
    'Content-Type': 'application/json'
}
```

### Validation de Code
Le système détecte automatiquement :
- ❌ `eval()`, `exec()`, `__import__()`
- ❌ Accès système avec `subprocess`, `os.system`
- ❌ Écriture de fichiers non sécurisée
- ❌ Imports dangereux
- ✅ Code sécurisé avec score 0-100

### Rate Limiting
- 1000 requêtes/heure par IP par défaut
- Personnalisable selon le rôle
- Protection anti-DDoS

## 💻 Utilisation - Exemples

### 1. Interface Web
```bash
# Démarrer l'agent
python agent.py

# Ouvrir dans le navigateur
http://localhost:5000/
```

### 2. Client Python
```python
from client_example import AIAgentClient

client = AIAgentClient(api_key="votre_cle")

# Suggestion de code
result = client.suggest_code(
    "Créer une API REST pour gérer des utilisateurs",
    context={"language": "python", "framework": "flask"}
)

print(result['data']['suggestion'])
```

### 3. Interface CLI
```bash
# Suggestions interactives
python cli.py suggest

# Validation de fichier
python cli.py validate --code-file mon_script.py

# Créer un utilisateur
python cli.py register
```

### 4. cURL (API directe)
```bash
# Créer un utilisateur
curl -X POST http://localhost:5000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "dev1", "password": "securepass123"}'

# Suggestion de code
curl -X POST http://localhost:5000/api/v1/suggest \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Fonction pour valider email", "context": {"language": "python"}}'
```

## 🧪 Tests et Qualité

### Tests automatisés
```bash
# Tests complets
python -m pytest tests/ -v

# Tests de sécurité uniquement
python tests/test_security.py

# Test d'intégration
python test_complete.py
```

### Validation continue
```bash
# Linter de code
flake8 *.py

# Formatage automatique
black *.py

# Vérification des vulnérabilités
bandit -r *.py
```

## 🐳 Déploiement Production

### Docker
```bash
# Build de l'image
docker build -t ai-agent .

# Démarrage avec docker-compose
docker-compose up -d
```

### Serveur dédié
```bash
# Avec Gunicorn (production)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 agent:app

# Avec proxy Nginx
# Configuration fournie dans nginx.conf
```

### Variables d'environnement production
```bash
FLASK_ENV=production
FLASK_DEBUG=False
DATABASE_PATH=/data/agent_db.sqlite
LOG_LEVEL=WARNING
MAX_REQUESTS_PER_HOUR=2000
```

## 📊 Monitoring et Maintenance

### Logs disponibles
```bash
# Logs de l'application
tail -f logs/agent.log

# Logs de sécurité
tail -f logs/security.log

# Statistiques en temps réel
curl http://localhost:5000/api/v1/admin/stats \
  -H "X-API-Key: ADMIN_KEY"
```

### Sauvegarde de données
```bash
# Sauvegarde automatique de la DB
sqlite3 data/agent_db.sqlite .dump > backup.sql

# Restauration
sqlite3 data/agent_db.sqlite < backup.sql
```

## ⚡ Performance et Optimisation

### Recommandations matériel
- **Minimum** : 2 CPU cores, 4GB RAM, 10GB stockage
- **Recommandé** : 4 CPU cores, 8GB RAM, 50GB SSD
- **Production** : 8+ CPU cores, 16GB+ RAM, SSD rapide

### Optimisations
```python
# Cache Redis (optionnel)
pip install redis
export CACHE_URL=redis://localhost:6379

# Base de données PostgreSQL (optionnel)
pip install psycopg2
export DATABASE_URL=postgresql://user:pass@localhost/aiagent
```

## 🔧 Dépannage

### Problèmes courants

#### 1. Erreur clé API Gemini
```
❌ GEMINI_API_KEY non définie
```
**Solution** : Vérifier le fichier `.env` et la clé API

#### 2. Port déjà utilisé
```
❌ Address already in use: Port 5000
```
**Solution** : 
```bash
export PORT=8000
python agent.py
```

#### 3. Erreur de permissions base de données
```
❌ Permission denied: agent_db.sqlite
```
**Solution** :
```bash
mkdir -p data
chmod 755 data
```

#### 4. Rate limit dépassé
```
❌ Rate limit exceeded
```
**Solution** : Attendre ou configurer `MAX_REQUESTS_PER_HOUR`

### Support et Debug
```python
# Mode debug (développement uniquement)
export FLASK_DEBUG=True
export LOG_LEVEL=DEBUG

# Tests de connectivité
python -c "
from client_example import AIAgentClient
client = AIAgentClient()
print(client.health_check())
"
```

## 📈 Roadmap et Évolutions

### Version actuelle (2.0)
- ✅ Agent Gemini Flash 2 intégré
- ✅ Sécurité avancée
- ✅ Interface web moderne
- ✅ API REST complète
- ✅ Multi-utilisateur avec rôles

### Prochaines versions
- 🔜 Support GPT-4, Claude
- 🔜 Intégration VS Code
- 🔜 Templates de code
- 🔜 Collaboration en équipe
- 🔜 Intégration CI/CD
- 🔜 Analytics avancées

## 📞 Support et Contribution

### Signaler un bug
1. Vérifier les logs : `logs/agent.log`
2. Tester avec la dernière version
3. Créer un issue avec :
   - Version Python/OS
   - Message d'erreur complet
   - Étapes de reproduction

### Contribuer
1. Fork du projet
2. Créer une branche feature
3. Tests ajoutés/mis à jour
4. Pull request avec description

### Licence
MIT License - Utilisation libre pour projets personnels et commerciaux

---

## 🎯 Résumé Rapide

**Votre Agent IA est prêt !** Il combine :

- 🧠 **Intelligence** : Gemini Flash 2 pour des suggestions précises
- 🔐 **Sécurité** : Validation, authentification, contrôle d'accès
- 🚀 **Performance** : API optimisée, cache, rate limiting
- 🎨 **Interface** : Web moderne, CLI, client Python
- 📊 **Monitoring** : Logs, stats, alertes de sécurité
- 🐳 **Production** : Docker, scripts de déploiement

**Commandes essentielles** :
```bash
./install.sh           # Installation complète
python agent.py        # Démarrer l'agent
http://localhost:5000  # Interface web
python cli.py --help   # Interface CLI
```

**Votre agent évite tous les problèmes des agents existants et apporte bien plus !** 🎉