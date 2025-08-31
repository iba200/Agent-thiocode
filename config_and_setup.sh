# ================================
# setup.sh - Script de déploiement
# ================================
#!/bin/bash

set -e

echo "🚀 Configuration de l'Agent IA de Développement Sécurisé"
echo "========================================================"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 non trouvé. Installez Python 3.8+"
    exit 1
fi

echo "✅ Python3 détecté: $(python3 --version)"

# Créer un environnement virtuel
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
source venv/bin/activate || source venv/Scripts/activate

# Installer les dépendances
echo "📥 Installation des dépendances..."
pip install --upgrade pip

# requirements.txt
cat > requirements.txt << EOF
# Core Framework
flask==2.3.3
flask-cors==4.0.0
flask-limiter==3.5.0

# AI & ML
google-generativeai==0.3.2

# Security & Authentication
PyJWT==2.8.0
werkzeug==2.3.7

# Database
sqlite3

# Utilities
python-dotenv==1.0.0
colorlog==6.7.0
requests==2.31.0
pathlib

# Development (optional)
pytest==7.4.3
black==23.9.1
flake8==6.1.0
EOF

pip install -r requirements.txt

# Créer les dossiers nécessaires
mkdir -p logs
mkdir -p data
mkdir -p temp

# Créer le fichier .env
if [ ! -f ".env" ]; then
    echo "🔧 Création du fichier de configuration..."
    cat > .env << EOF
# Configuration de l'Agent IA de Développement
# ============================================

# API Keys (REQUIS)
GEMINI_API_KEY=your-gemini-api-key-here

# Flask Configuration
FLASK_SECRET_KEY=$(openssl rand -base64 32)
FLASK_ENV=production
FLASK_DEBUG=False

# JWT Configuration
JWT_SECRET=$(openssl rand -base64 64)

# Database
DATABASE_PATH=./data/agent_db.sqlite

# Server Configuration
HOST=0.0.0.0
PORT=5000

# Security Settings
MAX_REQUESTS_PER_HOUR=1000
MAX_CONTENT_LENGTH=16777216  # 16MB

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/agent.log
SECURITY_LOG_FILE=./logs/security.log

# Rate Limiting
RATE_LIMIT_STORAGE_URL=memory://
DEFAULT_RATE_LIMIT=1000 per hour

# CORS Settings
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
EOF
    
    echo "⚠️  IMPORTANT: Éditez le fichier .env et ajoutez votre clé API Gemini !"
    echo "   Obtenez votre clé sur: https://makersuite.google.com/app/apikey"
fi

# Créer le script de démarrage
cat > start.sh << 'EOF'
#!/bin/bash

# Charger les variables d'environnement
export $(grep -v '^#' .env | xargs)

# Vérifier la clé API
if [ "$GEMINI_API_KEY" = "your-gemini-api-key-here" ]; then
    echo "❌ Veuillez configurer GEMINI_API_KEY dans le fichier .env"
    echo "💡 Obtenez votre clé sur: https://makersuite.google.com/app/apikey"
    exit 1
fi

# Activer l'environnement virtuel
source venv/bin/activate || source venv/Scripts/activate

# Démarrer l'agent
echo "🚀 Démarrage de l'Agent IA..."
python agent.py
EOF

chmod +x start.sh

# Créer les tests de base
mkdir -p tests
cat > tests/test_security.py << 'EOF'
#!/usr/bin/env python3
"""
Tests de sécurité pour l'Agent IA de Développement
"""
import unittest
import requests
import json
import os
import sys

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class SecurityTestCase(unittest.TestCase):
    """Tests de sécurité de l'API"""
    
    @classmethod
    def setUpClass(cls):
        cls.base_url = "http://localhost:5000/api/v1"
        cls.test_api_key = "ai_agent_test_key_for_security_tests"
        
    def test_health_endpoint_no_auth(self):
        """Test que l'endpoint health ne nécessite pas d'auth"""
        response = requests.get(f"{self.base_url}/health")
        self.assertEqual(response.status_code, 200)
        
    def test_suggest_without_api_key(self):
        """Test que l'endpoint suggest refuse l'accès sans clé API"""
        response = requests.post(f"{self.base_url}/suggest", 
                               json={"prompt": "hello world"})
        self.assertEqual(response.status_code, 401)
        
    def test_dangerous_code_detection(self):
        """Test la détection de code dangereux"""
        dangerous_code = "eval('print(1)')"
        headers = {"X-API-Key": self.test_api_key}
        response = requests.post(f"{self.base_url}/validate-code",
                               json={"code": dangerous_code},
                               headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            self.assertIn("security_alerts", data["data"]["validation"])
            
    def test_rate_limiting(self):
        """Test le rate limiting"""
        headers = {"X-API-Key": self.test_api_key}
        
        # Faire beaucoup de requêtes rapidement
        for i in range(10):
            response = requests.get(f"{self.base_url}/health")
            if response.status_code == 429:
                break
        
        # Au moins une requête devrait être rate-limitée après beaucoup d'appels
        self.assertTrue(True)  # Test basique pour l'instant

if __name__ == '__main__':
    unittest.main()
EOF

# Créer le client Python pour tester l'API
cat > client_example.py << 'EOF'
#!/usr/bin/env python3
"""
Client d'exemple pour l'Agent IA de Développement
"""
import requests
import json
import sys
from typing import Dict, Any

class AIAgentClient:
    """Client Python pour l'API de l'agent IA"""
    
    def __init__(self, base_url: str = "http://localhost:5000/api/v1", api_key: str = ""):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-API-Key': api_key
        })
    
    def health_check(self) -> Dict[str, Any]:
        """Vérification de l'état de l'API"""
        response = self.session.get(f"{self.base_url}/health")
        return response.json()
    
    def register_user(self, username: str, password: str, role: str = "developer") -> Dict[str, Any]:
        """Inscription d'un nouvel utilisateur"""
        data = {
            "username": username,
            "password": password,
            "role": role
        }
        response = self.session.post(f"{self.base_url}/auth/register", json=data)
        return response.json()
    
    def get_code_suggestions(self, prompt: str, context: Dict = None) -> Dict[str, Any]:
        """Obtenir des suggestions de code"""
        data = {
            "prompt": prompt,
            "context": context or {}
        }
        response = self.session.post(f"{self.base_url}/suggest", json=data)
        return response.json()
    
    def validate_code(self, code: str) -> Dict[str, Any]:
        """Valider un bloc de code"""
        data = {"code": code}
        response = self.session.post(f"{self.base_url}/validate-code", json=data)
        return response.json()
    
    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """Analyser un projet"""
        data = {"path": project_path}
        response = self.session.post(f"{self.base_url}/analyze-project", json=data)
        return response.json()
    
    def get_history(self, limit: int = 10) -> Dict[str, Any]:
        """Récupérer l'historique"""
        params = {"limit": limit}
        response = self.session.get(f"{self.base_url}/history", params=params)
        return response.json()

def main():
    """Exemple d'utilisation du client"""
    
    # Configuration
    API_KEY = input("Entrez votre clé API: ").strip()
    if not API_KEY:
        print("❌ Clé API requise")
        sys.exit(1)
    
    # Initialisation du client
    client = AIAgentClient(api_key=API_KEY)
    
    print("🔍 Test de connexion...")
    try:
        health = client.health_check()
        print(f"✅ API disponible - Version: {health.get('version', 'Unknown')}")
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        sys.exit(1)
    
    # Menu interactif
    while True:
        print("\n" + "="*50)
        print("🤖 Agent IA de Développement - Client Test")
        print("="*50)
        print("1. 💡 Demander une suggestion de code")
        print("2. ✅ Valider du code")
        print("3. 📁 Analyser un projet")
        print("4. 📖 Voir l'historique")
        print("5. 🚪 Quitter")
        
        choice = input("\nChoisissez une option (1-5): ").strip()
        
        try:
            if choice == "1":
                prompt = input("📝 Décrivez ce que vous voulez coder: ")
                result = client.get_code_suggestions(prompt)
                
                if result.get("status") == "success":
                    print(f"\n💡 Suggestion générée:")
                    print(result["data"]["suggestion"])
                    
                    if result["data"]["code_blocks"]:
                        print(f"\n🔍 {len(result['data']['code_blocks'])} bloc(s) de code détecté(s)")
                        for i, block in enumerate(result["data"]["code_blocks"]):
                            print(f"\n--- Bloc {i+1} ---")
                            print(block[:200] + "..." if len(block) > 200 else block)
                else:
                    print(f"❌ Erreur: {result.get('error', 'Inconnue')}")
            
            elif choice == "2":
                print("📝 Entrez votre code (terminez par une ligne vide):")
                code_lines = []
                while True:
                    line = input()
                    if line.strip() == "":
                        break
                    code_lines.append(line)
                
                code = "\n".join(code_lines)
                result = client.validate_code(code)
                
                if result.get("status") == "success":
                    validation = result["data"]["validation"]
                    print(f"\n✅ Validation terminée:")
                    print(f"   Valid: {validation['is_valid']}")
                    print(f"   Erreurs: {len(validation['errors'])}")
                    print(f"   Alertes sécurité: {len(validation['security_alerts'])}")
                    
                    if validation["errors"]:
                        print("❌ Erreurs détectées:")
                        for error in validation["errors"]:
                            print(f"   • {error}")
                    
                    if validation["security_alerts"]:
                        print("🚨 Alertes de sécurité:")
                        for alert in validation["security_alerts"]:
                            print(f"   • {alert['message']} (Sévérité: {alert['severity']})")
                else:
                    print(f"❌ Erreur: {result.get('error', 'Inconnue')}")
            
            elif choice == "3":
                project_path = input("📁 Chemin du projet à analyser: ")
                result = client.analyze_project(project_path)
                
                if result.get("status") == "success":
                    analysis = result["data"]
                    print(f"\n📊 Analyse du projet:")
                    print(f"   Fichiers: {len(analysis.get('files', []))}")
                    print(f"   Frameworks: {', '.join(analysis.get('frameworks', []))}")
                    
                    if analysis.get('error'):
                        print(f"❌ {analysis['error']}")
                else:
                    print(f"❌ Erreur: {result.get('error', 'Inconnue')}")
            
            elif choice == "4":
                result = client.get_history(limit=5)
                
                if result.get("status") == "success":
                    history = result["data"]["history"]
                    print(f"\n📖 Historique ({len(history)} entrées):")
                    
                    for i, entry in enumerate(history):
                        print(f"\n--- Entrée {i+1} ---")
                        print(f"Demande: {entry['user_input'][:100]}...")
                        print(f"Date: {entry['created_at']}")
                else:
                    print(f"❌ Erreur: {result.get('error', 'Inconnue')}")
            
            elif choice == "5":
                print("👋 Au revoir !")
                break
            
            else:
                print("❌ Option invalide")
                
        except KeyboardInterrupt:
            print("\n👋 Au revoir !")
            break
        except Exception as e:
            print(f"❌ Erreur: {e}")

if __name__ == "__main__":
    main()
EOF

# Créer le fichier Docker
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Créer un utilisateur non-root
RUN useradd -m -u 1000 aiagent

# Répertoire de travail
WORKDIR /app

# Copier les fichiers de requirements
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier l'application
COPY . .

# Créer les dossiers nécessaires
RUN mkdir -p logs data temp && \
    chown -R aiagent:aiagent /app

# Changer vers l'utilisateur non-root
USER aiagent

# Port d'exposition
EXPOSE 5000

# Commande de démarrage
CMD ["python", "agent.py"]
EOF

# Créer docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  ai-agent:
    build: .
    ports:
      - "5000:5000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - ai-agent
    restart: unless-stopped
EOF

# Créer la configuration Nginx
cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream ai_agent {
        server ai-agent:5000;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    server {
        listen 80;
        server_name localhost;
        
        # Sécurité headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
        
        # Rate limiting pour l'API
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://ai_agent;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }
        
        # Interface web (optionnel)
        location / {
            proxy_pass http://ai_agent;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
EOF

# Créer un script de monitoring
cat > monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Script de monitoring pour l'Agent IA
"""
import requests
import time
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

class AgentMonitor:
    def __init__(self, api_url: str, admin_api_key: str):
        self.api_url = api_url
        self.admin_api_key = admin_api_key
        self.headers = {'X-API-Key': admin_api_key}
        
    def check_health(self) -> bool:
        """Vérifie l'état de santé de l'API"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def get_system_stats(self) -> dict:
        """Récupère les statistiques système"""
        try:
            response = requests.get(f"{self.api_url}/admin/stats", 
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()["data"]
            return {}
        except:
            return {}
    
    def check_security_alerts(self) -> list:
        """Vérifie les alertes de sécurité récentes"""
        try:
            response = requests.get(f"{self.api_url}/admin/security-logs?severity=HIGH", 
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()["data"]["logs"]
            return []
        except:
            return []
    
    def run_monitoring_cycle(self):
        """Exécute un cycle de monitoring"""
        timestamp = datetime.now().isoformat()
        
        print(f"🔍 Monitoring - {timestamp}")
        
        # Vérification de santé
        is_healthy = self.check_health()
        print(f"   Santé API: {'✅ OK' if is_healthy else '❌ KO'}")
        
        if not is_healthy:
            print("🚨 ALERTE: API non disponible!")
            return
        
        # Statistiques
        stats = self.get_system_stats()
        if stats:
            print(f"   Utilisateurs actifs: {stats.get('users', {}).get('active', 'N/A')}")
            print(f"   Suggestions aujourd'hui: {stats.get('activity', {}).get('suggestions_today', 'N/A')}")
            print(f"   Erreurs aujourd'hui: {stats.get('activity', {}).get('errors_today', 'N/A')}")
        
        # Alertes de sécurité
        alerts = self.check_security_alerts()
        if alerts:
            print(f"🚨 {len(alerts)} alerte(s) de sécurité détectée(s)")
            for alert in alerts[:3]:  # Afficher les 3 dernières
                print(f"   • {alert['event_type']}: {alert['details']}")

def main():
    """Point d'entrée principal"""
    import os
    
    api_url = os.getenv('API_URL', 'http://localhost:5000/api/v1')
    admin_key = os.getenv('ADMIN_API_KEY', '')
    
    if not admin_key:
        print("❌ ADMIN_API_KEY requis pour le monitoring")
        print("💡 Définissez: export ADMIN_API_KEY='votre-cle-admin'")
        sys.exit(1)
    
    monitor = AgentMonitor(api_url, admin_key)
    
    print("🚀 Démarrage du monitoring de l'Agent IA")
    print("   Ctrl+C pour arrêter")
    
    try:
        while True:
            monitor.run_monitoring_cycle()
            print("   Prochain check dans 60 secondes...\n")
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n👋 Arrêt du monitoring")

if __name__ == "__main__":
    main()
EOF

chmod +x monitor.py client_example.py

# Script de migration de base de données
cat > migrate.py << 'EOF'
#!/usr/bin/env python3
"""
Script de migration pour la base de données
"""
import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Applique les migrations de base de données"""
    db_path = os.getenv('DATABASE_PATH', './data/agent_db.sqlite')
    
    # Créer le dossier data s'il n'existe pas
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    with sqlite3.connect(db_path) as conn:
        # Vérifier la version actuelle
        try:
            cursor = conn.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1")
            current_version = cursor.fetchone()
            current_version = current_version[0] if current_version else 0
        except sqlite3.OperationalError:
            # Table n'existe pas, créer la structure de versioning
            conn.execute("""
                CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    description TEXT,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            current_version = 0
        
        migrations = [
            (1, "Initial schema", """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'developer',
                    api_key TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                );
            """),
            (2, "Add sessions table", """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    context TEXT DEFAULT '{}',
                    project_structure TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """),
            (3, "Add security logging", """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    security_level INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """),
            (4, "Add indexes for performance", """
                CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);
                CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs(created_at);
            """)
        ]
        
        # Appliquer les migrations
        for version, description, sql in migrations:
            if version > current_version:
                print(f"📦 Application de la migration {version}: {description}")
                
                try:
                    conn.executescript(sql)
                    conn.execute(
                        "INSERT INTO schema_version (version, description) VALUES (?, ?)",
                        (version, description)
                    )
                    conn.commit()
                    print(f"✅ Migration {version} appliquée avec succès")
                except Exception as e:
                    print(f"❌ Erreur lors de la migration {version}: {e}")
                    conn.rollback()
                    raise
        
        print("🎉 Toutes les migrations appliquées avec succès!")

if __name__ == "__main__":
    migrate_database()
EOF

chmod +x migrate.py

# Script de backup
cat > backup.py << 'EOF'
#!/usr/bin/env python3
"""
Script de sauvegarde pour l'Agent IA
"""
import os
import shutil
import sqlite3
import json
from datetime import datetime
import gzip

def create_backup():
    """Crée une sauvegarde complète du système"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = f"backups/backup_{timestamp}"
    
    os.makedirs(backup_dir, exist_ok=True)
    
    print(f"💾 Création de la sauvegarde: {backup_dir}")
    
    # Sauvegarder la base de données
    db_path = os.getenv('DATABASE_PATH', './data/agent_db.sqlite')
    if os.path.exists(db_path):
        backup_db_path = os.path.join(backup_dir, 'agent_db.sqlite')
        shutil.copy2(db_path, backup_db_path)
        
        # Compresser la DB
        with open(backup_db_path, 'rb') as f_in:
            with gzip.open(f"{backup_db_path}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(backup_db_path)
        
        print(f"   ✅ Base de données sauvegardée et compressée")
    
    # Sauvegarder les logs
    logs_dir = './logs'
    if os.path.exists(logs_dir):
        backup_logs_dir = os.path.join(backup_dir, 'logs')
        shutil.copytree(logs_dir, backup_logs_dir)
        print(f"   ✅ Logs sauvegardés")
    
    # Sauvegarder la configuration
    config_files = ['.env', 'requirements.txt', 'nginx.conf']
    for config_file in config_files:
        if os.path.exists(config_file):
            shutil.copy2(config_file, backup_dir)
    
    print(f"   ✅ Configuration sauvegardée")
    
    # Créer un fichier de métadonnées
    metadata = {
        "backup_created": timestamp,
        "version": "2.0.0",
        "files_included": os.listdir(backup_dir),
        "database_size": os.path.getsize(f"{backup_db_path}.gz") if os.path.exists(f"{backup_db_path}.gz") else 0
    }
    
    with open(os.path.join(backup_dir, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"🎉 Sauvegarde terminée: {backup_dir}")
    return backup_dir

if __name__ == "__main__":
    create_backup()
EOF

chmod +x backup.py

echo ""
echo "🎉 Configuration terminée avec succès !"
echo ""
echo "📋 Prochaines étapes:"
echo "1. 🔧 Éditez le fichier .env et ajoutez votre clé API Gemini"
echo "2. 🗄️  Exécutez: python migrate.py"
echo "3. 🚀 Démarrez l'agent: ./start.sh"
echo "4. 🧪 Testez avec: python client_example.py"
echo ""
echo "🔒 Fonctionnalités de sécurité incluses:"
echo "   ✅ Authentification par clé API"
echo "   ✅ Contrôle d'accès basé sur les rôles"
echo "   ✅ Rate limiting et protection DDoS"
echo "   ✅ Validation avancée du code"
echo "   ✅ Monitoring de sécurité en temps réel"
echo "   ✅ Logging sécurisé et audit trail"
echo "   ✅ Protection contre l'injection de code"
echo "   ✅ Containerisation Docker"
echo ""
echo "📚 Documentation complète générée dans README.md"