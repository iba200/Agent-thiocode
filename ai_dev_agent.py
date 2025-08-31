import os
import json
import traceback
import logging
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import google.generativeai as genai
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash
import re
import ast
import subprocess
import tempfile
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager
import time
from dataclasses import dataclass
from enum import Enum
import uuid
from flask import render_template

# Configuration du logging avancé
class ColoredFormatter(logging.Formatter):
    """Formateur coloré pour les logs"""
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Vert
        'WARNING': '\033[33m',  # Jaune
        'ERROR': '\033[31m',    # Rouge
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('agent.log')
    ]
)

for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.setFormatter(ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logger = logging.getLogger(__name__)

# Énumérations
class UserRole(Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"

class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: UserRole
    api_key: str
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True

class DatabaseManager:
    """Gestionnaire de base de données SQLite thread-safe"""
    
    def __init__(self, db_path: str = "agent_db.sqlite"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions DB"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    def init_db(self):
        """Initialise les tables de la base de données"""
        with self.get_connection() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    api_key TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                );
                
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    context TEXT DEFAULT '{}',
                    project_structure TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
                
                CREATE TABLE IF NOT EXISTS code_history (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    user_input TEXT NOT NULL,
                    ai_response TEXT NOT NULL,
                    validation_result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions (id)
                );
                
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
                
                CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);
            ''')
            conn.commit()
    
    def create_user(self, username: str, password: str, role: UserRole = UserRole.DEVELOPER) -> User:
        """Crée un nouvel utilisateur"""
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)
        api_key = self.generate_api_key()
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO users (id, username, password_hash, role, api_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, password_hash, role.value, api_key))
            conn.commit()
        
        return User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            api_key=api_key,
            created_at=datetime.now()
        )
    
    def get_user_by_api_key(self, api_key: str) -> Optional[User]:
        """Récupère un utilisateur par sa clé API"""
        with self.get_connection() as conn:
            row = conn.execute('''
                SELECT * FROM users WHERE api_key = ? AND is_active = 1
            ''', (api_key,)).fetchone()
            
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    role=UserRole(row['role']),
                    api_key=row['api_key'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                    is_active=bool(row['is_active'])
                )
        return None
    
    def generate_api_key(self) -> str:
        """Génère une clé API sécurisée"""
        return f"ai_agent_{secrets.token_urlsafe(32)}"
    
    def log_security_event(self, user_id: Optional[str], event_type: str, 
                          ip_address: str, user_agent: str, details: str, 
                          security_level: SecurityLevel = SecurityLevel.LOW):
        """Enregistre un événement de sécurité"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO security_logs 
                (id, user_id, event_type, ip_address, user_agent, details, security_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                user_id,
                event_type,
                ip_address,
                user_agent,
                details,
                security_level.value
            ))
            conn.commit()

class SecurityManager:
    """Gestionnaire de sécurité avancé"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.jwt_secret = os.getenv('JWT_SECRET', secrets.token_urlsafe(64))
        self.failed_attempts = {}  # IP -> count
        self.blocked_ips = set()
        
    def authenticate_api_key(self, api_key: str, request_info: dict) -> Optional[User]:
        """Authentifie une clé API"""
        if not api_key or not api_key.startswith('ai_agent_'):
            self.db.log_security_event(
                None, "INVALID_API_KEY_FORMAT", 
                request_info.get('ip', ''), 
                request_info.get('user_agent', ''),
                f"Invalid API key format: {api_key[:20]}...",
                SecurityLevel.MEDIUM
            )
            return None
        
        user = self.db.get_user_by_api_key(api_key)
        if user:
            self.db.log_security_event(
                user.id, "API_KEY_SUCCESS",
                request_info.get('ip', ''),
                request_info.get('user_agent', ''),
                "Successful API key authentication",
                SecurityLevel.LOW
            )
            return user
        else:
            self.db.log_security_event(
                None, "API_KEY_FAILED",
                request_info.get('ip', ''),
                request_info.get('user_agent', ''),
                f"Failed API key: {api_key[:20]}...",
                SecurityLevel.HIGH
            )
            return None
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Vérifie si une IP est bloquée"""
        return ip in self.blocked_ips
    
    def rate_limit_check(self, ip: str, endpoint: str) -> bool:
        """Vérification du rate limiting basique"""
        # Implémentation basique - peut être améliorée avec Redis
        current_time = time.time()
        key = f"{ip}:{endpoint}"
        
        if key not in self.failed_attempts:
            self.failed_attempts[key] = []
        
        # Nettoyer les anciennes tentatives (dernière minute)
        self.failed_attempts[key] = [
            timestamp for timestamp in self.failed_attempts[key] 
            if current_time - timestamp < 60
        ]
        
        # Vérifier la limite (max 100 requêtes par minute)
        if len(self.failed_attempts[key]) >= 100:
            return False
        
        self.failed_attempts[key].append(current_time)
        return True

class SmartCodeAgent:
    """Agent IA intelligent et sécurisé pour le développement"""
    
    def __init__(self, gemini_api_key: str, db_manager: DatabaseManager):
        # Configuration Gemini
        genai.configure(api_key=gemini_api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        # Gestionnaires
        self.db = db_manager
        self.security = SecurityManager(db_manager)
        
        # Configuration de sécurité pour l'IA
        self.safe_imports = {
            'os', 'sys', 'json', 'datetime', 'typing', 'pathlib', 're',
            'math', 'random', 'collections', 'itertools', 'functools',
            'flask', 'django', 'fastapi', 'pandas', 'numpy', 'requests'
        }
        
        self.dangerous_patterns = [
            (r'eval\s*\(', 'eval() usage detected'),
            (r'exec\s*\(', 'exec() usage detected'),
            (r'__import__\s*\(', '__import__ usage detected'),
            (r'subprocess\.(?:call|run|Popen)', 'subprocess execution detected'),
            (r'os\.system\s*\(', 'os.system() usage detected'),
            (r'open\s*\([^)]*["\']w|a["\']', 'file write access detected')
        ]

    def generate_comprehensive_prompt(self, user_request: str, context: Dict[str, Any], 
                                    user_role: UserRole) -> str:
        """Génère un prompt complet basé sur le rôle utilisateur"""
        
        role_restrictions = {
            UserRole.VIEWER: "Tu ne peux que lire et analyser le code, pas le modifier.",
            UserRole.DEVELOPER: "Tu peux suggérer et modifier du code selon les bonnes pratiques.",
            UserRole.ADMIN: "Tu as accès complet pour toutes les opérations de développement."
        }
        
        base_prompt = f"""
Tu es un assistant de développement expert et sécurisé.

🔒 RESTRICTIONS DE SÉCURITÉ:
- JAMAIS de code utilisant eval(), exec(), __import__(), subprocess
- JAMAIS d'accès système ou fichiers critiques
- TOUJOURS valider la syntaxe avant suggestion
- TOUJOURS expliquer les risques potentiels

👤 RÔLE UTILISATEUR: {user_role.value}
{role_restrictions.get(user_role, "")}

❌ ANTI-PATTERNS À ÉVITER:
- Hallucinations de bibliothèques inexistantes
- Code non testé ou syntaxiquement incorrect
- Suggestions hors contexte du projet
- Réponses génériques sans analyse spécifique
- Oubli des dépendances et imports
- Code incomplet ou non-fonctionnel
- Vulnérabilités de sécurité

✅ RÈGLES STRICTES:
1. Analyser le contexte existant AVANT de répondre
2. Proposer UNIQUEMENT du code testé et sécurisé
3. Vérifier la compatibilité avec les imports existants
4. Donner des explications claires et détaillées
5. Proposer des solutions incrémentales et sûres
6. Anticiper et signaler les erreurs potentielles
7. Respecter les bonnes pratiques de sécurité

CONTEXTE DU PROJET:
{json.dumps(context, indent=2)}

DEMANDE UTILISATEUR:
{user_request}

RÉPONSE ATTENDUE:
1. Analyse du contexte fourni
2. Identification des dépendances nécessaires
3. Solution complète, testée et sécurisée
4. Explication des choix techniques
5. Signalement des risques potentiels
6. Tests de validation suggérés
"""
        return base_prompt

    def advanced_code_analysis(self, code: str, file_path: str = "") -> Dict[str, Any]:
        """Analyse avancée du code avec détection de sécurité"""
        try:
            tree = ast.parse(code)
            
            analysis = {
                "imports": [],
                "functions": [],
                "classes": [],
                "variables": [],
                "dependencies": [],
                "security_issues": [],
                "complexity_score": 0,
                "syntax_valid": True,
                "file_path": file_path,
                "lines_of_code": len(code.split('\n')),
                "estimated_execution_time": "< 1ms"
            }
            
            # Analyse AST détaillée
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        import_name = alias.name
                        analysis["imports"].append(import_name)
                        if import_name not in self.safe_imports:
                            analysis["security_issues"].append({
                                "type": "unsafe_import",
                                "detail": f"Import potentiellement dangereux: {import_name}",
                                "line": node.lineno
                            })
                
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        full_import = f"{module}.{alias.name}" if module else alias.name
                        analysis["imports"].append(full_import)
                
                elif isinstance(node, ast.FunctionDef):
                    func_info = {
                        "name": node.name,
                        "args": [arg.arg for arg in node.args.args],
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node),
                        "complexity": self._calculate_complexity(node)
                    }
                    analysis["functions"].append(func_info)
                    analysis["complexity_score"] += func_info["complexity"]
                
                elif isinstance(node, ast.ClassDef):
                    class_info = {
                        "name": node.name,
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node),
                        "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                    }
                    analysis["classes"].append(class_info)
                
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            analysis["variables"].append({
                                "name": target.id,
                                "line": node.lineno,
                                "type": self._infer_type(node.value)
                            })
            
            # Détection de patterns dangereux
            for pattern, description in self.dangerous_patterns:
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_num = code[:match.start()].count('\n') + 1
                    analysis["security_issues"].append({
                        "type": "dangerous_pattern",
                        "detail": description,
                        "line": line_num,
                        "code": match.group()
                    })
            
            return analysis
            
        except SyntaxError as e:
            return {
                "syntax_valid": False,
                "error": str(e),
                "line": e.lineno,
                "file_path": file_path,
                "security_issues": [{"type": "syntax_error", "detail": str(e)}]
            }
    
    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calcule la complexité cyclomatique d'une fonction"""
        complexity = 1  # Complexité de base
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
        
        return complexity
    
    def _infer_type(self, node) -> str:
        """Infère le type d'une variable"""
        if isinstance(node, ast.Constant):
            return type(node.value).__name__
        elif isinstance(node, ast.List):
            return "list"
        elif isinstance(node, ast.Dict):
            return "dict"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"result_of_{node.func.id}"
        return "unknown"
    
    def comprehensive_validation(self, code: str, user_role: UserRole) -> Dict[str, Any]:
        """Validation complète avec vérifications de sécurité"""
        validation = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "security_alerts": [],
            "suggestions": [],
            "performance_notes": []
        }
        
        # Validation syntaxique
        try:
            ast.parse(code)
        except SyntaxError as e:
            validation["is_valid"] = False
            validation["errors"].append(f"Erreur de syntaxe ligne {e.lineno}: {e.msg}")
        
        # Vérifications de sécurité
        analysis = self.advanced_code_analysis(code)
        if analysis.get("security_issues"):
            for issue in analysis["security_issues"]:
                validation["security_alerts"].append({
                    "severity": "HIGH" if "dangerous" in issue["type"] else "MEDIUM",
                    "message": issue["detail"],
                    "line": issue.get("line", 0)
                })
                
                if user_role == UserRole.VIEWER and "dangerous" in issue["type"]:
                    validation["is_valid"] = False
                    validation["errors"].append("Code dangereux détecté - accès refusé")
        
        # Vérification de performance
        if analysis.get("complexity_score", 0) > 20:
            validation["performance_notes"].append(
                "Complexité élevée détectée - considérer la refactorisation"
            )
        
        # Suggestions d'amélioration
        if len(analysis.get("functions", [])) > 10:
            validation["suggestions"].append(
                "Beaucoup de fonctions - considérer la modularisation"
            )
        
        return validation

    def get_smart_suggestions(self, user_input: str, context: Dict, user: User) -> Dict[str, Any]:
        """Génère des suggestions intelligentes et sécurisées"""
        try:
            # Générer le prompt sécurisé
            prompt = self.generate_comprehensive_prompt(user_input, context, user.role)
            
            # Appel sécurisé à Gemini avec retry
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(
                        prompt,
                        generation_config={
                            'temperature': 0.1,  # Plus déterministe
                            'top_p': 0.8,
                            'top_k': 40,
                            'max_output_tokens': 4096
                        }
                    )
                    suggestion = response.text
                    break
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    time.sleep(1)
            
            # Extraire et valider le code
            code_blocks = re.findall(r'```(?:python|py)?\n(.*?)\n```', suggestion, re.DOTALL)
            
            result = {
                "suggestion": suggestion,
                "code_blocks": code_blocks,
                "validations": {},
                "security_assessment": "SAFE",
                "user_role": user.role.value,
                "timestamp": datetime.now().isoformat(),
                "model_used": "gemini-2.0-flash-exp"
            }
            
            # Validation complète de chaque bloc de code
            all_safe = True
            for i, code_block in enumerate(code_blocks):
                validation = self.comprehensive_validation(code_block, user.role)
                result["validations"][f"block_{i}"] = validation
                
                if validation["security_alerts"]:
                    all_safe = False
                    result["security_assessment"] = "RISKY"
                
                if not validation["is_valid"]:
                    result["security_assessment"] = "UNSAFE"
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération pour {user.username}: {e}")
            return {
                "error": "Erreur interne lors de la génération",
                "details": str(e) if user.role == UserRole.ADMIN else "Contactez l'administrateur",
                "suggestion": "",
                "code_blocks": [],
                "validations": {}
            }

# Initialisation Flask avec sécurité avancée
app = Flask(__name__)
CORS(app, origins=['http://localhost:3000', 'https://yourdomain.com'])

# Configuration sécurisée
app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY', secrets.token_urlsafe(64)),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max
    JSON_SORT_KEYS=False,
    JSONIFY_PRETTYPRINT_REGULAR=False
)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
limiter.init_app(app)

# Initialisation des composants
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    logger.error("❌ GEMINI_API_KEY non définie")
    exit(1)

db_manager = DatabaseManager()
agent = SmartCodeAgent(GEMINI_API_KEY, db_manager)

# Décorateurs de sécurité
def require_api_key(f):
    """Décorateur pour l'authentification par clé API"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Vérifications de sécurité de base
        client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        user_agent = request.headers.get('User-Agent', 'unknown')
        
        if agent.security.is_ip_blocked(client_ip):
            return jsonify({"error": "IP bloquée", "status": "blocked"}), 403
        
        if not agent.security.rate_limit_check(client_ip, request.endpoint):
            return jsonify({"error": "Rate limit dépassé", "status": "rate_limited"}), 429
        
        # Vérification de la clé API
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            agent.db.log_security_event(
                None, "MISSING_API_KEY", client_ip, user_agent,
                f"Tentative d'accès sans clé API sur {request.endpoint}",
                SecurityLevel.MEDIUM
            )
            return jsonify({"error": "Clé API requise", "status": "unauthorized"}), 401
        
        # Authentification
        request_info = {"ip": client_ip, "user_agent": user_agent}
        user = agent.security.authenticate_api_key(api_key, request_info)
        
        if not user:
            return jsonify({"error": "Clé API invalide", "status": "unauthorized"}), 401
        
        g.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(required_role: UserRole):
    """Décorateur pour vérifier les rôles utilisateur"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({"error": "Non authentifié", "status": "unauthorized"}), 401
            
            user_role_hierarchy = {
                UserRole.VIEWER: 1,
                UserRole.DEVELOPER: 2,
                UserRole.ADMIN: 3
            }
            
            if user_role_hierarchy[g.current_user.role] < user_role_hierarchy[required_role]:
                return jsonify({
                    "error": f"Rôle {required_role.value} requis",
                    "status": "forbidden",
                    "current_role": g.current_user.role.value
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes API sécurisées
@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Vérification de l'état de l'API - pas d'auth requise"""
    return jsonify({
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "secure_authentication",
            "role_based_access",
            "advanced_validation",
            "security_monitoring"
        ]
    })

@app.route('/api/v1/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    """Inscription d'un nouvel utilisateur - admin seulement pour la production"""
    try:
        data = request.get_json()
        
        required_fields = ['username', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({
                "error": "Username et password requis",
                "status": "bad_request"
            }), 400
        
        username = data['username']
        password = data['password']
        role = UserRole(data.get('role', 'developer'))
        
        # Validation du mot de passe
        if len(password) < 8:
            return jsonify({
                "error": "Mot de passe trop court (min 8 caractères)",
                "status": "bad_request"
            }), 400
        
        try:
            user = db_manager.create_user(username, password, role)
            
            return jsonify({
                "status": "success",
                "message": "Utilisateur créé avec succès",
                "data": {
                    "user_id": user.id,
                    "username": user.username,
                    "api_key": user.api_key,
                    "role": user.role.value
                }
            })
            
        except sqlite3.IntegrityError:
            return jsonify({
                "error": "Nom d'utilisateur déjà existant",
                "status": "conflict"
            }), 409
            
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {e}")
        return jsonify({
            "error": "Erreur interne",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/suggest', methods=['POST'])
@require_api_key
@require_role(UserRole.DEVELOPER)
@limiter.limit("30 per minute")
def suggest_code():
    """Endpoint principal pour les suggestions de code sécurisées"""
    try:
        data = request.get_json()
        
        if not data or 'prompt' not in data:
            return jsonify({
                "error": "Prompt requis",
                "status": "bad_request"
            }), 400
        
        user_prompt = data['prompt']
        context = data.get('context', {})
        
        # Validation de sécurité du prompt
        if len(user_prompt) > 5000:
            return jsonify({
                "error": "Prompt trop long (max 5000 caractères)",
                "status": "bad_request"
            }), 400
        
        # Génération sécurisée
        result = agent.get_smart_suggestions(user_prompt, context, g.current_user)
        
        # Log de l'activité
        db_manager.log_security_event(
            g.current_user.id, "CODE_SUGGESTION",
            request.environ.get('REMOTE_ADDR', ''),
            request.headers.get('User-Agent', ''),
            f"Suggestion générée: {len(result.get('code_blocks', []))} blocs",
            SecurityLevel.LOW
        )
        
        return jsonify({
            "status": "success",
            "data": result,
            "meta": {
                "user": g.current_user.username,
                "timestamp": datetime.now().isoformat(),
                "model": "gemini-2.0-flash-exp",
                "security_level": result.get("security_assessment", "UNKNOWN")
            }
        })
        
    except RequestEntityTooLarge:
        return jsonify({
            "error": "Requête trop volumineuse",
            "status": "payload_too_large"
        }), 413
    
    except Exception as e:
        logger.error(f"Erreur dans suggest_code pour {g.current_user.username}: {e}")
        db_manager.log_security_event(
            g.current_user.id, "SUGGESTION_ERROR",
            request.environ.get('REMOTE_ADDR', ''),
            request.headers.get('User-Agent', ''),
            f"Erreur: {str(e)}",
            SecurityLevel.HIGH
        )
        return jsonify({
            "error": "Erreur lors de la génération",
            "status": "internal_error",
            "details": str(e) if g.current_user.role == UserRole.ADMIN else None
        }), 500

@app.route('/api/v1/analyze-project', methods=['POST'])
@require_api_key
@require_role(UserRole.DEVELOPER)
@limiter.limit("10 per minute")
def analyze_project():
    """Analyse sécurisée de la structure d'un projet"""
    try:
        data = request.get_json()
        project_path = data.get('path')
        
        if not project_path:
            return jsonify({
                "error": "Chemin de projet requis",
                "status": "bad_request"
            }), 400
        
        # Validation de sécurité du chemin
        if not agent.validate_project_path(project_path, g.current_user.role):
            return jsonify({
                "error": "Chemin de projet non autorisé",
                "status": "forbidden"
            }), 403
        
        analysis = agent.analyze_project_structure_secure(project_path, g.current_user)
        
        db_manager.log_security_event(
            g.current_user.id, "PROJECT_ANALYSIS",
            request.environ.get('REMOTE_ADDR', ''),
            request.headers.get('User-Agent', ''),
            f"Analyse projet: {project_path}",
            SecurityLevel.MEDIUM
        )
        
        return jsonify({
            "status": "success",
            "data": analysis,
            "meta": {
                "user": g.current_user.username,
                "timestamp": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur dans analyze_project: {e}")
        return jsonify({
            "error": "Erreur lors de l'analyse",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/validate-code', methods=['POST'])
@require_api_key
@limiter.limit("50 per minute")
def validate_code():
    """Validation sécurisée de code"""
    try:
        data = request.get_json()
        code = data.get('code')
        
        if not code:
            return jsonify({
                "error": "Code requis pour validation",
                "status": "bad_request"
            }), 400
        
        if len(code) > 50000:  # 50KB max
            return jsonify({
                "error": "Code trop volumineux (max 50KB)",
                "status": "bad_request"
            }), 400
        
        validation = agent.comprehensive_validation(code, g.current_user.role)
        analysis = agent.advanced_code_analysis(code)
        
        return jsonify({
            "status": "success",
            "data": {
                "validation": validation,
                "analysis": analysis,
                "security_score": agent.calculate_security_score(analysis),
                "recommendations": agent.get_security_recommendations(analysis)
            },
            "meta": {
                "user": g.current_user.username,
                "timestamp": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur dans validate_code: {e}")
        return jsonify({
            "error": "Erreur lors de la validation",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/session', methods=['GET', 'POST', 'DELETE'])
@require_api_key
def manage_session():
    """Gestion sécurisée des sessions utilisateur"""
    try:
        if request.method == 'GET':
            session_data = db_manager.get_user_session(g.current_user.id)
            return jsonify({
                "status": "success",
                "data": session_data
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            session_id = db_manager.create_or_update_session(
                g.current_user.id,
                data.get('context', {}),
                data.get('project_structure', {})
            )
            
            return jsonify({
                "status": "success",
                "data": {"session_id": session_id}
            })
        
        elif request.method == 'DELETE':
            db_manager.clear_user_session(g.current_user.id)
            return jsonify({
                "status": "success",
                "message": "Session supprimée"
            })
            
    except Exception as e:
        logger.error(f"Erreur dans manage_session: {e}")
        return jsonify({
            "error": "Erreur de gestion de session",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/history', methods=['GET'])
@require_api_key
def get_user_history():
    """Récupération de l'historique utilisateur"""
    try:
        limit = min(request.args.get('limit', 50, type=int), 100)  # Max 100
        offset = max(request.args.get('offset', 0, type=int), 0)
        
        history = db_manager.get_user_history(g.current_user.id, limit, offset)
        
        return jsonify({
            "status": "success",
            "data": {
                "history": history,
                "limit": limit,
                "offset": offset
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur dans get_user_history: {e}")
        return jsonify({
            "error": "Erreur de récupération de l'historique",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/admin/users', methods=['GET'])
@require_api_key
@require_role(UserRole.ADMIN)
def list_users():
    """Liste des utilisateurs - admin seulement"""
    try:
        users = db_manager.get_all_users()
        return jsonify({
            "status": "success",
            "data": {
                "users": users,
                "count": len(users)
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur dans list_users: {e}")
        return jsonify({
            "error": "Erreur de récupération des utilisateurs",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/admin/security-logs', methods=['GET'])
@require_api_key
@require_role(UserRole.ADMIN)
def get_security_logs():
    """Logs de sécurité - admin seulement"""
    try:
        limit = min(request.args.get('limit', 100, type=int), 500)
        severity = request.args.get('severity')  # LOW, MEDIUM, HIGH, CRITICAL
        
        logs = db_manager.get_security_logs(limit, severity)
        
        return jsonify({
            "status": "success",
            "data": {
                "logs": logs,
                "count": len(logs)
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur dans get_security_logs: {e}")
        return jsonify({
            "error": "Erreur de récupération des logs",
            "status": "internal_error"
        }), 500

@app.route('/api/v1/admin/stats', methods=['GET'])
@require_api_key
@require_role(UserRole.ADMIN)
def get_system_stats():
    """Statistiques système - admin seulement"""
    try:
        stats = {
            "users": {
                "total": db_manager.count_users(),
                "active": db_manager.count_active_users(),
                "by_role": db_manager.count_users_by_role()
            },
            "activity": {
                "suggestions_today": db_manager.count_suggestions_today(),
                "validations_today": db_manager.count_validations_today(),
                "errors_today": db_manager.count_errors_today()
            },
            "security": {
                "blocked_ips": len(agent.security.blocked_ips),
                "security_alerts_today": db_manager.count_security_alerts_today()
            },
            "system": {
                "uptime": time.time() - start_time,
                "memory_usage": "N/A",  # Peut être implémenté avec psutil
                "disk_usage": "N/A"
            }
        }
        
        return jsonify({
            "status": "success",
            "data": stats
        })
        
    except Exception as e:
        logger.error(f"Erreur dans get_system_stats: {e}")
        return jsonify({
            "error": "Erreur de récupération des statistiques",
            "status": "internal_error"
        }), 500

# Gestionnaires d'erreur globaux
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "error": "Requête invalide",
        "status": "bad_request",
        "details": str(error.description) if hasattr(error, 'description') else None
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "error": "Non autorisé",
        "status": "unauthorized"
    }), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "error": "Accès interdit",
        "status": "forbidden"
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint non trouvé",
        "status": "not_found"
    }), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        "error": "Limite de taux dépassée",
        "status": "rate_limited",
        "retry_after": "60 seconds"
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erreur interne: {error}")
    return jsonify({
        "error": "Erreur interne du serveur",
        "status": "internal_error"
    }), 500

# Extensions des méthodes de l'agent pour les nouvelles fonctionnalités
def extend_agent_methods():
    """Étend les méthodes de l'agent avec des fonctionnalités de sécurité"""
    
    def validate_project_path(self, project_path: str, user_role: UserRole) -> bool:
        """Valide un chemin de projet selon le rôle utilisateur"""
        import os.path
        
        # Chemins interdits
        forbidden_paths = [
            '/etc', '/usr', '/bin', '/sbin', '/root',
            'C:\\Windows', 'C:\\Program Files', 'C:\\System32'
        ]
        
        # Normalisation du chemin
        normalized_path = os.path.normpath(project_path)
        
        # Vérification des chemins interdits
        for forbidden in forbidden_paths:
            if normalized_path.startswith(forbidden):
                return False
        
        # Vérification des caractères dangereux
        dangerous_chars = ['..', '~',  '`']
        if any(char in normalized_path for char in dangerous_chars):
            return False
        
        return True
    
    def analyze_project_structure_secure(self, project_path: str, user: User) -> Dict[str, Any]:
        """Analyse sécurisée de la structure du projet"""
        try:
            if not self.validate_project_path(project_path, user.role):
                return {"error": "Chemin non autorisé"}
            
            analysis = self.analyze_project_structure(project_path)
            
            # Filtrer les informations sensibles selon le rôle
            if user.role == UserRole.VIEWER:
                # Supprimer les chemins complets pour les viewers
                if 'files' in analysis:
                    for file_info in analysis['files']:
                        if 'path' in file_info:
                            file_info['path'] = os.path.basename(file_info['path'])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erreur dans analyze_project_structure_secure: {e}")
            return {"error": "Erreur lors de l'analyse sécurisée"}
    
    def calculate_security_score(self, analysis: Dict[str, Any]) -> int:
        """Calcule un score de sécurité sur 100"""
        score = 100
        
        # Pénalités pour problèmes de sécurité
        security_issues = analysis.get('security_issues', [])
        for issue in security_issues:
            if issue['type'] == 'dangerous_pattern':
                score -= 30
            elif issue['type'] == 'unsafe_import':
                score -= 20
            elif issue['type'] == 'syntax_error':
                score -= 10
        
        # Bonus pour bonnes pratiques
        if analysis.get('functions'):
            documented_functions = sum(1 for f in analysis['functions'] if f.get('docstring'))
            if documented_functions > 0:
                score += min(10, documented_functions * 2)
        
        return max(0, min(100, score))
    
    def get_security_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Génère des recommandations de sécurité"""
        recommendations = []
        
        security_issues = analysis.get('security_issues', [])
        
        if any(issue['type'] == 'dangerous_pattern' for issue in security_issues):
            recommendations.append("Évitez l'utilisation de eval(), exec() et subprocess pour la sécurité")
        
        if any(issue['type'] == 'unsafe_import' for issue in security_issues):
            recommendations.append("Vérifiez les imports non standard et leur sécurité")
        
        if analysis.get('complexity_score', 0) > 20:
            recommendations.append("Considérez la refactorisation pour réduire la complexité")
        
        undocumented_functions = [f for f in analysis.get('functions', []) if not f.get('docstring')]
        if len(undocumented_functions) > 3:
            recommendations.append("Ajoutez de la documentation pour améliorer la maintenabilité")
        
        if not recommendations:
            recommendations.append("Code sécurisé - bonnes pratiques respectées")
        
        return recommendations
    
    # Ajouter les méthodes à l'agent
    SmartCodeAgent.validate_project_path = validate_project_path
    SmartCodeAgent.analyze_project_structure_secure = analyze_project_structure_secure
    SmartCodeAgent.calculate_security_score = calculate_security_score
    SmartCodeAgent.get_security_recommendations = get_security_recommendations

# Extensions des méthodes de DatabaseManager
def extend_db_methods():
    """Étend les méthodes du gestionnaire de base de données"""
    
    def create_or_update_session(self, user_id: str, context: dict, project_structure: dict) -> str:
        """Crée ou met à jour une session utilisateur"""
        session_id = str(uuid.uuid4())
        
        with self.get_connection() as conn:
            # Supprimer l'ancienne session
            conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            
            # Créer la nouvelle session
            conn.execute('''
                INSERT INTO sessions (id, user_id, context, project_structure)
                VALUES (?, ?, ?, ?)
            ''', (session_id, user_id, json.dumps(context), json.dumps(project_structure)))
            conn.commit()
        
        return session_id
    
    def get_user_session(self, user_id: str) -> Dict[str, Any]:
        """Récupère la session d'un utilisateur"""
        with self.get_connection() as conn:
            row = conn.execute('''
                SELECT context, project_structure, created_at, updated_at 
                FROM sessions WHERE user_id = ?
            ''', (user_id,)).fetchone()
            
            if row:
                return {
                    "context": json.loads(row['context']),
                    "project_structure": json.loads(row['project_structure']),
                    "created_at": row['created_at'],
                    "updated_at": row['updated_at']
                }
            return {}
    
    def clear_user_session(self, user_id: str):
        """Supprime la session d'un utilisateur"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            conn.commit()
    
    def get_user_history(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Récupère l'historique d'un utilisateur"""
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT ch.user_input, ch.ai_response, ch.validation_result, ch.created_at
                FROM code_history ch
                JOIN sessions s ON ch.session_id = s.id
                WHERE s.user_id = ?
                ORDER BY ch.created_at DESC
                LIMIT ? OFFSET ?
            ''', (user_id, limit, offset)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_all_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs (admin seulement)"""
        with self.get_connection() as conn:
            rows = conn.execute('''
                SELECT id, username, role, created_at, last_login, is_active
                FROM users ORDER BY created_at DESC
            ''').fetchall()
            
            return [dict(row) for row in rows]
    
    def get_security_logs(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Récupère les logs de sécurité"""
        with self.get_connection() as conn:
            query = 'SELECT * FROM security_logs'
            params = []
            
            if severity:
                severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                if severity in severity_map:
                    query += ' WHERE security_level = ?'
                    params.append(severity_map[severity])
            
            query += ' ORDER BY created_at DESC LIMIT ?'
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
    
    # Méthodes de comptage pour les statistiques
    def count_users(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    
    def count_active_users(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0]
    
    def count_users_by_role(self) -> Dict[str, int]:
        with self.get_connection() as conn:
            rows = conn.execute('SELECT role, COUNT(*) as count FROM users GROUP BY role').fetchall()
            return {row[0]: row[1] for row in rows}
    
    def count_suggestions_today(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('''
                SELECT COUNT(*) FROM security_logs 
                WHERE event_type = 'CODE_SUGGESTION' 
                AND date(created_at) = date('now')
            ''').fetchone()[0]
    
    def count_validations_today(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('''
                SELECT COUNT(*) FROM security_logs 
                WHERE event_type LIKE '%VALIDATION%' 
                AND date(created_at) = date('now')
            ''').fetchone()[0]
    
    def count_errors_today(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('''
                SELECT COUNT(*) FROM security_logs 
                WHERE event_type LIKE '%ERROR%' 
                AND date(created_at) = date('now')
            ''').fetchone()[0]
    
    def count_security_alerts_today(self) -> int:
        with self.get_connection() as conn:
            return conn.execute('''
                SELECT COUNT(*) FROM security_logs 
                WHERE security_level >= 3 
                AND date(created_at) = date('now')
            ''').fetchone()[0]
    
    # Ajouter les méthodes au DatabaseManager
    DatabaseManager.create_or_update_session = create_or_update_session
    DatabaseManager.get_user_session = get_user_session
    DatabaseManager.clear_user_session = clear_user_session
    DatabaseManager.get_user_history = get_user_history
    DatabaseManager.get_all_users = get_all_users
    DatabaseManager.get_security_logs = get_security_logs
    DatabaseManager.count_users = count_users
    DatabaseManager.count_active_users = count_active_users
    DatabaseManager.count_users_by_role = count_users_by_role
    DatabaseManager.count_suggestions_today = count_suggestions_today
    DatabaseManager.count_validations_today = count_validations_today
    DatabaseManager.count_errors_today = count_errors_today
    DatabaseManager.count_security_alerts_today = count_security_alerts_today

@app.route("/")
def home():
    return render_template("frontend.html")
# Application des extensions
extend_agent_methods()
extend_db_methods()

# Variables globales pour les statistiques
start_time = time.time()

if __name__ == '__main__':
    # Vérifications de sécurité au démarrage
    required_env_vars = ['GEMINI_API_KEY']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"❌ Variables d'environnement manquantes: {', '.join(missing_vars)}")
        logger.info("💡 Définissez les variables requises:")
        logger.info("   export GEMINI_API_KEY='votre-cle-gemini'")
        logger.info("   export FLASK_SECRET_KEY='cle-secrete-flask'")
        logger.info("   export JWT_SECRET='cle-secrete-jwt'")
        exit(1)
    
    # Création d'un utilisateur admin par défaut si nécessaire
    try:
        admin_user = db_manager.create_user("admin", "admin123456", UserRole.ADMIN)
        logger.info(f"👤 Utilisateur admin créé - API Key: {admin_user.api_key}")
    except sqlite3.IntegrityError:
        logger.info("👤 Utilisateur admin existant détecté")
    
    logger.info("🚀 Démarrage de l'Agent IA de Développement Sécurisé v2.0")
    logger.info("🔒 Fonctionnalités de sécurité:")
    logger.info("   ✅ Authentification par clé API")
    logger.info("   ✅ Contrôle d'accès basé sur les rôles")
    logger.info("   ✅ Validation avancée du code")
    logger.info("   ✅ Monitoring de sécurité")
    logger.info("   ✅ Rate limiting")
    logger.info("   ✅ Logging sécurisé")
    logger.info("")
    logger.info("📋 Endpoints API v1:")
    logger.info("   🔓 GET  /api/v1/health - État de l'API")
    logger.info("   👤 POST /api/v1/auth/register - Inscription")
    logger.info("   🤖 POST /api/v1/suggest - Suggestions de code")
    logger.info("   📁 POST /api/v1/analyze-project - Analyse de projet")
    logger.info("   ✅ POST /api/v1/validate-code - Validation de code")
    logger.info("   💾 GET/POST/DELETE /api/v1/session - Gestion des sessions")
    logger.info("   📖 GET  /api/v1/history - Historique utilisateur")
    logger.info("   🔧 GET  /api/v1/admin/* - Endpoints administrateur")
    logger.info("")
    logger.info("🔑 Utilisez l'en-tête: X-API-Key: votre_cle_api")
    logger.info("🌐 API disponible sur: http://localhost:5000")
    
    app.run(
        debug=True,  # Sécurité: pas de debug en production
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        threaded=True
    )