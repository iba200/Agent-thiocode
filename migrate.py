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
