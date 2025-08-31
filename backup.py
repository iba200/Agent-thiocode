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
