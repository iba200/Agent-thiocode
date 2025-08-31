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
