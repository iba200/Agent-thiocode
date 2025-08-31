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
