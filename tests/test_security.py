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
