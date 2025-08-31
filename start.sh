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
