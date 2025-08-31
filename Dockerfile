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
