import pandas as pd
import random
from datetime import datetime, timedelta

# Nombre de lignes
n = 10000

# Paramètres des valeurs possibles
sources = ["Firewall", "Serveur", "IDS", "Proxy", "VPN", "WebApp"]
type_logs = ["Info", "Alerte", "Erreur", "Warning"]
niveaux = {
    "Info": "info",
    "Alerte": "warning",
    "Erreur": "erreur",
    "Warning": "warning"
}

# Début aléatoire pour les horodatages
start_time = datetime(2025, 1, 1)

# Génération des données
data = []
for _ in range(n):
    horodatage = start_time + timedelta(seconds=random.randint(0, 60 * 60 * 24 * 30))  # sur 1 mois
    source = random.choice(sources)
    type_log = random.choice(type_logs)
    niveau = niveaux[type_log]
    message = f"{type_log} détectée par {source} à {horodatage.strftime('%H:%M:%S')}"
    data.append([horodatage, source, type_log, message, niveau])

# Création du DataFrame
df_logs = pd.DataFrame(data, columns=[
    "Horodatage", "Source", "Type_Log", "Message", "Niveau"
])

# Export vers Excel
nom_fichier = "logs_systeme_10000.xlsx"
df_logs.to_excel(nom_fichier, index=False)

print(f"✅ Fichier généré avec succès : {nom_fichier}")
