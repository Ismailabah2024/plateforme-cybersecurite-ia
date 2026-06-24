import pandas as pd
import random
from datetime import datetime, timedelta

# Définir les valeurs possibles
types_incidents = ["Panne Réseau", "Bug Logiciel", "Intrusion", "Défaillance Matériel", "Erreur Humaine"]
sévérités = ["Critique", "Majeure", "Mineure", "Info"]
statuts = ["Ouvert", "En cours", "Résolu", "Clos", "Rejeté"]

# Générer 10 000 lignes de données simulées
n = 10000
data = []

start_date = datetime(2023, 1, 1)

for i in range(1, n + 1):
    date_incident = start_date + timedelta(days=random.randint(0, 500), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    type_incident = random.choice(types_incidents)
    sévérité = random.choice(sévérités)
    statut = random.choice(statuts)
    description = f"{type_incident} détecté avec sévérité {sévérité.lower()} (simulation #{i})"
    data.append([i, date_incident, type_incident, sévérité, statut, description])

# Créer DataFrame
df = pd.DataFrame(data, columns=[
    "ID_Incident",
    "Date_Incident",
    "Type_Incident",
    "Sévérité",
    "Statut",
    "Description"
])

# Sauvegarder au format Excel
output_file = "incidents_10000.xlsx"
df.to_excel(output_file, index=False)
print(f"Fichier Excel généré avec succès : {output_file}")
