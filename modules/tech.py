import streamlit as st
import pandas as pd
from datetime import datetime
import os
from io import BytesIO

DATA_FILE = "data/incidents_affectes.xlsx"

def display(df=None):
    st.header("🛠️ Tableau de bord du Technicien")

    if not os.path.exists(DATA_FILE):
        st.info("Aucun incident n’a encore été affecté.")
        return

    df = pd.read_excel(DATA_FILE)
    incidents_technicien = df[df['Assigné_à'] == "Technicien"]

    if incidents_technicien.empty:
        st.info("Aucun incident affecté au Technicien.")
        return

    st.subheader("📋 Incidents affectés")
    st.dataframe(incidents_technicien)

    incident_id = st.selectbox("🆔 Sélectionner un incident à gérer", incidents_technicien['ID_Incident'])
    incident = incidents_technicien[incidents_technicien['ID_Incident'] == incident_id].iloc[0]

    st.markdown(f"**📄 Description :** {incident['Description']}")
    st.markdown(f"**📌 Statut actuel :** `{incident['Statut']}`")
    st.markdown(f"**💬 Commentaires :**\n{incident['Commentaires']}")

    action = st.radio("🛠️ Action", ["Clôturer", "Retourner au superviseur"])
    commentaire = st.text_area("📝 Commentaire / résolution")

    if st.button("✅ Mettre à jour l'incident"):
        horodatage = datetime.now().strftime("%Y-%m-%d %H:%M")
        idx = df[df['ID_Incident'] == incident_id].index[0]
        df.at[idx, 'Commentaires'] += f"\n[{horodatage}] Technicien : {commentaire}"

        if action == "Clôturer":
            df.at[idx, 'Statut'] = "Résolu"
            st.success("✅ Incident clôturé avec succès.")
        else:
            df.at[idx, 'Statut'] = "En attente superviseur"
            df.at[idx, 'Assigné_à'] = "Superviseur"
            st.warning("🚨 Incident retourné au superviseur pour réaffectation.")

        # Sauvegarde dans le fichier partagé
        df.to_excel(DATA_FILE, index=False)

    # ✅ Export Excel corrigé avec BytesIO
    st.subheader("📤 Export des incidents")
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df[df['Assigné_à'] == "Technicien"].to_excel(writer, index=False, sheet_name="Incidents_Tech")
    buffer.seek(0)

    st.download_button(
        label="⬇️ Télécharger les incidents au format Excel",
        data=buffer,
        file_name="incidents_technicien.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
