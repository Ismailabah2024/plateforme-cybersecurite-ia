import streamlit as st
import pandas as pd
from datetime import datetime
import os
from io import BytesIO

DATA_FILE = "data/incidents_affectes.xlsx"

def display(df=None):
    st.header("🛡️ Tableau de bord de l'Ingénieur Sécurité")

    if not os.path.exists(DATA_FILE):
        st.info("Aucun incident n’a encore été affecté.")
        return

    df = pd.read_excel(DATA_FILE)

    # Ne voir que les incidents EN COURS, non résolus
    df_sec = df[(df['Assigné_à'] == "Ingénieur Sécurité") & (~df['Statut'].isin(["À archiver", "Résolu"]))]

    if df_sec.empty:
        st.success("Aucun incident en attente de traitement par l'Ingénieur Sécurité.")
        return

    st.subheader("📋 Incidents à traiter")
    st.dataframe(df_sec)

    incident_id = st.selectbox("🆔 Sélectionner un incident", df_sec['ID_Incident'])
    incident = df_sec[df_sec['ID_Incident'] == incident_id].iloc[0]

    st.markdown(f"**📄 Description :** {incident['Description']}")
    st.markdown(f"**📌 Statut :** `{incident['Statut']}`")
    st.markdown(f"**💬 Commentaires :**\n{incident['Commentaires']}")

    action = st.radio("Action", ["Clôturer", "Retourner au superviseur"])
    commentaire = st.text_area("📝 Résolution ou remarque")

    if st.button("✅ Mettre à jour l'incident"):
        horodatage = datetime.now().strftime("%Y-%m-%d %H:%M")
        idx = df[df['ID_Incident'] == incident_id].index[0]
        df.at[idx, 'Commentaires'] += f"\n[{horodatage}] Ing. Sécu : {commentaire}"

        if action == "Clôturer":
            df.at[idx, 'Statut'] = "À archiver"
            df.at[idx, 'Assigné_à'] = "Superviseur"
            st.success("✅ Incident clôturé et envoyé pour archivage.")
        else:
            df.at[idx, 'Statut'] = "En attente superviseur"
            df.at[idx, 'Assigné_à'] = "Superviseur"
            st.warning("🔁 Incident retourné au superviseur.")

        df.to_excel(DATA_FILE, index=False)

    # 📤 Export incidents non encore archivés
    st.subheader("📤 Export Excel des incidents actifs")
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df[df['Assigné_à'] == "Ingénieur Sécurité"].to_excel(writer, index=False, sheet_name="Incidents_Sec")
    buffer.seek(0)

    st.download_button(
        label="⬇️ Télécharger incidents Excel",
        data=buffer,
        file_name="incidents_securite.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    # CVE + Base de connaissances conservés
    st.subheader("🔍 Analyse des vulnérabilités (CVE)")
    cve_df = df[df['CVE'] != 'N/A']
    if not cve_df.empty:
        cve_counts = cve_df['CVE'].value_counts().reset_index()
        cve_counts.columns = ['CVE', 'Occurrences']
        st.dataframe(cve_counts)

        st.subheader("🧠 Suggestions de règles de sécurité")
        selected_cve = st.selectbox("Choisir une CVE", cve_counts['CVE'].unique())
        if selected_cve:
            st.markdown(f"**Règles recommandées pour `{selected_cve}` :**")
            st.write("- 🧱 NGFW : Bloquer les payloads suspects")
            st.write("- 🔎 IDS : Détecter les patterns d'attaque")
            st.write("- 📊 SIEM : Alerter sur les exploitations")

    st.subheader("📚 Base de connaissances")
    knowledge = {
        "SQL Injection": "Filtrer les caractères spéciaux dans les entrées SQL.",
        "XSS": "Échapper le contenu HTML/JS côté client.",
        "DDoS": "Limiter les requêtes et utiliser un WAF.",
        "Phishing": "Configurer SPF/DKIM/DMARC et sensibiliser les utilisateurs."
    }
    selected_topic = st.selectbox("🧩 Rechercher un sujet", list(knowledge.keys()))
    st.info(knowledge.get(selected_topic, "Aucune recommandation disponible."))
