import streamlit as st
import pandas as pd
from datetime import datetime
import os

DATA_FILE = "data/incidents_affectes.xlsx"

def enregistrer_affectation(incident_dict):
    # Sauvegarder ou créer le fichier partagé
    if os.path.exists(DATA_FILE):
        df_exist = pd.read_excel(DATA_FILE)
        df_new = pd.concat([df_exist, pd.DataFrame([incident_dict])], ignore_index=True)
    else:
        df_new = pd.DataFrame([incident_dict])
    df_new.to_excel(DATA_FILE, index=False)

def display(df):
    st.header("📡 Tableau de bord du Superviseur")

    # ========== Statistiques globales ==========
    col1, col2, col3 = st.columns(3)
    col1.metric("Incidents totaux", len(df))
    col2.metric("Incidents critiques", len(df[df['Type_Menace'] == 'Critique']))
    col3.metric("Incidents escaladés", len(df[df['Statut'] == 'Escaladé']))

    # ========== Filtres ==========
    st.subheader("Filtres avancés")
    f1, f2, f3 = st.columns(3)
    with f1:
        selected_source = st.selectbox("Source", ["Toutes"] + list(df['Source'].unique()))
    with f2:
        selected_threat = st.selectbox("Type de menace", ["Toutes"] + list(df['Type_Menace'].unique()))
    with f3:
        selected_status = st.selectbox("Statut", ["Tous"] + list(df['Statut'].unique()))

    filtered_df = df.copy()
    if selected_source != "Toutes":
        filtered_df = filtered_df[filtered_df['Source'] == selected_source]
    if selected_threat != "Toutes":
        filtered_df = filtered_df[filtered_df['Type_Menace'] == selected_threat]
    if selected_status != "Tous":
        filtered_df = filtered_df[filtered_df['Statut'] == selected_status]

    # ========== Visualisation tableau ==========
    st.dataframe(filtered_df)

    # ========== Graphiques ==========
    st.subheader("Visualisations")
    tab1, tab2, tab3 = st.tabs(["Par type de menace", "Par source", "Évolution temporelle"])

    with tab1:
        st.bar_chart(filtered_df['Type_Menace'].value_counts())
    with tab2:
        st.bar_chart(filtered_df['Source'].value_counts())
    with tab3:
        df_daily = filtered_df.copy()
        df_daily['Date'] = pd.to_datetime(df_daily['Date_Heure'], errors='coerce').dt.date
        st.line_chart(df_daily.groupby('Date').size())

    # ========== Gestion des affectations et escalades ==========
    st.subheader("Affectation / Escalade d’incident")

    if filtered_df.empty:
        st.info("Aucun incident disponible pour traitement.")
        return

    incident_id = st.selectbox("Sélectionner un incident", filtered_df['ID_Incident'])
    selected = df[df['ID_Incident'] == incident_id].iloc[0]

    st.markdown(f"**📝 Description :** {selected['Description']}")
    st.markdown(f"**🔍 Statut actuel :** `{selected['Statut']}`")
    st.markdown(f"**📂 Commentaires :**\n{selected['Commentaires']}")

    col1, col2 = st.columns(2)
    with col1:
        action = st.radio("Type d'action", ["Affecter", "Escalader"])
    with col2:
        cible = st.selectbox("Vers :", ["Technicien", "Ingénieur Sécurité", "Ingénieur Réseau", "Administrateur"])

    commentaire = st.text_area("💬 Motif ou consignes")

    if st.button("Valider l’action"):
        horodatage = datetime.now().strftime("%Y-%m-%d %H:%M")
        idx = df[df['ID_Incident'] == incident_id].index[0]

        # Mise à jour dans df principal
        df.at[idx, 'Statut'] = 'Escaladé' if action == "Escalader" else 'En cours'
        df.at[idx, 'Assigné_à'] = cible
        df.at[idx, 'Commentaires'] += f"\n[{horodatage}] Superviseur : {action} vers {cible} - {commentaire}"

        # Enregistrement dans fichier partagé pour les autres rôles
        incident_dict = df.loc[idx].to_dict()
        enregistrer_affectation(incident_dict)

        # Confirmation
        st.success(f"Incident {incident_id} {action.lower()} vers {cible}")
        st.info(f"Ajouté à `{DATA_FILE}` pour visibilité côté {cible}")
