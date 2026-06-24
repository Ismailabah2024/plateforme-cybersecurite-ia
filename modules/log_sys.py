import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def display():
    st.title("🖥️ Analyse des Logs Système")

    # Upload fichier XLSX
    uploaded_file = st.file_uploader("📂 Importer un fichier Excel de logs", type=["xlsx"])
    if uploaded_file is None:
        st.info("Merci de sélectionner un fichier Excel contenant les logs système.")
        return

    # Lecture Excel
    try:
        df = pd.read_excel(uploaded_file)
    except Exception as e:
        st.error(f"Erreur lors de la lecture du fichier Excel : {e}")
        return

    # Colonnes attendues
    expected_cols = [
        "Horodatage",  # datetime
        "Source",      # équipement (firewall, IDS, serveur, etc.)
        "Type_Log",    # type de log (alerte, info, erreur, warning)
        "Message",     # texte libre
        "Niveau"       # criticité (info, warning, erreur)
    ]

    st.subheader("✅ Colonnes détectées dans le fichier :")
    st.write(df.columns.tolist())

    # Vérification des colonnes
    missing_cols = [col for col in expected_cols if col not in df.columns]
    if missing_cols:
        st.warning(f"Colonnes manquantes : {missing_cols}")
        st.info("Le fichier doit contenir au moins les colonnes suivantes : " + ", ".join(expected_cols))
        return

    # Conversion Horodatage
    df["Horodatage"] = pd.to_datetime(df["Horodatage"], errors="coerce")

    # Filtres latéraux
    st.sidebar.header("🎛️ Filtres")
    sources = df["Source"].dropna().unique().tolist()
    types_log = df["Type_Log"].dropna().unique().tolist()
    niveaux = df["Niveau"].dropna().unique().tolist()

    filt_source = st.sidebar.multiselect("📡 Source", sources, default=sources)
    filt_type = st.sidebar.multiselect("📁 Type de Log", types_log, default=types_log)
    filt_niveau = st.sidebar.multiselect("⚠️ Niveau", niveaux, default=niveaux)

    recherche = st.sidebar.text_input("🔍 Recherche textuelle dans les messages")

    # Application des filtres
    df_filtre = df[
        df["Source"].isin(filt_source) &
        df["Type_Log"].isin(filt_type) &
        df["Niveau"].isin(filt_niveau)
    ]

    if recherche:
        df_filtre = df_filtre[df_filtre["Message"].str.contains(recherche, case=False, na=False)]

    st.markdown(f"### 🧾 Logs filtrés ({len(df_filtre)} lignes)")
    st.dataframe(df_filtre, use_container_width=True)

    # Statistiques : types de log
    st.markdown("### 📊 Répartition des types de logs")
    type_counts = df_filtre["Type_Log"].value_counts()
    st.bar_chart(type_counts)

    # Analyse d'anomalies simples
    st.markdown("### 🚨 Détection d'anomalies (pics d'erreurs par heure)")
    df_erreurs = df_filtre[df_filtre["Niveau"].str.lower() == "erreur"]

    if not df_erreurs.empty:
        df_erreurs["Heure"] = df_erreurs["Horodatage"].dt.hour
        erreurs_par_heure = df_erreurs.groupby("Heure").size()

        seuil = erreurs_par_heure.mean() + 2 * erreurs_par_heure.std()

        fig, ax = plt.subplots(figsize=(10, 4))
        sns.lineplot(x=erreurs_par_heure.index, y=erreurs_par_heure.values, ax=ax, marker="o")
        ax.axhline(seuil, color="red", linestyle="--", label="Seuil d'anomalie")
        ax.set_xlabel("Heure de la journée")
        ax.set_ylabel("Nombre d'erreurs")
        ax.set_title("Nombre d'erreurs par heure")
        ax.legend()
        st.pyplot(fig)

        anomalies = erreurs_par_heure[erreurs_par_heure > seuil]
        if not anomalies.empty:
            st.warning(f"Anomalies détectées aux heures : {list(anomalies.index)}")
        else:
            st.success("✅ Aucun pic d'erreurs détecté.")
    else:
        st.info("Aucune erreur détectée dans les logs filtrés.")

if __name__ == "__main__":
    display()
