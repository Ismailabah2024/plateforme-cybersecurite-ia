import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px

def display(df):
    st.subheader("🔐 Tableau de Bord – Ingénieur Sécurité Applicative")

    # Juste logger dans la console Python (pas affiché dans Streamlit)
    print("Colonnes détectées :", list(df.columns))

    # Vérifier si la colonne 'Sévérité' existe, sinon créer une colonne par défaut
    if "Sévérité" not in df.columns:
    # Message uniquement dans la console, pas dans l'app
        print("Colonne 'Sévérité' introuvable. Une valeur par défaut 'Non spécifié' sera utilisée.")
        df["Sévérité"] = "Non spécifié"
    # Vérifier si la colonne 'Type' existe (dans ton cas 'Type_Menace')
    type_col = "Type" if "Type" in df.columns else "Type_Menace"

    # Filtres latéraux
    st.sidebar.subheader("🎛️ Filtres de sécurité")
    selected_type = st.sidebar.multiselect("Type d'incident", df[type_col].unique(), default=df[type_col].unique())
    selected_severity = st.sidebar.multiselect("Sévérité", df["Sévérité"].unique(), default=df["Sévérité"].unique())
    selected_status = st.sidebar.multiselect("Statut", df["Statut"].unique(), default=df["Statut"].unique())

    df_filtered = df[
        df[type_col].isin(selected_type) &
        df["Sévérité"].isin(selected_severity) &
        df["Statut"].isin(selected_status)
    ]

    # KPIs
    st.markdown("### 📊 Indicateurs Clés de Performance (KPI)")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Incidents", len(df_filtered))
    col2.metric("Incidents Critiques", len(df_filtered[df_filtered["Sévérité"] == "Critique"]))
    taux_resolution = (
        len(df_filtered[df_filtered["Statut"] == "Résolu"]) / len(df_filtered) * 100
        if len(df_filtered) > 0 else 0
    )
    col3.metric("Taux de résolution", f"{taux_resolution:.1f} %")

    # Courbe temporelle
    st.markdown("### 📈 Evolution des incidents dans le temps")
    df_filtered["Date_Heure"] = pd.to_datetime(df_filtered["Date_Heure"], errors='coerce')
    incidents_par_jour = df_filtered.groupby(df_filtered["Date_Heure"].dt.date).size().reset_index(name="Nombre d'incidents")
    fig = px.line(incidents_par_jour, x="Date_Heure", y="Nombre d'incidents", markers=True)
    st.plotly_chart(fig, use_container_width=True)

    # Répartition par type
    st.markdown("### 🧨 Répartition des types d'incidents")
    fig2 = px.pie(df_filtered, names=type_col, title="Répartition par type d'incident", hole=0.4)
    st.plotly_chart(fig2, use_container_width=True)

    # Heatmap des incidents critiques
    st.markdown("### 🚨 Heatmap des incidents critiques par jour et heure")
    df_crit = df_filtered[df_filtered["Sévérité"] == "Critique"].copy()
    if not df_crit.empty:
        df_crit["Jour"] = df_crit["Date_Heure"].dt.strftime("%A")
        df_crit["Heure"] = df_crit["Date_Heure"].dt.hour
        pivot = df_crit.pivot_table(index="Jour", columns="Heure", values=type_col, aggfunc="count").fillna(0)
        fig3, ax = plt.subplots(figsize=(12, 5))
        sns.heatmap(pivot, cmap="Reds", annot=True, fmt=".0f", linewidths=0.5, ax=ax)
        st.pyplot(fig3)
    else:
        st.info("Aucun incident critique trouvé pour la période sélectionnée.")

    # Détail des incidents critiques
    with st.expander("📋 Détails des incidents critiques"):
        df_crit_detail = df_filtered[df_filtered["Sévérité"] == "Critique"]
        st.dataframe(df_crit_detail)

    # Analyse des tendances
    st.markdown("### 📌 Analyse Automatisée")
    st.write(analyse_tendance(df_filtered, type_col))


def analyse_tendance(df, type_col):
    output = ""

    if df.empty:
        return "Aucune donnée à analyser."

    nb_total = len(df)
    nb_crit = len(df[df["Sévérité"] == "Critique"])
    taux_critique = (nb_crit / nb_total) * 100 if nb_total else 0

    if taux_critique > 30:
        output += f"🔴 Le pourcentage d'incidents critiques est élevé ({taux_critique:.1f} %). Cela nécessite une investigation approfondie.\n\n"
    else:
        output += f"🟢 Le taux d'incidents critiques est sous contrôle ({taux_critique:.1f} %).\n\n"

    types_freq = df[type_col].value_counts()
    top_type = types_freq.idxmax()
    output += f"📌 Le type d'incident le plus fréquent est : **{top_type}** ({types_freq.max()} cas).\n"

    if "Résolu" in df["Statut"].values:
        taux_resolution = len(df[df["Statut"] == "Résolu"]) / nb_total * 100
        if taux_resolution < 60:
            output += f"⚠️ Le taux de résolution est faible ({taux_resolution:.1f} %). Un suivi des tickets en attente est recommandé.\n"
        else:
            output += f"✅ Le taux de résolution est satisfaisant ({taux_resolution:.1f} %).\n"

    return output
