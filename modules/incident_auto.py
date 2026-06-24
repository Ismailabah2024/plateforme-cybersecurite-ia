import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from io import BytesIO
from fpdf import FPDF

def display(df):
    st.title("📄 Rapport d’Incidents Automatisé")

    uploaded_file = st.file_uploader("📂 Importer un fichier Excel des incidents", type=["xlsx"])
    if uploaded_file is None:
        st.info("Sélectionnez un fichier Excel contenant les incidents.")
        return

    try:
        df = pd.read_excel(uploaded_file)
    except Exception as e:
        st.error(f"Erreur lors de la lecture : {e}")
        return

    # Colonnes attendues
    expected_cols = [
        "ID_Incident",
        "Date_Incident",
        "Type_Incident",
        "Sévérité",
        "Statut",
        "Description"
    ]
    st.write("Colonnes détectées :", list(df.columns))
    missing = [col for col in expected_cols if col not in df.columns]
    if missing:
        st.warning(f"Colonnes manquantes : {missing}")
        return

    df["Date_Incident"] = pd.to_datetime(df["Date_Incident"], errors='coerce')

    # Filtrer par période
    st.sidebar.header("Filtres")
    min_date = df["Date_Incident"].min()
    max_date = df["Date_Incident"].max()

    date_range = st.sidebar.date_input("Période", [min_date, max_date], min_value=min_date, max_value=max_date)
    if len(date_range) != 2:
        st.error("Veuillez sélectionner une période valide.")
        return

    start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
    df_period = df[(df["Date_Incident"] >= start_date) & (df["Date_Incident"] <= end_date)]

    st.markdown(f"### Incidents du {start_date.date()} au {end_date.date()} ({len(df_period)} incidents)")

    # KPIs
    total_incidents = len(df_period)
    incidents_critiques = len(df_period[df_period["Sévérité"].str.lower() == "critique"])
    taux_resolution = (len(df_period[df_period["Statut"].str.lower() == "résolu"]) / total_incidents * 100) if total_incidents else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total incidents", total_incidents)
    col2.metric("Incidents critiques", incidents_critiques)
    col3.metric("Taux de résolution", f"{taux_resolution:.1f} %")

    # Graphiques
    st.markdown("### Evolution temporelle des incidents")
    incidents_par_jour = df_period.groupby(df_period["Date_Incident"].dt.date).size().reset_index(name="Nombre d'incidents")
    fig = px.line(incidents_par_jour, x="Date_Incident", y="Nombre d'incidents", markers=True)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Répartition par type d'incident")
    fig2 = px.pie(df_period, names="Type_Incident", title="Types d'incidents", hole=0.4)
    st.plotly_chart(fig2, use_container_width=True)

    # Génération rapport PDF simple
    if st.button("📥 Générer et télécharger le rapport PDF"):
        pdf = create_pdf_report(df_period, total_incidents, incidents_critiques, taux_resolution)
        st.download_button(
            label="Télécharger le rapport PDF",
            data=pdf,
            file_name=f"rapport_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )

def create_pdf_report(df, total, critiques, taux_res):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Rapport d'Incidents", ln=True, align="C")
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Date de génération : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)

    pdf.cell(0, 10, f"Total incidents : {total}", ln=True)
    pdf.cell(0, 10, f"Incidents critiques : {critiques}", ln=True)
    pdf.cell(0, 10, f"Taux de résolution : {taux_res:.1f} %", ln=True)
    pdf.ln(10)

    # Top 5 types incidents
    pdf.cell(0, 10, "Top 5 types d'incidents :", ln=True)
    top_types = df["Type_Incident"].value_counts().head(5)
    for typ, count in top_types.items():
        pdf.cell(0, 10, f" - {typ} : {count} incidents", ln=True)

    pdf_output = pdf.output(dest='S').encode('latin1')
    return pdf_output

if __name__ == "__main__":
    display()
