import streamlit as st
from modules import ingen_network, ingen_sec, ingen_sec_app, tech, administrateur, superviseur
from modules import log_sys, incident_auto, sim_attaque
# NOUVEAUX IMPORTS IA - CORRIGÉ
from modules.ia_models import ThreatDetectionModels, ModelConfig
from modules.data_processor import DataProcessor  # Changé: DataPreprocessor n'existe pas
from modules.correlation_engine import CorrelationEngine
from modules.recommendations import RecommendationEngine
from modules.threat_intel import ThreatIntelligence

import pandas as pd
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import socket
import time
import hashlib

st.set_page_config(
    page_title="Plateforme à base d’IA pour la gestion et l’investigation des menaces de sécurité ",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DATA_FILE = "data/incidents.xlsx"
AI_DATA_FILE = "data2/network_logs.csv"

USERS = {
    "superviseur": {"password": "sup123", "role": "Superviseur"},
    "ingenieur_sec": {"password": "sec123", "role": "Ingénieur Sécurité"},
    "ingenieur_sec_app": {"password": "app123", "role": "Ingénieur Sécurité Applicative"},
    "ingenieur_res": {"password": "res123", "role": "Ingénieur Réseau"},
    "technicien": {"password": "tech123", "role": "Technicien"},
    "admin": {"password": "admin123", "role": "Administrateur"}
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@st.cache_data
def load_data():
    if os.path.exists(DATA_FILE):
        return pd.read_excel(DATA_FILE, sheet_name="Tous_Incidents")
    else:
        st.error("Fichier incidents.xlsx introuvable dans le dossier data/")
        return pd.DataFrame()

@st.cache_data
def load_ai_data():
    """Charge les données pour l'IA (fichier CSV généré)"""
    if os.path.exists(AI_DATA_FILE):
        return pd.read_csv(AI_DATA_FILE)
    else:
        return None

def fetch_data_from_ip(ip_address):
    try:
        socket.inet_aton(ip_address)
        st.success(f"Connexion établie avec {ip_address}")
        time.sleep(2)
        return load_data()
    except socket.error:
        st.error("Adresse IP invalide ou serveur inaccessible")
        return pd.DataFrame()

def generate_pdf_report(df, filename="rapport_incidents.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Rapport d'Incidents de Sécurité", styles['Title']))
    elements.append(Paragraph(f"Généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    data = [df.columns.tolist()] + df.values.tolist()

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements.append(table)
    doc.build(elements)
    return filename

def authenticate(username, password):
    if username in USERS:
        hashed_password = hash_password(password)
        stored_password = hash_password(USERS[username]["password"])
        if hashed_password == stored_password:
            return True, USERS[username]["role"]
    return False, None

def load_logos():
    col1, col2 = st.columns([1, 3])
    with col1:
        if os.path.exists("images/logo_tt.png"):
            st.image("images/logo_tt.png", width=150)
        else:
            st.write("🏢 TT")
    with col2:
        if os.path.exists("images/logo_umt.png"):
            st.image("images/logo_umt.png", width=150)
        else:
            st.write("🎓 UMT")

def initialize_ai_models():
    """Initialise les modèles IA dans session_state"""
    if 'ai_models' not in st.session_state:
        with st.spinner("Chargement des modèles IA..."):
            try:
                st.session_state.ai_models = ThreatDetectionModels()
                st.session_state.ai_models.train_all_models()
                st.session_state.models_initialized = True
            except Exception as e:
                st.error(f"Erreur d'initialisation des modèles IA: {e}")
                st.session_state.models_initialized = False

def main():
    load_logos()

    st.markdown("""
    <div style="background-color:#0E1117;padding:20px;border-radius:10px;margin-bottom:20px">
        <h1 style="color:#ffffff;text-align:center">Plateforme à base d’IA pour la gestion et l’investigation des menaces de sécurité</h1>
        <h3 style="color:#ffffff;text-align:center">Projet de fin d'études</h3>
        <p style="color:#ffffff;text-align:center">Elaboré par : Ismaila BAH, étudiant en Master Professionnel en Cloud Computing et Virtualisation | Encadré par : Nizar Haj Ferjani</p>
    </div>
    """, unsafe_allow_html=True)

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'username' not in st.session_state:
        st.session_state.username = ""

    if not st.session_state.authenticated:
        st.sidebar.title("Authentification")
        username = st.sidebar.text_input("Nom d'utilisateur")
        password = st.sidebar.text_input("Mot de passe", type="password")

        if st.sidebar.button("Se connecter"):
            authenticated, role = authenticate(username, password)
            if authenticated:
                st.session_state.authenticated = True
                st.session_state.user_role = role
                st.session_state.username = username
                initialize_ai_models()
                st.rerun()
            else:
                st.sidebar.error("Identifiants incorrects")
        return

    st.sidebar.title("Configuration")
    st.sidebar.write(f"Connecté en tant que : **{st.session_state.user_role}**")
    st.sidebar.write(f"Utilisateur : **{st.session_state.username}**")

    if st.sidebar.button("Se déconnecter"):
        st.session_state.authenticated = False
        st.session_state.user_role = None
        st.session_state.username = None
        st.rerun()

    st.sidebar.title("Source des données")
    data_source = st.sidebar.radio("Choisir la source des données", 
                                   ["Fichier local (incidents.xlsx)", 
                                    "Adresse IP source",
                                    "Données IA (network_logs.csv)"])

    if data_source == "Adresse IP source":
        ip_address = st.sidebar.text_input("Adresse IP du serveur de données", "192.168.1.100")
        df = fetch_data_from_ip(ip_address)
        ai_df = None
    elif data_source == "Données IA (network_logs.csv)":
        df = load_data()
        ai_df = load_ai_data()
        if ai_df is None:
            st.warning("⚠️ Fichier network_logs.csv introuvable. Exécutez d'abord: python data2/generate_data.py")
    else:
        df = load_data()
        ai_df = None

    # Menu avec les nouvelles fonctionnalités IA
    menu_options = [
        "Dashboard principal",
        "Analyse des Logs Système",
        "Rapport d'Incidents Automatisé",
        "Simulation d'Attaque"
    ]
    
    if st.session_state.user_role in ["Ingénieur Sécurité", "Administrateur", "Superviseur"]:
        menu_options.extend([
            "🔍 Détection IA",
            "🔄 Corrélation des menaces",
            "💡 Recommandations IA",
            "🔎 Investigation avancée",
            "⚙️ Configuration IA"
        ])
    
    page = st.sidebar.selectbox("Menu principal", menu_options)

    if page == "Dashboard principal":
        if st.session_state.user_role == "Superviseur":
            superviseur.display(df)
        elif st.session_state.user_role == "Ingénieur Sécurité":
            ingen_sec.display(df)
        elif st.session_state.user_role == "Ingénieur Sécurité Applicative":
            ingen_sec_app.display(df)
        elif st.session_state.user_role == "Ingénieur Réseau":
            ingen_network.display(df)
        elif st.session_state.user_role == "Technicien":
            tech.display(df)
        elif st.session_state.user_role == "Administrateur":
            administrateur.display(df)
        else:
            st.info("Sélectionnez un tableau de bord")

    elif page == "Analyse des Logs Système":
        log_sys.display()

    elif page == "Rapport d'Incidents Automatisé":
        incident_auto.display(df)

    elif page == "Simulation d'Attaque":
        sim_attaque.display()

    elif page == "🔍 Détection IA":
        from pages.detection_ia import display_detection_ia
        if ai_df is not None:
            display_detection_ia(ai_df, st.session_state.ai_models)
        else:
            st.warning("Veuillez sélectionner la source 'Données IA'")

    elif page == "🔄 Corrélation des menaces":
        from pages.correlation import display_correlation
        if ai_df is not None:
            display_correlation(ai_df, st.session_state.ai_models)
        else:
            st.warning("Veuillez sélectionner la source 'Données IA'")

    elif page == "💡 Recommandations IA":
        from pages.recommandations import display_recommendations
        if ai_df is not None:
            display_recommendations(ai_df, st.session_state.ai_models)
        else:
            st.warning("Veuillez sélectionner la source 'Données IA'")

    elif page == "🔎 Investigation avancée":
        from pages.investigation import display_investigation
        if ai_df is not None:
            display_investigation(ai_df)
        else:
            st.warning("Veuillez sélectionner la source 'Données IA'")

    elif page == "⚙️ Configuration IA":
        from pages.configuration import display_configuration
        display_configuration()

    if st.checkbox("Afficher les données brutes"):
        if ai_df is not None:
            st.dataframe(ai_df.head(100))
        else:
            st.dataframe(df)

if __name__ == "__main__":
    main()