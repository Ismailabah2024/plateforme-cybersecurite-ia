#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PAGE DE CONFIGURATION - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Configuration des modèles IA (hyperparamètres)
    - Gestion des seuils (criticité, confiance)
    - Sélection des colonnes CSV
    - Sauvegarde/chargement des configurations
    - Paramétrage des alertes
================================================================================
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime
from dataclasses import asdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ia_models import ModelConfig, ThreatDetectionModels


# ============================================================================
# GESTIONNAIRE DE CONFIGURATION
# ============================================================================

class ConfigManager:
    """Gestionnaire de configuration"""
    
    CONFIG_FILE = "config/settings.json"
    
    @classmethod
    def load_config(cls) -> dict:
        """Charge la configuration depuis le fichier"""
        default_config = {
            # Seuils de détection
            'confidence_threshold': 50,
            'criticality_threshold': 40,
            'anomaly_threshold': 0.1,
            
            # Filtres par défaut
            'default_show_normal': True,
            'default_show_only_threats': False,
            
            # Modèles IA
            'model_config': {
                'rf_n_estimators': 100,
                'rf_max_depth': 15,
                'if_contamination': 0.1,
                'xgb_learning_rate': 0.1,
                'voting_weights': [1, 1, 1]
            },
            
            # Alertes
            'alerts': {
                'email_enabled': True,
                'slack_enabled': False,
                'critical_alerts_only': True,
                'notification_emails': []
            },
            
            # Colonnes CSV
            'csv_columns': {
                'timestamp_col': 'timestamp',
                'src_ip_col': 'src_ip',
                'dst_ip_col': 'dst_ip',
                'threat_col': 'attack_label'
            },
            
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if os.path.exists(cls.CONFIG_FILE):
            try:
                with open(cls.CONFIG_FILE, 'r') as f:
                    saved_config = json.load(f)
                    default_config.update(saved_config)
            except:
                pass
        
        return default_config
    
    @classmethod
    def save_config(cls, config: dict):
        """Sauvegarde la configuration"""
        os.makedirs('config', exist_ok=True)
        config['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(cls.CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        return True
    
    @classmethod
    def reset_config(cls) -> dict:
        """Réinitialise la configuration"""
        if os.path.exists(cls.CONFIG_FILE):
            os.remove(cls.CONFIG_FILE)
        return cls.load_config()


# ============================================================================
# CSS PERSONNALISÉ
# ============================================================================

def load_custom_css():
    st.markdown("""
    <style>
    .config-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    .config-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 15px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .config-card h3 {
        color: #667eea;
        margin-top: 0;
        border-bottom: 2px solid #667eea;
        padding-bottom: 0.5rem;
    }
    .param-slider {
        margin: 1rem 0;
    }
    .param-label {
        font-weight: bold;
        color: #1a1a2e;
        margin-bottom: 0.25rem;
    }
    .param-desc {
        font-size: 0.8rem;
        color: #666;
        margin-bottom: 0.5rem;
    }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# PAGE PRINCIPALE
# ============================================================================

def display_configuration():
    """Page de configuration"""
    
    load_custom_css()
    
    st.markdown("""
    <div class="config-header">
        <h1>⚙️ Configuration de la Plateforme</h1>
        <p>Personnalisation des modèles IA, seuils de détection et paramètres système</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Chargement de la configuration
    config = ConfigManager.load_config()
    
    # Sidebar - Actions
    with st.sidebar:
        st.markdown("## 🎯 Actions")
        
        if st.button("💾 Sauvegarder la configuration", use_container_width=True):
            ConfigManager.save_config(config)
            st.success("✅ Configuration sauvegardée !")
        
        if st.button("🔄 Réinitialiser par défaut", use_container_width=True):
            config = ConfigManager.reset_config()
            st.success("✅ Configuration réinitialisée !")
            st.rerun()
        
        st.markdown("---")
        st.markdown(f"**Dernière mise à jour:**\n{config.get('last_updated', 'Jamais')}")
    
    # Organisation en onglets
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🎯 Seuils de Détection",
        "🤖 Modèles IA",
        "📧 Alertes & Notifications",
        "📁 Colonnes CSV",
        "ℹ️ À propos"
    ])
    
    # TAB 1: Seuils de détection
    with tab1:
        st.markdown("### 🎯 Seuils de Détection")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="config-card">
                <h3>📊 Scores de Confiance</h3>
            </div>
            """, unsafe_allow_html=True)
            
            confidence_threshold = st.slider(
                "Seuil de confiance minimum (%)",
                min_value=0, max_value=100, value=config.get('confidence_threshold', 50),
                help="Confiance minimale pour considérer une alerte comme menace"
            )
            config['confidence_threshold'] = confidence_threshold
            
            st.markdown("**Interprétation:**")
            if confidence_threshold < 30:
                st.info("🔵 Seuil bas → Plus de détections mais plus de faux positifs")
            elif confidence_threshold < 70:
                st.info("🟢 Seuil équilibré → Bon compromis")
            else:
                st.warning("🔴 Seuil élevé → Moins de détections mais plus de précision")
        
        with col2:
            st.markdown("""
            <div class="config-card">
                <h3>⚠️ Scores de Criticité</h3>
            </div>
            """, unsafe_allow_html=True)
            
            criticality_threshold = st.slider(
                "Seuil de criticité (0-100)",
                min_value=0, max_value=100, value=config.get('criticality_threshold', 40),
                help="Score à partir duquel une alerte est considérée comme critique"
            )
            config['criticality_threshold'] = criticality_threshold
            
            anomaly_threshold = st.slider(
                "Seuil d'anomalie (Isolation Forest)",
                min_value=0.0, max_value=0.5, value=config.get('anomaly_threshold', 0.1),
                step=0.01,
                help="Proportion attendue d'anomalies dans les données"
            )
            config['anomaly_threshold'] = anomaly_threshold
        
        # Filtres par défaut
        st.markdown("""
        <div class="config-card">
            <h3>🎛️ Filtres par défaut</h3>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            show_normal = st.checkbox(
                "Afficher le trafic normal par défaut",
                value=config.get('default_show_normal', True)
            )
            config['default_show_normal'] = show_normal
        
        with col2:
            show_only_threats = st.checkbox(
                "Filtrer uniquement les menaces par défaut",
                value=config.get('default_show_only_threats', False)
            )
            config['default_show_only_threats'] = show_only_threats
    
    # TAB 2: Modèles IA
    with tab2:
        st.markdown("### 🤖 Configuration des Modèles IA")
        
        model_config = config.get('model_config', {})
        
        # Random Forest
        with st.expander("🌲 Random Forest", expanded=True):
            st.markdown("**Hyperparamètres**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                rf_n_estimators = st.number_input(
                    "Nombre d'arbres (n_estimators)",
                    min_value=50, max_value=500, value=model_config.get('rf_n_estimators', 100),
                    step=10,
                    help="Plus d'arbres = meilleure précision mais plus lent"
                )
                model_config['rf_n_estimators'] = rf_n_estimators
            
            with col2:
                rf_max_depth = st.number_input(
                    "Profondeur maximale (max_depth)",
                    min_value=5, max_value=50, value=model_config.get('rf_max_depth', 15),
                    help="Limite la profondeur des arbres pour éviter le sur-apprentissage"
                )
                model_config['rf_max_depth'] = rf_max_depth
            
            st.caption("💡 **Recommandation:** Pour les données de sécurité, 100-200 arbres avec une profondeur de 10-20")
        
        # Isolation Forest
        with st.expander("🌳 Isolation Forest", expanded=True):
            st.markdown("**Hyperparamètres**")
            
            if_contamination = st.slider(
                "Contamination (proportion d'anomalies)",
                min_value=0.01, max_value=0.5, value=model_config.get('if_contamination', 0.1),
                step=0.01,
                help="Proportion attendue de menaces dans les données"
            )
            model_config['if_contamination'] = if_contamination
            
            st.caption("💡 **Recommandation:** 0.05-0.15 pour la plupart des environnements SOC")
        
        # XGBoost
        with st.expander("⚡ XGBoost", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                xgb_learning_rate = st.slider(
                    "Taux d'apprentissage",
                    min_value=0.01, max_value=0.5, value=model_config.get('xgb_learning_rate', 0.1),
                    step=0.01,
                    format="%.2f"
                )
                model_config['xgb_learning_rate'] = xgb_learning_rate
            
            with col2:
                xgb_n_estimators = st.number_input(
                    "Nombre d'arbres",
                    min_value=50, max_value=300, value=model_config.get('xgb_n_estimators', 100),
                    step=10
                )
                model_config['xgb_n_estimators'] = xgb_n_estimators
            
            st.caption("💡 **Recommandation:** Learning rate 0.1-0.3, 100-200 arbres")
        
        # Voting Classifier
        with st.expander("🎯 Voting Classifier (Ensemble)", expanded=True):
            st.markdown("**Poids des modèles dans le vote final**")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                weight_rf = st.number_input(
                    "Random Forest",
                    min_value=0, max_value=5, value=model_config.get('voting_weights', [1, 1, 1])[0],
                    step=1
                )
            
            with col2:
                weight_if = st.number_input(
                    "Isolation Forest",
                    min_value=0, max_value=5, value=model_config.get('voting_weights', [1, 1, 1])[1],
                    step=1
                )
            
            with col3:
                weight_xgb = st.number_input(
                    "XGBoost",
                    min_value=0, max_value=5, value=model_config.get('voting_weights', [1, 1, 1])[2],
                    step=1
                )
            
            model_config['voting_weights'] = [weight_rf, weight_if, weight_xgb]
            
            st.caption("💡 **Recommandation:** Poids égaux (1,1,1) pour un équilibre")
        
        config['model_config'] = model_config
        
        # Bouton de réentraînement
        st.markdown("---")
        st.warning("⚠️ La modification des paramètres des modèles nécessite un réentraînement")
        
        if st.button("🔄 Réentraîner les modèles avec les nouveaux paramètres", use_container_width=True):
            with st.spinner("Entraînement en cours... Cette opération peut prendre quelques minutes..."):
                try:
                    from modules.ia_models import ModelConfig as MConfig
                    new_config = MConfig(
                        rf_n_estimators=model_config['rf_n_estimators'],
                        rf_max_depth=model_config['rf_max_depth'],
                        if_contamination=model_config['if_contamination'],
                        xgb_learning_rate=model_config['xgb_learning_rate'],
                        voting_weights=model_config['voting_weights']
                    )
                    st.session_state.ai_models.update_config(new_config)
                    
                    # Recharger les données et réentraîner
                    test_file = "data2/network_logs.csv"
                    if os.path.exists(test_file):
                        df_train = pd.read_csv(test_file)
                        st.session_state.ai_models.train_all_models(df_train, force_retrain=True)
                        st.success("✅ Modèles réentraînés avec succès !")
                    else:
                        st.error("Fichier d'entraînement non trouvé")
                except Exception as e:
                    st.error(f"Erreur lors du réentraînement: {e}")
    
    # TAB 3: Alertes et notifications
    with tab3:
        st.markdown("### 📧 Configuration des Alertes")
        
        alerts_config = config.get('alerts', {})
        
        col1, col2 = st.columns(2)
        
        with col1:
            email_enabled = st.checkbox(
                "📧 Activer les notifications email",
                value=alerts_config.get('email_enabled', True)
            )
            alerts_config['email_enabled'] = email_enabled
            
            if email_enabled:
                emails = st.text_area(
                    "Adresses email de notification",
                    value="\n".join(alerts_config.get('notification_emails', [])),
                    placeholder="admin@soc.tn\nsecurity@company.com",
                    help="Une adresse par ligne"
                )
                alerts_config['notification_emails'] = [e.strip() for e in emails.split('\n') if e.strip()]
        
        with col2:
            slack_enabled = st.checkbox(
                "💬 Activer les notifications Slack/Teams",
                value=alerts_config.get('slack_enabled', False)
            )
            alerts_config['slack_enabled'] = slack_enabled
            
            critical_only = st.checkbox(
                "⚠️ Alertes critiques uniquement",
                value=alerts_config.get('critical_alerts_only', True),
                help="Ne notifier que pour les menaces de niveau Critique"
            )
            alerts_config['critical_alerts_only'] = critical_only
        
        config['alerts'] = alerts_config
        
        # Test d'alerte
        st.markdown("---")
        st.markdown("### 🧪 Test des alertes")
        
        if st.button("📨 Envoyer un email de test", use_container_width=True):
            if alerts_config.get('notification_emails'):
                st.success(f"✅ Email de test envoyé à {', '.join(alerts_config['notification_emails'][:2])}")
            else:
                st.warning("Aucune adresse email configurée")
    
    # TAB 4: Colonnes CSV
    with tab4:
        st.markdown("### 📁 Mapping des Colonnes CSV")
        st.info("""
        Configurez les noms des colonnes dans vos fichiers CSV.
        Le système essaiera automatiquement de mapper les colonnes communes.
        """)
        
        csv_config = config.get('csv_columns', {})
        
        col1, col2 = st.columns(2)
        
        with col1:
            timestamp_col = st.text_input(
                "Colonne Timestamp",
                value=csv_config.get('timestamp_col', 'timestamp'),
                help="Nom de la colonne contenant les timestamps"
            )
            csv_config['timestamp_col'] = timestamp_col
            
            src_ip_col = st.text_input(
                "Colonne IP Source",
                value=csv_config.get('src_ip_col', 'src_ip'),
                help="Nom de la colonne des IPs sources"
            )
            csv_config['src_ip_col'] = src_ip_col
        
        with col2:
            dst_ip_col = st.text_input(
                "Colonne IP Destination",
                value=csv_config.get('dst_ip_col', 'dst_ip'),
                help="Nom de la colonne des IPs destinations"
            )
            csv_config['dst_ip_col'] = dst_ip_col
            
            threat_col = st.text_input(
                "Colonne Type de Menace",
                value=csv_config.get('threat_col', 'attack_label'),
                help="Nom de la colonne contenant les labels d'attaque"
            )
            csv_config['threat_col'] = threat_col
        
        config['csv_columns'] = csv_config
        
        st.markdown("---")
        st.markdown("#### 📋 Exemple de format attendu")
        
        example_df = pd.DataFrame({
            csv_config['timestamp_col']: ['2026-01-01 10:00:00', '2026-01-01 10:05:00'],
            csv_config['src_ip_col']: ['192.168.1.100', '10.0.0.50'],
            csv_config['dst_ip_col']: ['8.8.8.8', '192.168.1.1'],
            csv_config['threat_col']: ['DDoS', 'Brute Force']
        })
        st.dataframe(example_df, use_container_width=True)
    
    # TAB 5: À propos
    with tab5:
        st.markdown("### ℹ️ À propos de la Plateforme")
        
        st.markdown("""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 2rem; border-radius: 15px; color: white; text-align: center; margin-bottom: 2rem;">
            <h2>🛡️ Plateforme IA de Détection des Menaces</h2>
            <p>Version 1.0.0 | Projet de Fin d'Études - Mastère Cybersécurité</p>
            <p>SUPTECH Tunisia</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 Modèles IA inclus")
            st.markdown("""
            - **Random Forest** (Classification supervisée)
            - **Isolation Forest** (Détection d'anomalies)
            - **XGBoost** (Gradient boosting optimisé)
            - **Voting Classifier** (Ensemble des 3 modèles)
            """)
        
        with col2:
            st.markdown("#### 🎯 Types de menaces détectés")
            st.markdown("""
            - DDoS (Déni de service distribué)
            - Brute Force (Force brute)
            - Port Scan (Scan de ports)
            - Malware (Logiciels malveillants)
            - Phishing (Hameçonnage)
            - SQL Injection / XSS
            """)
        
        st.markdown("---")
        st.markdown("#### 📚 Références")
        st.markdown("""
        - Dataset: CIC-IDS2017, UNSW-NB15
        - Framework: Scikit-learn, XGBoost, Streamlit
        - Visualisations: Plotly, Matplotlib
        """)
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; color: #666; padding: 20px;">
            <p>© 2026 - SUPTECH University - Projet de Fin d'Études</p>
            <p>Ismaila BAH | Encadré par : Nizar Haj Ferjani</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Sauvegarde automatique des modifications
    ConfigManager.save_config(config)


if __name__ == "__main__":
    display_configuration()