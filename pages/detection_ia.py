#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PAGE DE DÉTECTION IA - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Sélection du modèle (4 modèles disponibles)
    - Configuration dynamique des paramètres
    - Upload/chargement de fichiers CSV
    - Détection en temps réel
    - Visualisations interactives (Plotly)
    - Filtres avancés
    - Exports (CSV, JSON, HTML)
================================================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime
import time
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ia_models import (
    ThreatDetectionModels, ThreatVisualizer, ThreatExporter
)

# NE PAS METTRE st.set_page_config() ICI !!!


# ============================================================================
# CSS PERSONNALISÉ
# ============================================================================

def load_custom_css():
    """Charge du CSS personnalisé pour un rendu professionnel"""
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    .main-header h1 {
        margin: 0;
        font-size: 2rem;
    }
    .main-header p {
        margin: 0.5rem 0 0;
        opacity: 0.9;
    }
    .metric-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 15px;
        padding: 1.2rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        text-align: center;
        border-left: 4px solid #667eea;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #1a1a2e;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #666;
        margin-top: 0.3rem;
    }
    .severity-critical {
        background-color: #ef4444;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        display: inline-block;
    }
    .severity-high {
        background-color: #f59e0b;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .severity-medium {
        background-color: #eab308;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .severity-low {
        background-color: #10b981;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .stButton button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s;
    }
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(102,126,234,0.4);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 16px;
        background-color: #f0f0f0;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# FONCTIONS PRINCIPALES
# ============================================================================

def run_detection(df: pd.DataFrame, model_name: str, models: ThreatDetectionModels,
                  progress_bar=None) -> pd.DataFrame:
    """Exécute la détection sur le DataFrame"""
    
    if progress_bar:
        progress_bar.progress(0.3, text="Prétraitement des données...")
    
    try:
        results = models.predict(df, model_name)
        if progress_bar:
            progress_bar.progress(0.9, text="Finalisation des résultats...")
        return results
    except Exception as e:
        st.error(f"❌ Erreur lors de la détection: {str(e)}")
        return pd.DataFrame()


def create_threat_gauge(percentage: float) -> go.Figure:
    """Crée une jauge de menace circulaire"""
    
    if percentage >= 70:
        color = "#ef4444"
    elif percentage >= 40:
        color = "#f59e0b"
    else:
        color = "#10b981"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=percentage,
        title={'text': "Taux de Menaces", 'font': {'size': 16}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 30], 'color': '#d1fae5'},
                {'range': [30, 70], 'color': '#fed7aa'},
                {'range': [70, 100], 'color': '#fecaca'}
            ]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=30, r=30, t=50, b=30))
    return fig


# ============================================================================
# PAGE PRINCIPALE
# ============================================================================

def display_detection_ia(df: pd.DataFrame, models: ThreatDetectionModels):
    """Affiche la page de détection IA"""
    
    load_custom_css()
    
    # En-tête
    st.markdown("""
    <div class="main-header">
        <h1>🤖 Détection des Menaces par Intelligence Artificielle</h1>
        <p>Détection automatique, scoring de confiance et analyse prédictive des cybermenaces</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar - Configuration
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        # Sélection du modèle
        st.markdown("### 🤖 Modèle IA")
        model_options = {
            "random_forest": "🌲 Random Forest (Supervisé)",
            "isolation_forest": "🌳 Isolation Forest (Anomalies)",
            "xgboost": "⚡ XGBoost (Optimisé)",
            "voting": "🎯 Voting Classifier (Ensemble)"
        }
        
        selected_model_display = st.selectbox(
            "Choisissez le modèle",
            list(model_options.values()),
            help="Sélectionnez le modèle d'IA à utiliser"
        )
        selected_model = [k for k, v in model_options.items() if v == selected_model_display][0]
        
        # Description du modèle
        model_descriptions = {
            "random_forest": "• Classification supervisée\n• Excellente précision\n• Interprétable\n• Recommandé pour données labellisées",
            "isolation_forest": "• Détection d'anomalies\n• Idéal pour les zero-day\n• Pas besoin de labels\n• Excellente détection des outliers",
            "xgboost": "• Gradient boosting optimisé\n• Haute performance\n• Gestion des données déséquilibrées",
            "voting": "• Ensemble des modèles\n• Meilleure robustesse\n• Réduit les faux positifs"
        }
        
        with st.expander("ℹ️ Description du modèle", expanded=False):
            st.info(model_descriptions.get(selected_model, ""))
        
        # Paramètres avancés
        with st.expander("🔧 Paramètres avancés", expanded=False):
            st.markdown("##### Seuils de détection")
            confidence_threshold = st.slider(
                "Seuil de confiance minimum",
                min_value=0, max_value=100, value=50,
                help="Confiance minimale pour considérer une alerte comme menace"
            )
            
            st.markdown("##### Filtrage")
            show_normal = st.checkbox("Afficher le trafic normal", value=True)
            show_only_threats = st.checkbox("Filtrer uniquement les menaces", value=False)
        
        # Bouton de lancement
        st.markdown("---")
        run_button = st.button("🚀 LANCER LA DÉTECTION", use_container_width=True)
    
    # Zone principale
    if run_button or ('detection_results' in st.session_state and st.session_state.get('results_loaded')):
        
        if run_button:
            with st.spinner("🔄 Analyse en cours..."):
                progress_bar = st.progress(0, text="Initialisation...")
                
                results = run_detection(df, selected_model, models, progress_bar)
                
                if not results.empty:
                    st.session_state.detection_results = results
                    st.session_state.selected_model = selected_model
                    st.session_state.results_loaded = True
                
                progress_bar.progress(100, text="Terminé !")
                time.sleep(0.5)
        
        if st.session_state.get('results_loaded'):
            results = st.session_state.detection_results
            
            # Application des filtres supplémentaires
            if 'confidence_score' in results.columns:
                results = results[results['confidence_score'] >= confidence_threshold]
            
            if show_only_threats and 'is_threat' in results.columns:
                results = results[results['is_threat'] == 1]
            
            if not show_normal and 'predicted_threat' in results.columns:
                results = results[results['predicted_threat'] != 'Normal']
            
            # ================================================================
            # TAB 1 : TABLEAU DE BORD
            # ================================================================
            tab1, tab2, tab3, tab4 = st.tabs([
                "📊 Tableau de Bord", "📈 Visualisations", 
                "📋 Résultats détaillés", "📤 Exports"
            ])
            
            # TAB 1 : Tableau de bord
            with tab1:
                st.markdown("### 📊 Tableau de Bord des Menaces")
                
                # Métriques
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    total_alerts = len(results)
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{total_alerts:,}</div>
                        <div class="metric-label">📊 Total Alertes</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    threats = results['is_threat'].sum() if 'is_threat' in results else 0
                    threat_pct = (threats / total_alerts * 100) if total_alerts > 0 else 0
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{threats:,} ({threat_pct:.1f}%)</div>
                        <div class="metric-label">⚠️ Menaces Détectées</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    avg_confidence = results['confidence_score'].mean() if 'confidence_score' in results else 0
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{avg_confidence:.1f}%</div>
                        <div class="metric-label">🎯 Confiance Moyenne</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    if 'criticality_score' in results:
                        avg_criticality = results['criticality_score'].mean()
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value">{avg_criticality:.1f}</div>
                            <div class="metric-label">⚠️ Criticité Moyenne</div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value">-</div>
                            <div class="metric-label">Criticité Moyenne</div>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Jauge
                col_left, col_right = st.columns(2)
                
                with col_left:
                    threat_rate = (results['is_threat'].sum() / len(results) * 100) if len(results) > 0 else 0
                    gauge = create_threat_gauge(threat_rate)
                    st.plotly_chart(gauge, use_container_width=True)
                
                with col_right:
                    if 'predicted_threat' in results.columns:
                        dist_fig = ThreatVisualizer.plot_threat_distribution(results)
                        st.plotly_chart(dist_fig, use_container_width=True)
                
                # Top IPs
                if 'src_ip' in results.columns and 'is_threat' in results.columns:
                    top_ips_fig = ThreatVisualizer.plot_top_attackers(results, top_n=10)
                    st.plotly_chart(top_ips_fig, use_container_width=True)
                
                # Timeline
                if 'timestamp' in results.columns:
                    timeline_fig = ThreatVisualizer.plot_timeline_evolution(results)
                    st.plotly_chart(timeline_fig, use_container_width=True)
            
            # TAB 2 : Visualisations
            with tab2:
                st.markdown("### 📈 Visualisations Avancées")
                
                if 'confidence_score' in results.columns:
                    confidence_fig = ThreatVisualizer.plot_confidence_distribution(results)
                    st.plotly_chart(confidence_fig, use_container_width=True)
                
                # Heatmap de corrélation
                st.markdown("#### Matrice de Corrélation")
                numeric_cols = results.select_dtypes(include=[np.number]).columns.tolist()
                numeric_cols = [c for c in numeric_cols if c not in ['confidence_score', 'criticality_score']][:8]
                
                if len(numeric_cols) >= 2:
                    corr_matrix = results[numeric_cols].corr()
                    fig = go.Figure(data=go.Heatmap(
                        z=corr_matrix.values,
                        x=corr_matrix.columns,
                        y=corr_matrix.index,
                        colorscale='RdBu',
                        zmin=-1, zmax=1,
                        text=corr_matrix.values.round(2),
                        texttemplate='%{text}',
                        textfont={"size": 10}
                    ))
                    fig.update_layout(title="Matrice de Corrélation des Features", height=500)
                    st.plotly_chart(fig, use_container_width=True)
                
                # Distribution par sévérité
                if 'criticality_level' in results.columns:
                    severity_counts = results['criticality_level'].value_counts()
                    fig = go.Figure(go.Bar(
                        x=severity_counts.index,
                        y=severity_counts.values,
                        marker_color=['#ef4444', '#f59e0b', '#eab308', '#10b981', '#6b7280']
                    ))
                    fig.update_layout(title="Distribution par Niveau de Criticité", height=400)
                    st.plotly_chart(fig, use_container_width=True)
            
            # TAB 3 : Résultats détaillés
            with tab3:
                st.markdown("### 📋 Résultats de Détection Détaillés")
                
                # Filtres sur les résultats
                col_filter1, col_filter2, col_filter3 = st.columns(3)
                
                with col_filter1:
                    if 'predicted_threat' in results.columns:
                        threat_filter = st.multiselect(
                            "Type de menace",
                            options=results['predicted_threat'].unique(),
                            default=results['predicted_threat'].unique()
                        )
                        if threat_filter:
                            results = results[results['predicted_threat'].isin(threat_filter)]
                
                with col_filter2:
                    if 'criticality_level' in results.columns:
                        severity_filter = st.multiselect(
                            "Niveau de criticité",
                            options=results['criticality_level'].unique(),
                            default=results['criticality_level'].unique()
                        )
                        if severity_filter:
                            results = results[results['criticality_level'].isin(severity_filter)]
                
                with col_filter3:
                    search_ip = st.text_input("🔍 Rechercher par IP", placeholder="ex: 192.168.1.1")
                    if search_ip:
                        results = results[
                            results['src_ip'].str.contains(search_ip, case=False, na=False) |
                            results['dst_ip'].str.contains(search_ip, case=False, na=False)
                        ]
                
                # Colonnes à afficher
                display_cols = ['timestamp', 'src_ip', 'dst_ip', 'predicted_threat', 
                               'confidence_score', 'criticality_level']
                display_cols = [col for col in display_cols if col in results.columns]
                
                st.dataframe(
                    results[display_cols].head(1000),
                    use_container_width=True,
                    height=400
                )
                
                st.caption(f"📊 Affichage de {min(1000, len(results))} résultats sur {len(results)}")
            
            # TAB 4 : Exports
            with tab4:
                st.markdown("### 📤 Export des Résultats")
                
                col_export1, col_export2, col_export3 = st.columns(3)
                
                with col_export1:
                    csv_data = ThreatExporter.to_csv(results)
                    st.download_button(
                        label="📄 CSV",
                        data=csv_data,
                        file_name=f"detection_ia_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                
                with col_export2:
                    json_data = ThreatExporter.to_json(results)
                    st.download_button(
                        label="📋 JSON",
                        data=json_data,
                        file_name=f"detection_ia_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with col_export3:
                    html_data = ThreatExporter.to_html(results)
                    st.download_button(
                        label="🌐 HTML",
                        data=html_data,
                        file_name=f"rapport_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html",
                        use_container_width=True
                    )
                
                st.markdown("---")
                st.markdown("#### 📊 Résumé Exportable")
                
                summary_data = {
                    "Métrique": [
                        "Date de génération",
                        "Modèle utilisé",
                        "Total des alertes analysées",
                        "Menaces détectées",
                        "Taux de menaces",
                        "Score de confiance moyen",
                        "Score de criticité moyen"
                    ],
                    "Valeur": [
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        selected_model_display,
                        len(results),
                        results['is_threat'].sum() if 'is_threat' in results else 0,
                        f"{(results['is_threat'].sum() / len(results) * 100):.1f}%" if len(results) > 0 else "0%",
                        f"{results['confidence_score'].mean():.1f}%" if 'confidence_score' in results else "N/A",
                        f"{results['criticality_score'].mean():.1f}" if 'criticality_score' in results else "N/A"
                    ]
                }
                
                summary_df = pd.DataFrame(summary_data)
                st.dataframe(summary_df, use_container_width=True)
    
    else:
        # Message d'accueil
        st.markdown("""
        <div style="text-align: center; padding: 50px;">
            <h2>🚀 Prêt à lancer la détection</h2>
            <p style="color: #666;">Configurez les paramètres dans la barre latérale et cliquez sur "Lancer la détection"</p>
            <div style="background-color: #f8f9fa; border-radius: 10px; padding: 20px; margin-top: 20px; text-align: left;">
                <h4>📋 Fonctionnalités disponibles</h4>
                <ul>
                    <li>✅ 4 modèles IA (Random Forest, Isolation Forest, XGBoost, Voting)</li>
                    <li>✅ Scoring de confiance 0-100%</li>
                    <li>✅ Détection des menaces (DDoS, Brute Force, Port Scan, Malware)</li>
                    <li>✅ Visualisations interactives (Plotly)</li>
                    <li>✅ Filtres avancés (IP, type de menace)</li>
                    <li>✅ Exports (CSV, JSON, HTML)</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Aperçu des données
        with st.expander("📊 Aperçu des données chargées"):
            st.dataframe(df.head(100), use_container_width=True)
            st.caption(f"Total: {len(df)} lignes | Colonnes: {len(df.columns)}")


if __name__ == "__main__":
    from modules.ia_models import ThreatDetectionModels
    
    test_file = "data2/network_logs.csv"
    if os.path.exists(test_file):
        df_test = pd.read_csv(test_file)
        models_test = ThreatDetectionModels()
        display_detection_ia(df_test, models_test)