#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PAGE D'INVESTIGATION - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Recherche avancée par IP, horodatage, type d'attaque
    - Timeline interactive
    - Extraction d'IOCs (IP, domaines, hash)
    - Génération de rapport PDF
    - Analyse forensique simplifiée
================================================================================
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import hashlib
import re
import os
import sys
import base64
from io import BytesIO

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# EXTRACTEUR D'INDICATEURS (IOC)
# ============================================================================

class IOCExtractor:
    """Extraction d'indicateurs de compromission"""
    
    @staticmethod
    def extract_ips(df: pd.DataFrame) -> list:
        """Extrait toutes les IPs uniques"""
        ips = set()
        for col in ['src_ip', 'dst_ip', 'ip']:
            if col in df.columns:
                ips.update(df[col].dropna().unique())
        return sorted(list(ips))
    
    @staticmethod
    def extract_domains(text_columns: list, df: pd.DataFrame) -> list:
        """Extrait les domaines potentiels"""
        domain_pattern = r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'
        domains = set()
        
        for col in text_columns:
            if col in df.columns:
                for text in df[col].dropna():
                    found = re.findall(domain_pattern, str(text))
                    domains.update(found)
        
        return sorted(list(domains))
    
    @staticmethod
    def extract_hashes(df: pd.DataFrame) -> list:
        """Extrait les hashs potentiels (MD5, SHA1, SHA256)"""
        hash_patterns = {
            'MD5': r'[a-fA-F0-9]{32}',
            'SHA1': r'[a-fA-F0-9]{40}',
            'SHA256': r'[a-fA-F0-9]{64}'
        }
        hashes = set()
        
        for col in df.columns:
            if df[col].dtype == 'object':
                for value in df[col].dropna():
                    for hash_type, pattern in hash_patterns.items():
                        found = re.findall(pattern, str(value))
                        for f in found:
                            hashes.add(f"{hash_type}:{f}")
        
        return sorted(list(hashes))
    
    @staticmethod
    def extract_ports(df: pd.DataFrame) -> list:
        """Extrait les ports"""
        ports = set()
        for col in ['src_port', 'dst_port', 'port']:
            if col in df.columns:
                ports.update(df[col].dropna().unique())
        return sorted(list(ports))


# ============================================================================
# GÉNÉRATEUR DE RAPPORT
# ============================================================================

class InvestigationReport:
    """Générateur de rapport d'investigation"""
    
    @staticmethod
    def generate_html_report(df: pd.DataFrame, search_criteria: dict, iocs: dict) -> str:
        """Génère un rapport HTML d'investigation"""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport d'Investigation - Plateforme SOC</title>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f0f2f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .section {{
                    padding: 20px;
                    border-bottom: 1px solid #eee;
                }}
                .section h2 {{
                    color: #1a1a2e;
                    border-left: 4px solid #667eea;
                    padding-left: 15px;
                }}
                .ioc-list {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }}
                .ioc-card {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 15px;
                    border-left: 3px solid #ef4444;
                }}
                .ioc-card h4 {{
                    margin: 0 0 10px 0;
                    color: #ef4444;
                }}
                .ioc-card code {{
                    background: #e9ecef;
                    padding: 5px;
                    border-radius: 4px;
                    font-size: 0.85rem;
                    display: inline-block;
                    margin: 2px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background: #667eea;
                    color: white;
                }}
                .footer {{
                    padding: 20px;
                    text-align: center;
                    background: #f8f9fa;
                    color: #666;
                    font-size: 0.8em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Rapport d'Investigation</h1>
                    <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>📋 Critères de recherche</h2>
                    <table>
        """
        
        for key, value in search_criteria.items():
            if value:
                html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        
        html += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>📊 Résultats de l'investigation</h2>
                    <table>
                        <tr><th>Métrique</th><th>Valeur</th></tr>
                        <tr><td>Total des événements</td><td>{}</td></tr>
                        <tr><td>Période analysée</td><td>{} - {}</td></tr>
                    </table>
                </div>
        """.format(
            len(df),
            df['timestamp'].min() if 'timestamp' in df.columns else 'N/A',
            df['timestamp'].max() if 'timestamp' in df.columns else 'N/A'
        )
        
        # Section IOC
        html += """
                <div class="section">
                    <h2>⚠️ Indicateurs de Compromission (IOCs)</h2>
                    <div class="ioc-list">
        """
        
        if iocs.get('ips'):
            html += f"""
                        <div class="ioc-card">
                            <h4>🌐 IPs Malveillantes ({len(iocs['ips'])})</h4>
                            {''.join([f'<code>{ip}</code> ' for ip in iocs['ips'][:20]])}
                        </div>
            """
        
        if iocs.get('domains'):
            html += f"""
                        <div class="ioc-card">
                            <h4>🌍 Domaines Suspects ({len(iocs['domains'])})</h4>
                            {''.join([f'<code>{domain}</code> ' for domain in iocs['domains'][:20]])}
                        </div>
            """
        
        if iocs.get('hashes'):
            html += f"""
                        <div class="ioc-card">
                            <h4>🔑 Hashs Malveillants ({len(iocs['hashes'])})</h4>
                            {''.join([f'<code>{h}</code><br>' for h in iocs['hashes'][:10]])}
                        </div>
            """
        
        html += """
                    </div>
                </div>
                
                <div class="section">
                    <h2>📝 Détail des événements</h2>
                    <table>
                        <thead>
                            <tr><th>Timestamp</th><th>IP Source</th><th>IP Destination</th><th>Type</th><th>Score</th></tr>
                        </thead>
                        <tbody>
        """
        
        display_cols = ['timestamp', 'src_ip', 'dst_ip', 'predicted_threat', 'confidence_score']
        display_cols = [col for col in display_cols if col in df.columns]
        
        for _, row in df.head(100).iterrows():
            html += "<tr>"
            for col in display_cols:
                html += f"<td>{row.get(col, 'N/A')}</td>"
            html += "</tr>"
        
        html += f"""
                        </tbody>
                    </table>
                    <p><small>Affichage des 100 premiers résultats sur {len(df)}</small></p>
                </div>
                
                <div class="footer">
                    <p>Rapport généré par la Plateforme IA de Détection des Menaces - Tunisie Telecom</p>
                    <p>Confidentiel - Usage interne uniquement</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def export_iocs_csv(iocs: dict) -> bytes:
        """Export des IOCs au format CSV"""
        rows = []
        for ioc_type, values in iocs.items():
            for value in values:
                rows.append({'IOC_Type': ioc_type.upper(), 'IOC_Value': value})
        
        df_iocs = pd.DataFrame(rows)
        return df_iocs.to_csv(index=False).encode('utf-8-sig')


# ============================================================================
# CSS PERSONNALISÉ
# ============================================================================

def load_custom_css():
    st.markdown("""
    <style>
    .investigation-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    .timeline-card {
        background: white;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 1rem;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .ioc-tag {
        display: inline-block;
        background: #f0f0f0;
        padding: 5px 10px;
        border-radius: 15px;
        margin: 3px;
        font-family: monospace;
        font-size: 0.8rem;
    }
    .ioc-tag-ip { background: #fee2e2; color: #dc2626; }
    .ioc-tag-domain { background: #fef3c7; color: #d97706; }
    .ioc-tag-hash { background: #dbeafe; color: #2563eb; }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# PAGE PRINCIPALE
# ============================================================================

def display_investigation(df: pd.DataFrame):
    """Page principale d'investigation"""
    
    load_custom_css()
    
    st.markdown("""
    <div class="investigation-header">
        <h1>🔍 Investigation et Recherche Avancée</h1>
        <p>Recherche multi-critères, extraction d'IOCs et génération de rapports forensiques</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar - Critères de recherche
    with st.sidebar:
        st.markdown("## 🔎 Critères de recherche")
        
        # Recherche par IP
        st.markdown("### 🌐 Recherche par IP")
        search_ip = st.text_input(
            "Adresse IP",
            placeholder="ex: 192.168.1.1",
            help="Recherche dans IP source et destination"
        )
        
        # Recherche par timestamp
        st.markdown("### 📅 Période")
        col1, col2 = st.columns(2)
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            min_date = df['timestamp'].min()
            max_date = df['timestamp'].max()
            
            if pd.notna(min_date) and pd.notna(max_date):
                with col1:
                    start_date = st.date_input(
                        "Date début",
                        value=min_date.date(),
                        min_value=min_date.date(),
                        max_value=max_date.date()
                    )
                with col2:
                    end_date = st.date_input(
                        "Date fin",
                        value=max_date.date(),
                        min_value=min_date.date(),
                        max_value=max_date.date()
                    )
            else:
                start_date = datetime.now().date() - timedelta(days=7)
                end_date = datetime.now().date()
        else:
            start_date = datetime.now().date() - timedelta(days=7)
            end_date = datetime.now().date()
        
        # Recherche par type
        st.markdown("### 🎯 Type de menace")
        if 'predicted_threat' in df.columns:
            threat_options = ['Tous'] + list(df['predicted_threat'].unique())
            selected_threat = st.selectbox("Type", threat_options)
        else:
            selected_threat = 'Tous'
        
        # Recherche par score
        st.markdown("### 📊 Filtres de score")
        min_confidence = st.slider(
            "Confiance minimale (%)",
            min_value=0, max_value=100, value=0
        )
        
        # Options d'export
        st.markdown("---")
        st.markdown("### 📤 Options d'export")
        export_format = st.selectbox(
            "Format d'export",
            ["HTML (Rapport complet)", "CSV (Données)", "IOCs uniquement"]
        )
        
        st.markdown("---")
        search_button = st.button("🔍 LANCER LA RECHERCHE", use_container_width=True)
    
    # Application des filtres
    filtered_df = df.copy()
    
    if search_ip:
        filtered_df = filtered_df[
            (filtered_df['src_ip'].astype(str).str.contains(search_ip, case=False, na=False)) |
            (filtered_df['dst_ip'].astype(str).str.contains(search_ip, case=False, na=False))
        ]
    
    if 'timestamp' in filtered_df.columns:
        filtered_df['timestamp'] = pd.to_datetime(filtered_df['timestamp'], errors='coerce')
        start_datetime = pd.Timestamp(start_date)
        end_datetime = pd.Timestamp(end_date) + pd.Timedelta(days=1)
        filtered_df = filtered_df[
            (filtered_df['timestamp'] >= start_datetime) & 
            (filtered_df['timestamp'] <= end_datetime)
        ]
    
    if selected_threat != 'Tous' and 'predicted_threat' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['predicted_threat'] == selected_threat]
    
    if 'confidence_score' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['confidence_score'] >= min_confidence]
    
    if search_button:
        st.markdown(f"### 📊 Résultats de l'investigation")
        st.markdown(f"**{len(filtered_df)} événements trouvés**")
        
        if filtered_df.empty:
            st.warning("Aucun résultat ne correspond aux critères de recherche.")
            return
        
        # Métriques
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            unique_src_ips = filtered_df['src_ip'].nunique() if 'src_ip' in filtered_df else 0
            st.metric("IP Sources uniques", unique_src_ips)
        
        with col2:
            unique_dst_ips = filtered_df['dst_ip'].nunique() if 'dst_ip' in filtered_df else 0
            st.metric("IP Destinations uniques", unique_dst_ips)
        
        with col3:
            if 'predicted_threat' in filtered_df:
                threat_count = filtered_df[filtered_df['predicted_threat'] != 'Normal'].shape[0]
                st.metric("Menaces détectées", threat_count)
            else:
                st.metric("Menaces détectées", "N/A")
        
        with col4:
            avg_score = filtered_df['confidence_score'].mean() if 'confidence_score' in filtered_df else 0
            st.metric("Confiance moyenne", f"{avg_score:.1f}%")
        
        # Timeline interactive
        st.markdown("### 📅 Timeline des événements")
        
        if 'timestamp' in filtered_df.columns:
            filtered_df['date'] = filtered_df['timestamp'].dt.date
            timeline_data = filtered_df.groupby('date').size().reset_index(name='count')
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=timeline_data['date'],
                y=timeline_data['count'],
                mode='lines+markers',
                name='Événements',
                fill='tozeroy',
                line=dict(color='#667eea', width=2),
                marker=dict(size=8, color='#667eea')
            ))
            
            # Ajout des seuils d'anomalie
            mean_count = timeline_data['count'].mean()
            std_count = timeline_data['count'].std()
            
            fig.add_hline(
                y=mean_count + 2*std_count,
                line_dash="dash",
                line_color="red",
                annotation_text="Seuil d'anomalie"
            )
            
            fig.update_layout(
                title="Évolution temporelle des événements",
                xaxis_title="Date",
                yaxis_title="Nombre d'événements",
                height=400,
                template='plotly_white'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Extraction des IOCs
        st.markdown("### ⚠️ Indicateurs de Compromission (IOCs)")
        
        iocs = {
            'ips': IOCExtractor.extract_ips(filtered_df),
            'domains': IOCExtractor.extract_domains(['raw_alert', 'description', 'message'], filtered_df),
            'hashes': IOCExtractor.extract_hashes(filtered_df),
            'ports': IOCExtractor.extract_ports(filtered_df)
        }
        
        col_ioc1, col_ioc2 = st.columns(2)
        
        with col_ioc1:
            st.markdown("#### 🌐 IPs")
            if iocs['ips']:
                ips_html = "".join([f'<span class="ioc-tag ioc-tag-ip">{ip}</span>' for ip in iocs['ips'][:20]])
                st.markdown(ips_html, unsafe_allow_html=True)
                if len(iocs['ips']) > 20:
                    st.caption(f"... et {len(iocs['ips']) - 20} autres")
            else:
                st.info("Aucune IP extraite")
            
            st.markdown("#### 🌍 Domaines")
            if iocs['domains']:
                domains_html = "".join([f'<span class="ioc-tag ioc-tag-domain">{d}</span>' for d in iocs['domains'][:20]])
                st.markdown(domains_html, unsafe_allow_html=True)
            else:
                st.info("Aucun domaine extrait")
        
        with col_ioc2:
            st.markdown("#### 🔑 Hashs")
            if iocs['hashes']:
                for h in iocs['hashes'][:10]:
                    st.code(h, language='text')
            else:
                st.info("Aucun hash extrait")
            
            st.markdown("#### 🔌 Ports")
            if iocs['ports']:
                ports_html = "".join([f'<span class="ioc-tag">{p}</span>' for p in iocs['ports'][:20]])
                st.markdown(ports_html, unsafe_allow_html=True)
            else:
                st.info("Aucun port extrait")
        
        # Tableau détaillé
        st.markdown("### 📋 Détail des événements")
        
        display_cols = []
        for col in ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                    'predicted_threat', 'confidence_score', 'criticality_level']:
            if col in filtered_df.columns:
                display_cols.append(col)
        
        st.dataframe(
            filtered_df[display_cols].head(500),
            use_container_width=True,
            height=400
        )
        
        # Export
        st.markdown("### 📤 Export des résultats")
        
        col_export1, col_export2, col_export3 = st.columns(3)
        
        with col_export1:
            if export_format == "HTML (Rapport complet)":
                search_criteria = {
                    'IP recherchée': search_ip or 'Toutes',
                    'Période': f"{start_date} → {end_date}",
                    'Type de menace': selected_threat,
                    'Confiance min.': f"{min_confidence}%"
                }
                html_report = InvestigationReport.generate_html_report(filtered_df, search_criteria, iocs)
                st.download_button(
                    label="📄 Télécharger Rapport HTML",
                    data=html_report,
                    file_name=f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    use_container_width=True
                )
        
        with col_export2:
            csv_data = filtered_df.to_csv(index=False).encode('utf-8-sig')
            st.download_button(
                label="📊 Télécharger CSV",
                data=csv_data,
                file_name=f"investigation_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col_export3:
            iocs_csv = InvestigationReport.export_iocs_csv(iocs)
            st.download_button(
                label="⚠️ Télécharger IOCs",
                data=iocs_csv,
                file_name=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
    
    else:
        st.markdown("""
        <div style="text-align: center; padding: 50px;">
            <h2>🔍 Outil d'Investigation</h2>
            <p style="color: #666;">Configurez vos critères de recherche dans la barre latérale et cliquez sur "Lancer la recherche"</p>
            <div style="background-color: #f8f9fa; border-radius: 10px; padding: 20px; margin-top: 20px;">
                <h4>📋 Fonctionnalités d'investigation</h4>
                <ul style="text-align: left;">
                    <li><strong>Recherche multi-critères</strong> : IP, date, type de menace, score de confiance</li>
                    <li><strong>Timeline interactive</strong> : Visualisation chronologique des événements</li>
                    <li><strong>Extraction d'IOCs</strong> : IPs, domaines, hashs, ports</li>
                    <li><strong>Rapports forensiques</strong> : Export HTML complet pour analyse</li>
                    <li><strong>Analyse de corrélation</strong> : Liens entre différentes alertes</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Aperçu des données récentes
        with st.expander("📊 Aperçu des données récentes"):
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                recent_df = df.nlargest(100, 'timestamp')
                st.dataframe(recent_df.head(100), use_container_width=True)
            else:
                st.dataframe(df.head(100), use_container_width=True)


if __name__ == "__main__":
    test_file = "../data2/network_logs.csv"
    if os.path.exists(test_file):
        df_test = pd.read_csv(test_file)
        if 'predicted_threat' not in df_test.columns and 'attack_label' in df_test.columns:
            df_test['predicted_threat'] = df_test['attack_label']
        display_investigation(df_test)