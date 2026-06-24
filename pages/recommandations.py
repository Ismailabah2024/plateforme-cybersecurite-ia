#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PAGE DE RECOMMANDATIONS IA - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Génération automatique d'actions correctives
    - Suggestion de règles firewall (iptables/ufw)
    - Recommandations d'isolation de machines
    - Export en checklist
    - Playbooks de réponse automatisés
================================================================================
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import json
import os
import sys
import random
import uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# CONFIGURATION DES RECOMMANDATIONS
# ============================================================================

class RecommendationEngine:
    """Moteur de génération de recommandations"""
    
    # Base de connaissances des actions par type de menace
    THREAT_ACTIONS = {
        'DDoS': {
            'immediate': [
                "🛑 Activer la limitation de débit (rate limiting) sur le pare-feu",
                "🔒 Mettre en place une règle de blocage géographique si l'attaque provient de l'étranger",
                "📊 Activer la protection anti-DDoS du FAI/Cloudflare",
                "🔄 Rediriger le trafic vers un service de nettoyage (scrubbing center)",
                "📈 Contacter le NOC pour augmentation de bande passante"
            ],
            'firewall_rules': [
                "iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute -j ACCEPT",
                "iptables -A INPUT -m recent --name ddos --update --seconds 60 --hitcount 100 -j DROP"
            ],
            'isolation': "Isoler le serveur cible du réseau de production, rediriger le trafic vers un honeypot",
            'playbook': "ddos_response_playbook",
            'priority': 'Critique',
            'sla_minutes': 15
        },
        'Brute Force': {
            'immediate': [
                "🔐 Désactiver temporairement le compte utilisateur ciblé",
                "📝 Mettre en place une politique de verrouillage après 3 échecs",
                "🌍 Bloquer l'IP source via fail2ban ou équivalent",
                "🔑 Forcer une réinitialisation de mot de passe"
            ],
            'firewall_rules': [
                "iptables -A INPUT -s {src_ip} -j DROP",
                "fail2ban-client set ssh banip {src_ip}",
                "iptables -A INPUT -p tcp --dport 22 -m recent --name bruteforce --update --seconds 60 --hitcount 4 -j DROP"
            ],
            'isolation': "Isoler la machine source compromise, désactiver les comptes suspects",
            'playbook': "bruteforce_response_playbook",
            'priority': 'Haute',
            'sla_minutes': 30
        },
        'Port Scan': {
            'immediate': [
                "🔍 Analyser les logs pour identifier les ports scannés",
                "🛡️ Activer le mode furtif (stealth mode) sur les services exposés",
                "📡 Mettre en place un honeypot pour identifier l'attaquant",
                "📊 Réaliser un audit des ports ouverts inutiles"
            ],
            'firewall_rules': [
                "iptables -A INPUT -p tcp --tcp-flags ALL SYN -m limit --limit 1/s -j ACCEPT",
                "iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP"
            ],
            'isolation': "Aucune isolation requise, mais surveillance renforcée",
            'playbook': "portscan_response_playbook",
            'priority': 'Moyenne',
            'sla_minutes': 120
        },
        'Malware': {
            'immediate': [
                "⚠️ ISOLER IMMÉDIATEMENT la machine infectée du réseau",
                "🔄 Désactiver les comptes de service compromis",
                "📸 Capturer la mémoire vive pour analyse forensique",
                "🔬 Scanner les systèmes adjacents pour détection de propagation"
            ],
            'firewall_rules': [
                "iptables -A OUTPUT -s {src_ip} -j DROP",
                "iptables -A FORWARD -s {src_ip} -j DROP"
            ],
            'isolation': "ISOLEMENT IMMÉDIAT de la machine du réseau (débrancher physiquement)",
            'playbook': "malware_response_playbook",
            'priority': 'Critique',
            'sla_minutes': 10
        },
        'Phishing': {
            'immediate': [
                "📧 Bloquer l'expéditeur au niveau du passerelle email",
                "🔗 Désactiver les URLs malveillantes sur le proxy",
                "👥 Informer les utilisateurs ayant reçu le mail",
                "🗑️ Supprimer les emails malveillants des boîtes"
            ],
            'firewall_rules': [
                "iptables -A OUTPUT -d {malicious_domain} -j REJECT",
                "echo '127.0.0.1 {malicious_domain}' >> /etc/hosts"
            ],
            'isolation': "Aucune isolation réseau, mais réinitialisation des mots de passe utilisateurs",
            'playbook': "phishing_response_playbook",
            'priority': 'Haute',
            'sla_minutes': 60
        },
        'SQL Injection': {
            'immediate': [
                "🛡️ Activer le WAF (Web Application Firewall)",
                "🔍 Analyser les logs d'accès pour identifier la requête malveillante",
                "📝 Corriger la vulnérabilité (requêtes paramétrées)",
                "🗄️ Vérifier l'intégrité des données en base"
            ],
            'firewall_rules': [
                "iptables -A INPUT -p tcp --dport 80 -m string --string 'union select' --algo bm -j DROP"
            ],
            'isolation': "Isoler le serveur web pour investigation",
            'playbook': "sqli_response_playbook",
            'priority': 'Haute',
            'sla_minutes': 45
        },
        'XSS': {
            'immediate': [
                "📝 Échapper les caractères spéciaux dans les entrées utilisateur",
                "🛡️ Mettre en place CSP (Content Security Policy)",
                "🔍 Scanner l'application pour identifier toutes les XSS",
                "📊 Valider et assainir toutes les entrées"
            ],
            'firewall_rules': [
                "Ajouter header: Content-Security-Policy: default-src 'self'"
            ],
            'isolation': "Pas d'isolation nécessaire",
            'playbook': "xss_response_playbook",
            'priority': 'Moyenne',
            'sla_minutes': 240
        },
        'Normal': {
            'immediate': [
                "✅ Trafic normal - Aucune action requise",
                "📊 Continuer la surveillance",
                "📈 Mettre à jour les modèles avec le trafic normal"
            ],
            'firewall_rules': [],
            'isolation': "Aucune",
            'playbook': None,
            'priority': 'Info',
            'sla_minutes': None
        }
    }
    
    @classmethod
    def get_recommendations(cls, threat_type: str, src_ip: str = None, dst_ip: str = None) -> dict:
        """Génère des recommandations pour un type de menace donné"""
        
        threat_type = threat_type if threat_type in cls.THREAT_ACTIONS else 'Normal'
        actions = cls.THREAT_ACTIONS[threat_type].copy()
        
        if src_ip:
            actions['firewall_rules'] = [
                rule.replace('{src_ip}', src_ip) for rule in actions['firewall_rules']
            ]
        
        if dst_ip:
            actions['firewall_rules'] = [
                rule.replace('{dst_ip}', dst_ip) for rule in actions['firewall_rules']
            ]
        
        actions['generated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        actions['threat_type'] = threat_type
        
        return actions
    
    @classmethod
    def generate_checklist(cls, recommendations: list) -> str:
        """Génère une checklist formatée"""
        checklist = f"""
# Checklist de Réponse aux Incidents
## Générée le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Actions Immédiates
"""
        for i, rec in enumerate(recommendations, 1):
            checklist += f"\n{i}. [ ] {rec.get('threat_type', 'Menace')} - {rec.get('immediate', ['Aucune action'])[0]}"
        
        checklist += "\n\n### Règles Firewall à Appliquer\n```bash\n"
        for rec in recommendations:
            for rule in rec.get('firewall_rules', []):
                checklist += f"{rule}\n"
        checklist += "```\n"
        
        checklist += f"""
### Checklist de Vérification

- [ ] L'incident a été documenté dans le système de tickets
- [ ] Les preuves ont été préservées (logs, captures)
- [ ] L'équipe SOC a été notifiée
- [ ] Le plan de remédiation est en cours d'exécution
- [ ] Les leçons apprises ont été documentées

---
**Signature de l'analyste:** __________________
**Date de clôture:** __________________
"""
        return checklist


def ensure_recommendations_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Ajoute les colonnes nécessaires pour les recommandations"""
    df = df.copy()
    
    # Colonne pour le type de menace
    if 'predicted_threat' not in df.columns:
        if 'attack_label' in df.columns:
            df['predicted_threat'] = df['attack_label']
        else:
            threats = ['DDoS', 'Brute Force', 'Port Scan', 'Malware', 'Phishing', 'Normal']
            df['predicted_threat'] = [random.choice(threats) for _ in range(len(df))]
    
    # Colonne pour le niveau de criticité
    if 'criticality_level' not in df.columns:
        if 'severity' in df.columns:
            df['criticality_level'] = df['severity']
        else:
            df['criticality_level'] = df['predicted_threat'].apply(
                lambda x: 'Critique' if x in ['DDoS', 'Malware'] else
                         'Haute' if x in ['Brute Force', 'SQL Injection'] else
                         'Moyenne' if x in ['Port Scan', 'XSS'] else
                         'Basse' if x == 'Phishing' else 'Info'
            )
    
    # Colonne src_ip
    if 'src_ip' not in df.columns:
        df['src_ip'] = [f"192.168.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(len(df))]
    
    # Colonne dst_ip
    if 'dst_ip' not in df.columns:
        df['dst_ip'] = [f"10.0.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(len(df))]
    
    # Colonne confidence_score
    if 'confidence_score' not in df.columns:
        df['confidence_score'] = [random.randint(50, 100) for _ in range(len(df))]
    
    return df


# ============================================================================
# CSS PERSONNALISÉ
# ============================================================================

def load_custom_css():
    st.markdown("""
    <style>
    .recommendation-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 15px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 4px solid;
    }
    .recommendation-critical { border-left-color: #ef4444; }
    .recommendation-high { border-left-color: #f59e0b; }
    .recommendation-medium { border-left-color: #eab308; }
    .recommendation-low { border-left-color: #10b981; }
    .recommendation-info { border-left-color: #667eea; }
    
    .rule-code {
        background-color: #1e1e1e;
        color: #d4d4d4;
        padding: 0.8rem;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        overflow-x: auto;
    }
    
    .badge-priority {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: bold;
    }
    .priority-critical { background-color: #ef4444; color: white; }
    .priority-high { background-color: #f59e0b; color: white; }
    .priority-medium { background-color: #eab308; color: white; }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# PAGE PRINCIPALE
# ============================================================================

def display_recommendations(df: pd.DataFrame, models):
    """Page principale des recommandations"""
    
    load_custom_css()
    
    # Ajout des colonnes manquantes
    df = ensure_recommendations_columns(df)
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1.5rem; border-radius: 10px; margin-bottom: 2rem; color: white; text-align: center;">
        <h1>💡 Recommandations IA</h1>
        <p>Actions correctives immédiates, règles firewall et playbooks de réponse automatisés</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        st.markdown("### 🎯 Filtres")
        
        threat_types = df['predicted_threat'].unique()
        selected_threats = st.multiselect(
            "Types de menace",
            options=threat_types,
            default=threat_types
        )
        
        severity_levels = df['criticality_level'].unique()
        selected_severities = st.multiselect(
            "Niveau de criticité",
            options=severity_levels,
            default=[s for s in severity_levels if s in ['Critique', 'Haute']]
        )
        
        st.markdown("---")
        
        st.markdown("### 📤 Export")
        include_checklist = st.checkbox("Inclure checklist d'incident", value=True)
        
        st.markdown("---")
        generate_button = st.button("🎯 GÉNÉRER LES RECOMMANDATIONS", use_container_width=True)
    
    if generate_button:
        # Filtrage des données
        filtered_df = df.copy()
        
        if selected_threats:
            filtered_df = filtered_df[filtered_df['predicted_threat'].isin(selected_threats)]
        
        if selected_severities:
            filtered_df = filtered_df[filtered_df['criticality_level'].isin(selected_severities)]
        
        if filtered_df.empty:
            st.warning("⚠️ Aucune donnée ne correspond aux filtres sélectionnés.")
            return
        
        # Regroupement des menaces par type et IP
        threats_summary = filtered_df.groupby(['predicted_threat', 'src_ip', 'dst_ip']).size().reset_index(name='count')
        threats_summary = threats_summary.sort_values('count', ascending=False)
        
        st.markdown(f"### 📊 Synthèse des Menaces ({len(threats_summary)} groupes)")
        
        # Métriques rapides
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Menaces critiques à traiter", len(threats_summary[threats_summary['predicted_threat'].isin(['DDoS', 'Malware'])]))
        with col2:
            total_actions = sum(len(RecommendationEngine.THREAT_ACTIONS.get(t, {}).get('immediate', [])) 
                              for t in threats_summary['predicted_threat'].unique())
            st.metric("Actions recommandées", total_actions)
        with col3:
            avg_sla = sum(RecommendationEngine.THREAT_ACTIONS.get(t, {}).get('sla_minutes', 0) 
                         for t in threats_summary['predicted_threat'].unique())
            avg_sla = avg_sla / len(threats_summary['predicted_threat'].unique()) if len(threats_summary) > 0 else 0
            st.metric("SLA moyen (minutes)", f"{avg_sla:.0f}")
        
        # Génération des recommandations par menace - Utilisation d'un conteneur unique
        all_recommendations = []
        
        # Utiliser un expander pour chaque recommandation au lieu de st.container
        for idx, row in threats_summary.iterrows():
            threat_type = row['predicted_threat']
            src_ip = row['src_ip']
            dst_ip = row['dst_ip']
            count = row['count']
            
            recommendations = RecommendationEngine.get_recommendations(threat_type, src_ip, dst_ip)
            recommendations['count'] = count
            all_recommendations.append(recommendations)
            
            priority_class = f"recommendation-{recommendations['priority'].lower()}"
            
            # Utiliser un expander avec un ID unique pour éviter les duplications
            expander_key = f"exp_{threat_type}_{src_ip}_{idx}_{uuid.uuid4().hex[:8]}"
            
            with st.expander(f"🎯 {threat_type} - IP: {src_ip} ({count} alertes) - {recommendations['priority']}", expanded=False):
                
                st.markdown(f"""
                <div class="recommendation-card {priority_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3>🎯 {threat_type}</h3>
                        <span class="badge-priority priority-{recommendations['priority'].lower()}">
                            {recommendations['priority']} | SLA: {recommendations['sla_minutes']} min
                        </span>
                    </div>
                    <p><strong>IP Source:</strong> <code>{src_ip}</code> | 
                       <strong>IP Destination:</strong> <code>{dst_ip}</code> | 
                       <strong>Alertes:</strong> {count}</p>
                </div>
                """, unsafe_allow_html=True)
                
                tabs = st.tabs(["⚡ Actions Immédiates", "🛡️ Règles Firewall", "🔒 Isolation", "📋 Playbook"])
                
                with tabs[0]:
                    st.markdown("#### Actions à exécuter immédiatement")
                    for action in recommendations['immediate']:
                        st.markdown(f"- {action}")
                    
                    if recommendations['sla_minutes']:
                        st.warning(f"⏰ SLA à respecter: {recommendations['sla_minutes']} minutes")
                
                with tabs[1]:
                    if recommendations['firewall_rules']:
                        st.markdown("#### Règles à appliquer")
                        for rule in recommendations['firewall_rules']:
                            st.code(rule, language='bash')
                    else:
                        st.info("Aucune règle firewall spécifique recommandée.")
                
                with tabs[2]:
                    st.markdown("#### Recommandation d'isolation")
                    st.info(recommendations['isolation'])
                    
                    if recommendations['priority'] == 'Critique':
                        st.error("⚠️ ISOLEMENT IMMÉDIAT RECOMMANDÉ")
                        # Afficher des messages sans boutons interactifs pour éviter les clés dupliquées
                        st.success("📞 Action recommandée: Isoler la machine et notifier l'équipe")
                
                with tabs[3]:
                    if recommendations['playbook']:
                        st.markdown(f"#### Playbook: {recommendations['playbook']}")
                        playbook_steps = [
                            "1. 🚨 **Détection et qualification** - Vérifier l'alerte",
                            "2. 🔍 **Analyse forensique** - Collecter les logs et preuves",
                            "3. 🛡️ **Containement** - Appliquer les règles firewall",
                            "4. 🔬 **Éradication** - Nettoyer la menace",
                            "5. 🔄 **Rétablissement** - Restaurer les services",
                            "6. 📝 **Post-mortem** - Documenter et améliorer"
                        ]
                        for step in playbook_steps:
                            st.markdown(f"- {step}")
                    else:
                        st.info("Aucun playbook spécifique requis pour le trafic normal.")
        
        # Section des exports
        st.markdown("---")
        st.markdown("### 📋 Actions Groupées")
        
        col_export1, col_export2 = st.columns(2)
        
        with col_export1:
            if include_checklist:
                checklist = RecommendationEngine.generate_checklist(all_recommendations)
                st.download_button(
                    label="📋 Télécharger Checklist",
                    data=checklist,
                    file_name=f"checklist_incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key=f"checklist_{uuid.uuid4().hex}"
                )
        
        with col_export2:
            all_rules = []
            for rec in all_recommendations:
                all_rules.extend(rec.get('firewall_rules', []))
            
            if all_rules:
                rules_script = "#!/bin/bash\n# Règles firewall générées automatiquement\n\n"
                rules_script += "\n".join(all_rules)
                st.download_button(
                    label="🛡️ Télécharger Script Firewall",
                    data=rules_script,
                    file_name=f"firewall_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh",
                    mime="text/plain",
                    use_container_width=True,
                    key=f"firewall_{uuid.uuid4().hex}"
                )
        
        # Graphique des priorités
        if all_recommendations:
            st.markdown("### 📊 Dashboard des Actions")
            
            priorities = [rec['priority'] for rec in all_recommendations]
            priority_counts = pd.Series(priorities).value_counts()
            
            fig = go.Figure(data=[go.Pie(
                labels=priority_counts.index,
                values=priority_counts.values,
                hole=0.4,
                marker_colors=['#ef4444', '#f59e0b', '#eab308', '#10b981']
            )])
            fig.update_layout(title="Répartition par Priorité", height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.markdown("""
        <div style="text-align: center; padding: 50px;">
            <h2>💡 Générateur de Recommandations</h2>
            <p style="color: #666;">Configurez les filtres et cliquez sur "Générer les recommandations"</p>
            <div style="background-color: #f8f9fa; border-radius: 10px; padding: 20px; margin-top: 20px;">
                <h4>📋 Types de recommandations disponibles</h4>
                <table style="width: 100%; text-align: left;">
                    <tr><th>Type de menace</th><th>Actions immédiates</th><th>SLA</th></tr>
                    <tr><td>DDoS</td><td>Rate limiting, blocage géographique</td><td>15 min</td></tr>
                    <tr><td>Brute Force</td><td>Fail2ban, blocage IP</td><td>30 min</td></tr>
                    <tr><td>Malware</td><td>Isolation immédiate</td><td>10 min</td></tr>
                    <tr><td>Port Scan</td><td>Mode furtif, honeypot</td><td>120 min</td></tr>
                    <tr><td>Phishing</td><td>Blocage emails, sensibilisation</td><td>60 min</td></tr>
                    <tr><td>SQL Injection</td><td>Activation WAF, correction code</td><td>45 min</td></tr>
                </table>
            </div>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    test_file = "data2/network_logs.csv"
    if os.path.exists(test_file):
        df_test = pd.read_csv(test_file)
        display_recommendations(df_test, None)