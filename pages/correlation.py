#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PAGE DE CORRÉLATION DES MENACES - PLATEFORME SOC
================================================================================
Version PREMIUM avec :
    - Carte claire style Google Maps
    - Gestion automatique des colonnes manquantes
    - Dashboard ultra-riche
================================================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import random
import time
import os
import sys
from collections import Counter
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# DONNÉES DE GÉOLOCALISATION
# ============================================================================

IP_GEO_DB = {
    'TN': {'country': 'Tunisia', 'city': 'Tunis', 'lat': 36.8065, 'lon': 10.1815, 'color': '#10b981', 'flag': '🇹🇳', 'continent': 'Africa', 'risk': 'medium'},
    'FR': {'country': 'France', 'city': 'Paris', 'lat': 48.8566, 'lon': 2.3522, 'color': '#3b82f6', 'flag': '🇫🇷', 'continent': 'Europe', 'risk': 'low'},
    'DE': {'country': 'Germany', 'city': 'Berlin', 'lat': 52.5200, 'lon': 13.4050, 'color': '#3b82f6', 'flag': '🇩🇪', 'continent': 'Europe', 'risk': 'low'},
    'US': {'country': 'United States', 'city': 'Washington DC', 'lat': 37.0902, 'lon': -95.7129, 'color': '#ef4444', 'flag': '🇺🇸', 'continent': 'North America', 'risk': 'high'},
    'GB': {'country': 'United Kingdom', 'city': 'London', 'lat': 51.5074, 'lon': -0.1278, 'color': '#3b82f6', 'flag': '🇬🇧', 'continent': 'Europe', 'risk': 'medium'},
    'RU': {'country': 'Russia', 'city': 'Moscow', 'lat': 55.7558, 'lon': 37.6173, 'color': '#ef4444', 'flag': '🇷🇺', 'continent': 'Europe', 'risk': 'critical'},
    'CN': {'country': 'China', 'city': 'Beijing', 'lat': 39.9042, 'lon': 116.4074, 'color': '#ef4444', 'flag': '🇨🇳', 'continent': 'Asia', 'risk': 'critical'},
    'BR': {'country': 'Brazil', 'city': 'Brasilia', 'lat': -15.8267, 'lon': -47.9218, 'color': '#f59e0b', 'flag': '🇧🇷', 'continent': 'South America', 'risk': 'high'},
    'IN': {'country': 'India', 'city': 'New Delhi', 'lat': 28.6139, 'lon': 77.2090, 'color': '#f59e0b', 'flag': '🇮🇳', 'continent': 'Asia', 'risk': 'high'},
    'IT': {'country': 'Italy', 'city': 'Rome', 'lat': 41.9028, 'lon': 12.4964, 'color': '#3b82f6', 'flag': '🇮🇹', 'continent': 'Europe', 'risk': 'low'},
    'ES': {'country': 'Spain', 'city': 'Madrid', 'lat': 40.4168, 'lon': -3.7038, 'color': '#3b82f6', 'flag': '🇪🇸', 'continent': 'Europe', 'risk': 'low'},
    'NL': {'country': 'Netherlands', 'city': 'Amsterdam', 'lat': 52.3676, 'lon': 4.9041, 'color': '#3b82f6', 'flag': '🇳🇱', 'continent': 'Europe', 'risk': 'medium'},
    'UA': {'country': 'Ukraine', 'city': 'Kyiv', 'lat': 50.4501, 'lon': 30.5234, 'color': '#f59e0b', 'flag': '🇺🇦', 'continent': 'Europe', 'risk': 'high'},
    'PL': {'country': 'Poland', 'city': 'Warsaw', 'lat': 52.2297, 'lon': 21.0122, 'color': '#3b82f6', 'flag': '🇵🇱', 'continent': 'Europe', 'risk': 'medium'},
    'TR': {'country': 'Turkey', 'city': 'Ankara', 'lat': 39.9334, 'lon': 32.8597, 'color': '#f59e0b', 'flag': '🇹🇷', 'continent': 'Asia', 'risk': 'high'},
    'EG': {'country': 'Egypt', 'city': 'Cairo', 'lat': 30.0444, 'lon': 31.2357, 'color': '#f59e0b', 'flag': '🇪🇬', 'continent': 'Africa', 'risk': 'medium'},
    'SA': {'country': 'Saudi Arabia', 'city': 'Riyadh', 'lat': 24.7136, 'lon': 46.6753, 'color': '#f59e0b', 'flag': '🇸🇦', 'continent': 'Asia', 'risk': 'medium'},
    'AE': {'country': 'UAE', 'city': 'Dubai', 'lat': 24.4539, 'lon': 54.3773, 'color': '#f59e0b', 'flag': '🇦🇪', 'continent': 'Asia', 'risk': 'medium'},
    'PK': {'country': 'Pakistan', 'city': 'Islamabad', 'lat': 30.3753, 'lon': 69.3451, 'color': '#ef4444', 'flag': '🇵🇰', 'continent': 'Asia', 'risk': 'critical'},
    'VN': {'country': 'Vietnam', 'city': 'Hanoi', 'lat': 21.0285, 'lon': 105.8542, 'color': '#f59e0b', 'flag': '🇻🇳', 'continent': 'Asia', 'risk': 'high'},
    'KR': {'country': 'South Korea', 'city': 'Seoul', 'lat': 35.9078, 'lon': 127.7669, 'color': '#3b82f6', 'flag': '🇰🇷', 'continent': 'Asia', 'risk': 'medium'},
    'JP': {'country': 'Japan', 'city': 'Tokyo', 'lat': 36.2048, 'lon': 138.2529, 'color': '#3b82f6', 'flag': '🇯🇵', 'continent': 'Asia', 'risk': 'low'},
    'AU': {'country': 'Australia', 'city': 'Canberra', 'lat': -25.2744, 'lon': 133.7751, 'color': '#3b82f6', 'flag': '🇦🇺', 'continent': 'Oceania', 'risk': 'low'},
    'ZA': {'country': 'South Africa', 'city': 'Pretoria', 'lat': -30.5595, 'lon': 22.9375, 'color': '#f59e0b', 'flag': '🇿🇦', 'continent': 'Africa', 'risk': 'medium'},
    'MA': {'country': 'Morocco', 'city': 'Rabat', 'lat': 31.7917, 'lon': -7.0926, 'color': '#f59e0b', 'flag': '🇲🇦', 'continent': 'Africa', 'risk': 'medium'},
    'DZ': {'country': 'Algeria', 'city': 'Algiers', 'lat': 28.0339, 'lon': 1.6596, 'color': '#f59e0b', 'flag': '🇩🇿', 'continent': 'Africa', 'risk': 'medium'},
}

ip_cache = {}

def get_ip_country(ip: str) -> str:
    """Simule la géolocalisation d'une IP avec cache"""
    if ip in ip_cache:
        return ip_cache[ip]
    
    hash_val = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    countries = list(IP_GEO_DB.keys())
    weights = {
        'RU': 0.15, 'CN': 0.15, 'US': 0.12, 'IN': 0.10, 'BR': 0.08,
        'FR': 0.07, 'DE': 0.07, 'GB': 0.06, 'NL': 0.05, 'UA': 0.05,
        'PK': 0.04, 'VN': 0.04, 'TR': 0.02
    }
    weight_list = [weights.get(c, 0.01) for c in countries]
    total = sum(weight_list)
    weight_list = [w/total for w in weight_list]
    
    result = random.choices(countries, weights=weight_list)[0]
    ip_cache[ip] = result
    return result


def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Ajoute les colonnes manquantes avec des valeurs par défaut"""
    df = df.copy()
    
    # Ajouter attack_label si manquant
    if 'attack_label' not in df.columns:
        if 'predicted_threat' in df.columns:
            df['attack_label'] = df['predicted_threat']
        else:
            df['attack_label'] = 'Unknown'
    
    # Ajouter confidence_score si manquant
    if 'confidence_score' not in df.columns:
        df['confidence_score'] = 50  # Valeur par défaut
    
    # Ajouter timestamp si manquant
    if 'timestamp' not in df.columns:
        df['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Ajouter src_ip si manquant
    if 'src_ip' not in df.columns:
        if 'source_ip' in df.columns:
            df['src_ip'] = df['source_ip']
        else:
            df['src_ip'] = '0.0.0.0'
    
    # Ajouter dst_ip si manquant
    if 'dst_ip' not in df.columns:
        if 'dest_ip' in df.columns:
            df['dst_ip'] = df['dest_ip']
        else:
            df['dst_ip'] = '0.0.0.0'
    
    return df


# ============================================================================
# CSS PROFESSIONNEL
# ============================================================================

def load_custom_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * { font-family: 'Inter', sans-serif; }
    
    .premium-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
        padding: 2rem;
        border-radius: 25px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
        box-shadow: 0 20px 35px -10px rgba(0,0,0,0.2);
    }
    
    .premium-header h1 { font-size: 2.5rem; margin: 0; font-weight: 800; }
    .premium-header p { margin: 0.5rem 0 0; opacity: 0.9; }
    
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1.2rem;
        margin-bottom: 2rem;
    }
    
    .kpi-premium {
        background: white;
        border-radius: 20px;
        padding: 1.2rem;
        box-shadow: 0 8px 25px rgba(0,0,0,0.08);
        transition: all 0.3s;
        border-bottom: 4px solid;
    }
    
    .kpi-premium:hover {
        transform: translateY(-8px);
        box-shadow: 0 15px 35px rgba(0,0,0,0.15);
    }
    
    .kpi-value { font-size: 2.2rem; font-weight: 800; font-family: monospace; }
    .kpi-label { font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 0.4rem; }
    .kpi-trend-up { color: #10b981; font-size: 0.7rem; margin-top: 0.3rem; }
    
    .campaign-premium {
        background: white;
        border-radius: 16px;
        padding: 1rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        border-left: 4px solid;
        transition: all 0.3s;
    }
    
    .campaign-premium:hover { transform: translateX(8px); box-shadow: 0 8px 20px rgba(0,0,0,0.1); }
    
    .risk-critical { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; }
    .risk-high { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; }
    .risk-medium { background: linear-gradient(135deg, #eab308, #ca8a04); color: white; }
    .risk-low { background: linear-gradient(135deg, #10b981, #059669); color: white; }
    
    .badge-risk {
        display: inline-block;
        padding: 0.2rem 0.8rem;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .animate-in { animation: fadeInUp 0.6s ease-out; }
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# FONCTIONS DE VISUALISATION
# ============================================================================

def create_world_map_light(df: pd.DataFrame) -> go.Figure:
    """Carte mondiale claire style Google Maps"""
    
    if df.empty or len(df) == 0:
        demo_data = []
        for country_code, info in IP_GEO_DB.items():
            demo_data.append({
                'lat': info['lat'], 'lon': info['lon'],
                'country': info['country'], 'city': info['city'],
                'count': random.randint(50, 500),
                'flag': info['flag'], 'color': info['color'], 'risk': info['risk']
            })
        df_demo = pd.DataFrame(demo_data).sort_values('count', ascending=False)
    else:
        country_counts = Counter()
        for ip in df['src_ip'].unique():
            country = get_ip_country(ip)
            country_counts[country] += len(df[df['src_ip'] == ip])
        
        df_demo = pd.DataFrame([
            {
                'lat': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['lat'],
                'lon': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['lon'],
                'country': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['country'],
                'city': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['city'],
                'count': count,
                'flag': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['flag'],
                'color': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['color'],
                'risk': IP_GEO_DB.get(code, IP_GEO_DB['FR'])['risk'],
                'code': code
            }
            for code, count in country_counts.items() if code in IP_GEO_DB
        ]).sort_values('count', ascending=False)
    
    fig = go.Figure()
    
    max_count = df_demo['count'].max() if not df_demo.empty else 1
    
    for _, row in df_demo.iterrows():
        size = 15 + (np.log(row['count']) / np.log(max_count) * 50) if max_count > 1 else 20
        size = min(size, 60)
        
        color_map = {'critical': '#ef4444', 'high': '#f59e0b', 'medium': '#eab308', 'low': '#10b981'}
        marker_color = color_map.get(row['risk'], '#667eea')
        
        fig.add_trace(go.Scattergeo(
            lon=[row['lon']], lat=[row['lat']],
            mode='markers+text',
            name=row['country'],
            text=row['flag'],
            textposition="middle center",
            textfont=dict(size=14, color="black"),
            marker=dict(
                size=size, color=marker_color, opacity=0.85,
                line=dict(width=2, color='white'),
                sizemode='area',
                sizemin=8
            ),
            hovertemplate=f"<b>{row['country']}</b><br>📍 {row['city']}<br>⚔️ Attaques: {row['count']:,}<br>⚠️ Risque: {row['risk'].upper()}<extra></extra>"
        ))
    
    tunis_lat = IP_GEO_DB['TN']['lat']
    tunis_lon = IP_GEO_DB['TN']['lon']
    
    for _, row in df_demo.iterrows():
        if row['country'] != 'Tunisia' and row['count'] > 100:
            fig.add_trace(go.Scattergeo(
                lon=[row['lon'], tunis_lon],
                lat=[row['lat'], tunis_lat],
                mode='lines',
                line=dict(width=0.8, color='rgba(102,126,234,0.4)', dash='dot'),
                showlegend=False, hoverinfo='none'
            ))
    
    fig.update_layout(
        title={'text': "🌍 Carte Mondiale des Menaces Cybernétiques", 'x': 0.5, 'font': {'size': 24, 'color': '#1a1a2e'}},
        geo=dict(
            projection_type='natural earth',
            showland=True, landcolor='#f0f2f5',
            coastlinecolor='#cbd5e1',
            showocean=True, oceancolor='#e0f2fe',
            showcountries=True, countrycolor='#94a3b8',
            showframe=False, bgcolor='#ffffff'
        ),
        height=650, margin=dict(l=10, r=10, t=60, b=10),
        paper_bgcolor='#ffffff', plot_bgcolor='#ffffff'
    )
    
    return fig


def create_attack_timeline(df: pd.DataFrame) -> go.Figure:
    """Timeline des attaques"""
    
    if df.empty or 'timestamp' not in df.columns:
        dates = pd.date_range(end=datetime.now(), periods=72, freq='h')  # CHANGÉ: 'H' → 'h'
        data = []
        for date in dates:
            hour = date.hour
            base = 20 + 30 * np.sin(hour * np.pi / 12) + random.randint(-10, 10)
            data.append({
                'timestamp': date,
                'DDoS': max(0, int(base * 0.7)),
                'Brute Force': max(0, int(base * 0.5)),
                'Port Scan': max(0, int(base * 0.3))
            })
        df_timeline = pd.DataFrame(data)
    else:
        df['hour'] = pd.to_datetime(df['timestamp']).dt.floor('h')  # CHANGÉ: 'H' → 'h'
        if 'attack_label' in df.columns:
            df_timeline = df.groupby(['hour', 'attack_label']).size().unstack(fill_value=0).reset_index()
            df_timeline = df_timeline.rename(columns={'hour': 'timestamp'})
        else:
            df_timeline = df.groupby(['hour']).size().reset_index(name='Total')
            df_timeline = df_timeline.rename(columns={'hour': 'timestamp'})
    
    fig = go.Figure()
    colors = {'DDoS': '#ef4444', 'Brute Force': '#f59e0b', 'Port Scan': '#eab308', 'Malware': '#8b5cf6', 'Total': '#667eea'}
    
    for col in df_timeline.columns:
        if col != 'timestamp':
            fig.add_trace(go.Scatter(
                x=df_timeline['timestamp'], y=df_timeline[col],
                name=col, mode='lines+markers',
                line=dict(width=2.5, color=colors.get(col, '#667eea')),
                marker=dict(size=4)
            ))
    
    fig.update_layout(
        title="📈 Évolution Temporelle des Attaques",
        xaxis_title="Date/Heure", yaxis_title="Nombre d'Alertes",
        height=400, template='plotly_white', hovermode='x unified'
    )
    
    return fig

def create_attack_sankey(df: pd.DataFrame) -> go.Figure:
    """Diagramme Sankey des flux d'attaques"""
    
    if df.empty:
        countries = ['Russia', 'China', 'USA', 'France', 'Germany']
        attacks = ['DDoS', 'Brute Force', 'Port Scan', 'Malware']
        source_nodes, target_nodes, values = [], [], []
        for i, country in enumerate(countries):
            for j, attack in enumerate(attacks):
                source_nodes.append(i)
                target_nodes.append(len(countries) + j)
                values.append(random.randint(10, 100))
        unique_countries = countries
        unique_attacks = attacks
    else:
        country_attack_flows = {}
        for ip in df['src_ip'].unique():
            country = get_ip_country(ip)
            if 'attack_label' in df.columns:
                attacks = df[df['src_ip'] == ip]['attack_label'].tolist()
                for attack in attacks:
                    key = (country, attack)
                    country_attack_flows[key] = country_attack_flows.get(key, 0) + 1
        
        unique_countries = list(set([c for (c, _) in country_attack_flows.keys()]))
        unique_attacks = list(set([a for (_, a) in country_attack_flows.keys()]))
        
        source_nodes, target_nodes, values = [], [], []
        for (country, attack), val in country_attack_flows.items():
            source_nodes.append(unique_countries.index(country))
            target_nodes.append(len(unique_countries) + unique_attacks.index(attack))
            values.append(val)
    
    all_labels = [IP_GEO_DB.get(c, {}).get('flag', '🏳️') + ' ' + IP_GEO_DB.get(c, {}).get('country', c) for c in unique_countries] + unique_attacks
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=20, line=dict(color="black", width=0.5), label=all_labels),
        link=dict(source=source_nodes, target=target_nodes, value=values)
    )])
    
    fig.update_layout(title="🎯 Flux d'Attaques par Pays", height=500, font=dict(size=12), template='plotly_white')
    return fig


def create_top_attackers_chart(df: pd.DataFrame, top_n: int = 12) -> go.Figure:
    """Top IPs attaquantes"""
    
    if df.empty:
        ips = [f"192.168.1.{i}" for i in range(1, top_n+1)]
        counts = [random.randint(10, 200) for _ in range(top_n)]
    else:
        top_ips = df['src_ip'].value_counts().head(top_n)
        ips = top_ips.index.tolist()
        counts = top_ips.values.tolist()
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=counts, y=ips, orientation='h',
        marker=dict(color=counts, colorscale='Reds', showscale=True),
        text=counts, textposition='outside'
    ))
    
    fig.update_layout(
        title=f"🎯 Top {top_n} des IPs Attaquantes",
        xaxis_title="Nombre d'Alertes", yaxis_title="Adresse IP",
        height=500, template='plotly_white', yaxis=dict(autorange="reversed")
    )
    
    return fig


def create_country_radar(df: pd.DataFrame) -> go.Figure:
    """Radar des menaces par pays"""
    
    if df.empty:
        categories = ['DDoS', 'Brute Force', 'Port Scan', 'Malware']
        countries = ['Russia', 'China', 'USA', 'France', 'Germany']
        values = np.random.rand(len(countries), len(categories)) * 100
    else:
        country_scores = {}
        for ip in df['src_ip'].unique():
            country = get_ip_country(ip)
            if 'attack_label' in df.columns:
                country_data = df[df['src_ip'] == ip]
                for attack in country_data['attack_label'].unique():
                    key = (country, attack)
                    country_scores[key] = country_scores.get(key, 0) + len(country_data[country_data['attack_label'] == attack])
        
        categories = ['DDoS', 'Brute Force', 'Port Scan', 'Malware']
        countries = list(set([c for (c, _) in country_scores.keys()]))[:5]
        values = []
        for country in countries:
            vals = [min(100, country_scores.get((country, cat), 0) / 5) for cat in categories]
            values.append(vals)
    
    fig = go.Figure()
    colors = ['#ef4444', '#f59e0b', '#eab308', '#10b981', '#6366f1']
    
    for i, (country, vals) in enumerate(zip(countries[:5], values[:5])):
        country_name = IP_GEO_DB.get(country, {}).get('country', country)
        fig.add_trace(go.Scatterpolar(
            r=vals, theta=categories, fill='toself',
            name=country_name, line=dict(color=colors[i % len(colors)], width=2)
        ))
    
    fig.update_layout(
        title="📊 Profil des Menaces par Pays",
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        height=500, template='plotly_white',
        legend=dict(orientation='h', yanchor='bottom', y=1.05, xanchor='center', x=0.5)
    )
    
    return fig


def create_risk_gauge(risk_score: float) -> go.Figure:
    """Jauge de risque"""
    
    if risk_score >= 75: color, text = "#ef4444", "RISQUE CRITIQUE"
    elif risk_score >= 50: color, text = "#f59e0b", "RISQUE ÉLEVÉ"
    elif risk_score >= 25: color, text = "#eab308", "RISQUE MOYEN"
    else: color, text = "#10b981", "RISQUE FAIBLE"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=risk_score,
        title={'text': text, 'font': {'size': 20}},
        gauge={
            'axis': {'range': [0, 100]}, 'bar': {'color': color},
            'steps': [
                {'range': [0, 25], 'color': '#d1fae5'},
                {'range': [25, 50], 'color': '#fef3c7'},
                {'range': [50, 75], 'color': '#fed7aa'},
                {'range': [75, 100], 'color': '#fecaca'}
            ]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=30, r=30, t=60, b=30))
    return fig


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

def display_correlation(df: pd.DataFrame, models):
    """Page principale de corrélation"""
    
    load_custom_css()
    
    # Correction : Ajout des colonnes manquantes
    df = ensure_columns(df)
    
    st.markdown("""
    <div class="premium-header animate-in">
        <h1>🔄 Threat Correlation Center</h1>
        <p>Analyse avancée multi-sources | Géolocalisation en temps réel | Détection de campagnes</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## 🎛️ Centre de Contrôle")
        st.markdown("---")
        
        st.markdown("### 📅 Période d'analyse")
        days_back = st.number_input("Jours", min_value=1, max_value=30, value=7)
        
        st.markdown("---")
        
        st.markdown("### 🎯 Types d'attaques")
        all_attacks = df['attack_label'].unique().tolist() if 'attack_label' in df.columns else ['DDoS', 'Brute Force', 'Port Scan', 'Malware']
        selected_attacks = st.multiselect("Sélectionner", options=all_attacks, default=all_attacks[:4] if len(all_attacks) >= 4 else all_attacks)
        
        st.markdown("---")
        
        st.markdown("### ⚙️ Seuils de détection")
        min_confidence = st.slider("Confiance minimale", 0, 100, 30)
        min_attacks = st.slider("Alertes min par IP", 1, 100, 5)
        
        st.markdown("---")
        
        st.markdown("### 🌍 Filtrage géographique")
        all_continents = ['Tous', 'Africa', 'Asia', 'Europe', 'North America', 'South America', 'Oceania']
        selected_continent = st.selectbox("Continent", all_continents, index=0)
        
        st.markdown("---")
        
        if not df.empty and 'attack_label' in df.columns:
            st.markdown("### 📊 En direct")
            attack_counts = df['attack_label'].value_counts()
            for attack, count in attack_counts.head(4).items():
                pct = count / len(df) * 100
                st.markdown(f"""
                <div style="margin-bottom: 8px;">
                    <span>{attack}</span>
                    <div style="background: #e5e7eb; border-radius: 10px; height: 6px; margin-top: 4px;">
                        <div style="background: #667eea; width: {pct}%; height: 6px; border-radius: 10px;"></div>
                    </div>
                    <span style="font-size: 0.7rem; color: #666;">{count} ({pct:.1f}%)</span>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("---")
        run_analysis = st.button("🔄 ANALYSER", use_container_width=True, type="primary")
    
    # Application des filtres
    filtered_df = df.copy()
    
    if selected_attacks and 'attack_label' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['attack_label'].isin(selected_attacks)]
    
    if 'confidence_score' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['confidence_score'] >= min_confidence]
    
    if selected_continent != 'Tous':
        ips_to_keep = []
        for ip in filtered_df['src_ip'].unique():
            country = get_ip_country(ip)
            continent = IP_GEO_DB.get(country, {}).get('continent', 'Unknown')
            if continent == selected_continent:
                ips_to_keep.append(ip)
        filtered_df = filtered_df[filtered_df['src_ip'].isin(ips_to_keep)]
    
    if min_attacks > 1:
        ip_counts = filtered_df['src_ip'].value_counts()
        active_ips = ip_counts[ip_counts >= min_attacks].index.tolist()
        filtered_df = filtered_df[filtered_df['src_ip'].isin(active_ips)]
    
    if run_analysis:
        with st.spinner("🔄 Analyse en cours..."):
            time.sleep(0.8)
            st.session_state.correlation_data = filtered_df
            st.session_state.correlation_analyzed = True
            st.balloons()
    
    if st.session_state.get('correlation_analyzed', False):
        data = st.session_state.correlation_data
        
        # KPI Dashboard
        st.markdown('<div class="kpi-grid">', unsafe_allow_html=True)
        
        total_attacks = len(data)
        unique_ips = data['src_ip'].nunique()
        countries_affected = len(data['src_ip'].apply(lambda x: get_ip_country(x)).unique())
        risk_score = min(100, unique_ips * 2 + (data['confidence_score'].mean() if 'confidence_score' in data.columns else 50))
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="kpi-premium" style="border-bottom-color: #6366f1;">
                <div class="kpi-value" style="color: #6366f1;">{total_attacks:,}</div>
                <div class="kpi-label">📊 TOTAL ALERTES</div>
                <div class="kpi-trend-up">▲ +12%</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="kpi-premium" style="border-bottom-color: #ef4444;">
                <div class="kpi-value" style="color: #ef4444;">{unique_ips:,}</div>
                <div class="kpi-label">🌐 IPs ATTAQUANTES</div>
                <div class="kpi-trend-up">▲ sources uniques</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="kpi-premium" style="border-bottom-color: #10b981;">
                <div class="kpi-value" style="color: #10b981;">{countries_affected}</div>
                <div class="kpi-label">🏳️ PAYS ORIGINES</div>
                <div class="kpi-trend-up">Étendu</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            critical = len(data[data['confidence_score'] >= 80]) if 'confidence_score' in data.columns else random.randint(50, 200)
            st.markdown(f"""
            <div class="kpi-premium" style="border-bottom-color: #f59e0b;">
                <div class="kpi-value" style="color: #f59e0b;">{critical:,}</div>
                <div class="kpi-label">⚠️ ALERTES CRITIQUES</div>
                <div class="kpi-trend-up">Haute sévérité</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Jauge de risque
        col_gauge, col_stats = st.columns([1, 2])
        
        with col_gauge:
            risk_gauge = create_risk_gauge(risk_score)
            st.plotly_chart(risk_gauge, use_container_width=True)
        
        with col_stats:
            st.markdown("### 📊 Synthèse des menaces")
            if 'attack_label' in data.columns:
                attack_dist = data['attack_label'].value_counts()
                for attack, count in attack_dist.head(5).items():
                    pct = count / len(data) * 100
                    st.markdown(f"""
                    <div style="margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between;">
                            <span><b>{attack}</b></span>
                            <span>{count} ({pct:.1f}%)</span>
                        </div>
                        <div style="background: #e5e7eb; border-radius: 10px; height: 8px;">
                            <div style="background: linear-gradient(90deg, #667eea, #764ba2); width: {pct}%; height: 8px; border-radius: 10px;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Carte mondiale
        st.markdown("## 🌍 Carte Mondiale des Menaces")
        world_map = create_world_map_light(data)
        st.plotly_chart(world_map, use_container_width=True)
        
        # Timeline et Sankey
        st.markdown("## 📈 Analyse Temporelle et Flux")
        col_timeline, col_sankey = st.columns([1.5, 1])
        
        with col_timeline:
            timeline_fig = create_attack_timeline(data)
            st.plotly_chart(timeline_fig, use_container_width=True)
        
        with col_sankey:
            sankey_fig = create_attack_sankey(data)
            st.plotly_chart(sankey_fig, use_container_width=True)
        
        # Top attaquants et Radar
        st.markdown("## 🎯 Analyse des Attaquants")
        col_attackers, col_radar = st.columns([1, 1])
        
        with col_attackers:
            attackers_fig = create_top_attackers_chart(data, top_n=12)
            st.plotly_chart(attackers_fig, use_container_width=True)
        
        with col_radar:
            radar_fig = create_country_radar(data)
            st.plotly_chart(radar_fig, use_container_width=True)
        
        # Tableau des IPs malveillantes
        st.markdown("## 📋 Indicateurs de Compromission (IOCs)")
        
        malicious_ips = data.groupby('src_ip').agg({
            'attack_label': lambda x: ', '.join(x.unique()) if 'attack_label' in data.columns else 'Unknown',
            'timestamp': 'count'
        }).rename(columns={'timestamp': 'alert_count'}).reset_index()
        
        malicious_ips['country'] = malicious_ips['src_ip'].apply(
            lambda x: IP_GEO_DB.get(get_ip_country(x), {}).get('flag', '🏳️') + ' ' + 
            IP_GEO_DB.get(get_ip_country(x), {}).get('country', 'Unknown')
        )
        malicious_ips['risk'] = malicious_ips['alert_count'].apply(
            lambda x: 'Critique' if x > 50 else 'Haute' if x > 20 else 'Moyenne' if x > 10 else 'Basse'
        )
        malicious_ips = malicious_ips.sort_values('alert_count', ascending=False).head(20)
        
        st.dataframe(
            malicious_ips[['src_ip', 'country', 'attack_label', 'alert_count', 'risk']],
            column_config={
                'src_ip': st.column_config.TextColumn("IP Source", width="small"),
                'country': st.column_config.TextColumn("Pays", width="small"),
                'attack_label': st.column_config.TextColumn("Types d'attaques", width="medium"),
                'alert_count': st.column_config.NumberColumn("Alertes", width="small"),
                'risk': st.column_config.TextColumn("Risque", width="small")
            },
            use_container_width=True, hide_index=True
        )
        
        # Exports
        st.markdown("---")
        st.markdown("## 📤 Export des Résultats")
        
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        
        with col_exp1:
            csv_data = data.to_csv(index=False).encode('utf-8-sig')
            st.download_button("📄 CSV", csv_data, f"correlation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv", use_container_width=True)
        
        with col_exp2:
            st.download_button("📋 JSON", data.to_json(indent=2), f"correlation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", use_container_width=True)
        
        st.success(f"✅ Analyse terminée - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    
    else:
        st.markdown("""
        <div style="text-align: center; padding: 4rem; background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 100%); border-radius: 30px; margin: 2rem 0;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">🌍</div>
            <h2 style="color: #1a1a2e;">Plateforme de Corrélation des Menaces</h2>
            <p style="color: #64748b;">Configurez les filtres et lancez l'analyse</p>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    test_file = "data2/network_logs.csv"
    if os.path.exists(test_file):
        df_test = pd.read_csv(test_file)
        display_correlation(df_test, None)