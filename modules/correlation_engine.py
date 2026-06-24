#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MOTEUR DE CORRÉLATION AVANCÉ - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Corrélation temporelle avec fenêtres glissantes
    - Corrélation spatiale (multi-sources)
    - Détection de campagnes d'attaque
    - Chaînes d'attaque multi-étapes
    - Score de criticité corrélé
    - Export des corrélations
================================================================================
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')


class CorrelationEngine:
    """Moteur de corrélation avancé pour la détection de campagnes"""
    
    def __init__(self, time_window_minutes: int = 30, similarity_threshold: float = 0.7):
        """
        Initialise le moteur de corrélation
        
        Args:
            time_window_minutes: Fenêtre temporelle pour regrouper les événements
            similarity_threshold: Seuil de similarité pour la corrélation
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.similarity_threshold = similarity_threshold
        
        # Pattern de chaînes d'attaque (MITRE ATT&CK simplifié)
        self.attack_chain_patterns = {
            'Reconnaissance': ['Port Scan', 'Network Scan', 'Vulnerability Scan', 'Service Discovery'],
            'Initial Access': ['Brute Force', 'SQL Injection', 'Phishing', 'Exploit Public'],
            'Execution': ['Malware Download', 'PowerShell', 'Script Execution', 'Command Injection'],
            'Persistence': ['Backdoor', 'Webshell', 'Registry Modification', 'Scheduled Task'],
            'Privilege Escalation': ['Privilege Abuse', 'Credential Dumping', 'Token Manipulation'],
            'Defense Evasion': ['Disable Security Tools', 'Obfuscation', 'File Deletion'],
            'Credential Access': ['Credential Dumping', 'Brute Force', 'Keylogging'],
            'Discovery': ['Network Scan', 'Account Discovery', 'System Info Discovery'],
            'Lateral Movement': ['RDP', 'SSH', 'SMB', 'Remote Execution'],
            'Collection': ['Data Staging', 'Archive Collected Data', 'Screen Capture'],
            'Exfiltration': ['DDoS', 'Data Transfer', 'C&C Communication']
        }
    
    def temporal_correlation(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Corrélation temporelle : regroupe les événements proches dans le temps
        """
        if df.empty or 'timestamp' not in df.columns:
            return df
        
        df = df.sort_values('timestamp').copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        temporal_groups = []
        current_group = 0
        last_timestamp = None
        
        for idx, row in df.iterrows():
            if last_timestamp is None:
                current_group += 1
                temporal_groups.append(current_group)
            elif (row['timestamp'] - last_timestamp) <= self.time_window:
                temporal_groups.append(current_group)
            else:
                current_group += 1
                temporal_groups.append(current_group)
            
            last_timestamp = row['timestamp']
        
        df['temporal_group_id'] = temporal_groups
        return df
    
    def spatial_correlation(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Corrélation spatiale : regroupe par IPs communes
        """
        if df.empty:
            return df
        
        # Créer un graphe de connexions entre IPs
        ip_connections = defaultdict(set)
        
        for _, row in df.iterrows():
            src = row.get('src_ip', '')
            dst = row.get('dst_ip', '')
            if src and dst:
                ip_connections[src].add(dst)
                ip_connections[dst].add(src)
        
        # Trouver les composantes connexes
        visited = set()
        groups = {}
        group_id = 0
        
        def dfs(ip, current_group):
            stack = [ip]
            while stack:
                node = stack.pop()
                if node not in visited:
                    visited.add(node)
                    groups[node] = current_group
                    for neighbor in ip_connections[node]:
                        if neighbor not in visited:
                            stack.append(neighbor)
        
        for ip in ip_connections:
            if ip not in visited:
                group_id += 1
                dfs(ip, group_id)
        
        # Assigner les groupes
        df['spatial_group_id'] = df['src_ip'].map(groups).fillna(0).astype(int)
        return df
    
    def detect_campaigns(self, df: pd.DataFrame, min_alerts: int = 3) -> pd.DataFrame:
        """
        Détecte les campagnes d'attaque
        """
        if df.empty:
            return pd.DataFrame()
        
        campaigns = []
        campaign_id = 0
        
        # Regrouper par IP source et fenêtre temporelle
        df = self.temporal_correlation(df)
        
        for (src_ip, temporal_group), group in df.groupby(['src_ip', 'temporal_group_id']):
            if len(group) >= min_alerts:
                campaign_id += 1
                
                # Types d'attaques dans la campagne
                attack_types = group['attack_label'].unique() if 'attack_label' in group else []
                
                # Score de confiance moyen
                confidence = group['confidence_score'].mean() if 'confidence_score' in group else 50
                
                # Criticité de la campagne
                if 'criticality_score' in group:
                    campaign_criticality = group['criticality_score'].mean()
                elif 'confidence_score' in group:
                    campaign_criticality = confidence
                else:
                    campaign_criticality = 50
                
                campaign_info = {
                    'campaign_id': f"CAMP_{campaign_id:04d}",
                    'src_ip': src_ip,
                    'start_time': group['timestamp'].min(),
                    'end_time': group['timestamp'].max(),
                    'alert_count': len(group),
                    'attack_types': ', '.join(attack_types),
                    'unique_attack_types': len(attack_types),
                    'avg_confidence': confidence,
                    'campaign_criticality': campaign_criticality,
                    'duration_minutes': (group['timestamp'].max() - group['timestamp'].min()).total_seconds() / 60,
                    'is_multi_stage': len(attack_types) > 1
                }
                
                campaigns.append(campaign_info)
        
        return pd.DataFrame(campaigns) if campaigns else pd.DataFrame()
    
    def detect_attack_chains(self, df: pd.DataFrame) -> List[Dict]:
        """
        Détecte des chaînes d'attaque complètes
        """
        chains = []
        
        for src_ip, group in df.groupby('src_ip'):
            group = group.sort_values('timestamp')
            
            current_chain = []
            
            for _, row in group.iterrows():
                attack = row.get('attack_label', row.get('predicted_threat', 'Unknown'))
                
                # Trouver le stage correspondant
                found_stage = None
                for stage, patterns in self.attack_chain_patterns.items():
                    if any(pattern.lower() in attack.lower() for pattern in patterns):
                        found_stage = stage
                        break
                
                if found_stage:
                    current_chain.append({
                        'stage': found_stage,
                        'attack': attack,
                        'timestamp': row['timestamp'],
                        'confidence': row.get('confidence_score', 50),
                        'src_ip': row.get('src_ip'),
                        'dst_ip': row.get('dst_ip')
                    })
            
            # Analyser la chaîne
            if len(current_chain) >= 2:
                stages_in_chain = list(set([s['stage'] for s in current_chain]))
                
                # Calculer le score de complétude
                completeness = len(stages_in_chain) / len(self.attack_chain_patterns) * 100
                
                chains.append({
                    'chain_id': f"CHAIN_{len(chains)+1:04d}",
                    'src_ip': src_ip,
                    'stages': current_chain,
                    'stage_count': len(current_chain),
                    'unique_stages': len(stages_in_chain),
                    'completeness': round(completeness, 1),
                    'start_time': current_chain[0]['timestamp'],
                    'end_time': current_chain[-1]['timestamp'],
                    'avg_confidence': np.mean([s['confidence'] for s in current_chain]),
                    'severity': self._calculate_chain_severity(current_chain)
                })
        
        return chains
    
    def _calculate_chain_severity(self, chain: List[Dict]) -> str:
        """Calcule la sévérité d'une chaîne d'attaque"""
        stages = [s['stage'] for s in chain]
        
        if 'Exfiltration' in stages or 'Lateral Movement' in stages:
            return 'Critique'
        elif 'Privilege Escalation' in stages or 'Credential Access' in stages:
            return 'Haute'
        elif 'Execution' in stages or 'Persistence' in stages:
            return 'Moyenne'
        else:
            return 'Basse'
    
    def correlate_by_ioc(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Corrélation par indicateurs de compromission
        """
        ioc_correlations = []
        
        # Extraire les IOCs potentiels
        if 'src_ip' in df.columns:
            for ip, group in df.groupby('src_ip'):
                if len(group) > 1:
                    ioc_correlations.append({
                        'ioc_type': 'IP',
                        'ioc_value': ip,
                        'alert_count': len(group),
                        'unique_targets': group['dst_ip'].nunique() if 'dst_ip' in group else 0,
                        'attack_types': ', '.join(group['attack_label'].unique()) if 'attack_label' in group else '',
                        'severity': 'Haute' if len(group) > 10 else 'Moyenne'
                    })
        
        return pd.DataFrame(ioc_correlations) if ioc_correlations else pd.DataFrame()
    
    def calculate_correlated_score(self, campaign_df: pd.DataFrame) -> pd.DataFrame:
        """
        Calcule un score de criticité corrélé pour chaque campagne
        """
        if campaign_df.empty:
            return campaign_df
        
        campaign_df = campaign_df.copy()
        
        # Normaliser les métriques
        max_alerts = campaign_df['alert_count'].max()
        campaign_df['volume_score'] = (campaign_df['alert_count'] / max_alerts * 100) if max_alerts > 0 else 0
        
        max_types = campaign_df['unique_attack_types'].max()
        campaign_df['diversity_score'] = (campaign_df['unique_attack_types'] / max_types * 100) if max_types > 0 else 0
        
        # Score de confiance
        campaign_df['confidence_score'] = campaign_df['avg_confidence']
        
        # Score de durée
        max_duration = campaign_df['duration_minutes'].max()
        campaign_df['duration_score'] = (campaign_df['duration_minutes'] / max_duration * 100) if max_duration > 0 else 0
        
        # Score combiné
        campaign_df['correlated_score'] = (
            campaign_df['volume_score'] * 0.3 +
            campaign_df['diversity_score'] * 0.3 +
            campaign_df['confidence_score'] * 0.2 +
            campaign_df['duration_score'] * 0.2
        )
        
        campaign_df['correlated_score'] = campaign_df['correlated_score'].clip(0, 100)
        
        # Niveau de criticité corrélé
        campaign_df['correlated_severity'] = campaign_df['correlated_score'].apply(
            lambda x: 'Critique' if x >= 80 else 'Haute' if x >= 60 else 
                      'Moyenne' if x >= 40 else 'Basse' if x >= 20 else 'Info'
        )
        
        return campaign_df
    
    def find_common_ips(self, df: pd.DataFrame, min_occurrences: int = 2) -> pd.DataFrame:
        """
        Trouve les IPs communes entre plusieurs alertes
        """
        common_ips = []
        
        # IPs sources communes
        if 'src_ip' in df.columns:
            src_ip_counts = df['src_ip'].value_counts()
            for ip, count in src_ip_counts[src_ip_counts >= min_occurrences].items():
                ip_alerts = df[df['src_ip'] == ip]
                common_ips.append({
                    'ip': ip,
                    'role': 'source',
                    'occurrences': count,
                    'unique_destinations': ip_alerts['dst_ip'].nunique() if 'dst_ip' in ip_alerts else 0,
                    'attack_types': ', '.join(ip_alerts['attack_label'].unique()) if 'attack_label' in ip_alerts else '',
                    'avg_confidence': ip_alerts['confidence_score'].mean() if 'confidence_score' in ip_alerts else 50
                })
        
        # IPs destinations communes
        if 'dst_ip' in df.columns:
            dst_ip_counts = df['dst_ip'].value_counts()
            for ip, count in dst_ip_counts[dst_ip_counts >= min_occurrences].items():
                ip_alerts = df[df['dst_ip'] == ip]
                common_ips.append({
                    'ip': ip,
                    'role': 'destination',
                    'occurrences': count,
                    'unique_sources': ip_alerts['src_ip'].nunique() if 'src_ip' in ip_alerts else 0,
                    'attack_types': ', '.join(ip_alerts['attack_label'].unique()) if 'attack_label' in ip_alerts else '',
                    'avg_confidence': ip_alerts['confidence_score'].mean() if 'confidence_score' in ip_alerts else 50
                })
        
        return pd.DataFrame(common_ips) if common_ips else pd.DataFrame()
    
    def full_correlation_pipeline(self, df: pd.DataFrame) -> Dict:
        """
        Pipeline complet de corrélation
        """
        results = {
            'temporal_correlated': self.temporal_correlation(df.copy()),
            'spatial_correlated': self.spatial_correlation(df.copy()),
            'campaigns': self.detect_campaigns(df),
            'attack_chains': self.detect_attack_chains(df),
            'ioc_correlations': self.correlate_by_ioc(df),
            'common_ips': self.find_common_ips(df)
        }
        
        # Ajouter les scores corrélés aux campagnes
        if not results['campaigns'].empty:
            results['campaigns'] = self.calculate_correlated_score(results['campaigns'])
        
        # Statistiques
        results['statistics'] = {
            'total_alerts': len(df),
            'campaigns_detected': len(results['campaigns']),
            'attack_chains_detected': len(results['attack_chains']),
            'iocs_found': len(results['ioc_correlations']),
            'common_ips_found': len(results['common_ips'])
        }
        
        return results


if __name__ == "__main__":
    # Test du module
    test_df = pd.DataFrame({
        'timestamp': [datetime.now() - timedelta(minutes=x) for x in range(20)],
        'src_ip': ['192.168.1.1'] * 10 + ['10.0.0.1'] * 10,
        'dst_ip': ['8.8.8.8'] * 20,
        'attack_label': ['Port Scan'] * 5 + ['Brute Force'] * 5 + ['DDoS'] * 10,
        'confidence_score': [70 + x for x in range(20)]
    })
    
    engine = CorrelationEngine(time_window_minutes=15)
    results = engine.full_correlation_pipeline(test_df)
    
    print(f"📊 Résultats de corrélation:")
    print(f"   - Campagnes: {results['statistics']['campaigns_detected']}")
    print(f"   - Chaînes d'attaque: {results['statistics']['attack_chains_detected']}")