#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
GÉNÉRATEUR DE DONNÉES DE SÉCURITÉ - PLATEFORME IA SOC
================================================================================
Auteur : Fabien | Projet : PFE Mastère
Description : Génère des datasets réalistes pour l'entraînement des modèles IA
              de détection de menaces (DDoS, Brute Force, Port Scan, Malware)
================================================================================
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os
import hashlib
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

class DataGeneratorConfig:
    """Configuration du générateur de données"""
    
    # Types d'attaques avec leurs probabilités et caractéristiques
    ATTACK_TYPES = {
        'DDoS': {
            'probability': 0.22,
            'severity': 'Critique',
            'base_score': 85,
            'bytes_range': (50000, 500000),
            'packets_range': (5000, 50000),
            'duration_range': (30, 600),
            'ports': [80, 443, 8080, 53, 25],
            'description': 'Distribution Denial of Service - Trafic anormalement élevé'
        },
        'Brute Force': {
            'probability': 0.23,
            'severity': 'Haute',
            'base_score': 75,
            'bytes_range': (500, 5000),
            'packets_range': (100, 2000),
            'duration_range': (60, 1800),
            'ports': [22, 3389, 3306, 1433, 21],
            'description': 'Tentatives répétées d\'authentification'
        },
        'Port Scan': {
            'probability': 0.18,
            'severity': 'Moyenne',
            'base_score': 55,
            'bytes_range': (100, 2000),
            'packets_range': (50, 500),
            'duration_range': (5, 120),
            'ports': list(range(1, 1025)),
            'description': 'Exploration de ports réseau'
        },
        'Malware': {
            'probability': 0.12,
            'severity': 'Critique',
            'base_score': 90,
            'bytes_range': (10000, 100000),
            'packets_range': (500, 5000),
            'duration_range': (10, 300),
            'ports': [443, 80, 53, 8080, 4443],
            'description': 'Communication avec C&C ou téléchargement malveillant'
        },
        'Phishing': {
            'probability': 0.10,
            'severity': 'Haute',
            'base_score': 70,
            'bytes_range': (1000, 50000),
            'packets_range': (10, 500),
            'duration_range': (1, 60),
            'ports': [80, 443, 25, 587],
            'description': 'Tentative d\'hameçonnage détectée'
        },
        'Normal': {
            'probability': 0.15,
            'severity': 'Info',
            'base_score': 10,
            'bytes_range': (500, 15000),
            'packets_range': (10, 200),
            'duration_range': (0.1, 10),
            'ports': [80, 443, 53, 22, 3306],
            'description': 'Trafic réseau normal'
        }
    }
    
    # Sources de menace
    THREAT_SOURCES = ['firewall', 'ids_suricata', 'ids_snort', 'edr_crowdstrike', 
                      'edr_sentinel', 'waf_cloudflare', 'siem_splunk', 'siem_qradar',
                      'antivirus', 'hids_ossec', 'nids_zeek', 'xdr']
    
    # Protocoles réseau
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
    
    # Pays sources (pour enrichissement)
    COUNTRIES = {
        'TN': 'Tunisia', 'FR': 'France', 'DE': 'Germany', 'US': 'United States',
        'GB': 'United Kingdom', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands',
        'RU': 'Russia', 'CN': 'China', 'BR': 'Brazil', 'IN': 'India'
    }
    
    # Plages IP par pays (simulation)
    IP_RANGES = {
        'TN': [('197.0.0.0', '197.27.255.255'), ('41.224.0.0', '41.227.255.255')],
        'FR': [('80.0.0.0', '95.255.255.255'), ('193.0.0.0', '195.255.255.255')],
        'US': [('8.0.0.0', '15.255.255.255'), ('44.0.0.0', '71.255.255.255')],
        'RU': [('5.0.0.0', '5.255.255.255'), ('95.0.0.0', '95.255.255.255')],
        'CN': [('1.0.0.0', '2.255.255.255'), ('58.0.0.0', '61.255.255.255')]
    }


# ============================================================================
# GÉNÉRATEUR D'IP
# ============================================================================

class IPGenerator:
    """Générateur d'adresses IP réalistes"""
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """Convertit une IP en entier"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    @staticmethod
    def int_to_ip(ip_int: int) -> str:
        """Convertit un entier en IP"""
        return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
    
    @classmethod
    def generate_ip(cls, country: str = None) -> str:
        """Génère une IP aléatoire"""
        if country and country in DataGeneratorConfig.IP_RANGES:
            ip_range = random.choice(DataGeneratorConfig.IP_RANGES[country])
            start = cls.ip_to_int(ip_range[0])
            end = cls.ip_to_int(ip_range[1])
            ip_int = random.randint(start, end)
            return cls.int_to_ip(ip_int)
        
        # IP aléatoire
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def is_malicious_ip(ip: str, attack_type: str) -> bool:
        """Détermine si une IP est malveillante selon le type d'attaque"""
        return attack_type != 'Normal'


# ============================================================================
# GÉNÉRATEUR PRINCIPAL
# ============================================================================

class SecurityDataGenerator:
    """Générateur principal de données de sécurité"""
    
    def __init__(self, seed: int = 42):
        """Initialise le générateur avec une seed pour reproductibilité"""
        random.seed(seed)
        np.random.seed(seed)
        self.config = DataGeneratorConfig()
        self.ip_gen = IPGenerator()
        
    def generate_timestamp(self, base_date: datetime = None) -> str:
        """Génère un timestamp réaliste"""
        if base_date is None:
            base_date = datetime.now() - timedelta(days=30)
        
        # Ajoute un délai aléatoire pour simuler des logs sur 30 jours
        random_seconds = random.randint(0, 30 * 24 * 3600)
        timestamp = base_date + timedelta(seconds=random_seconds)
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    def calculate_threat_score(self, attack_type: str, packets: int, bytes_sent: int, 
                               confidence: float) -> Dict:
        """Calcule un score de menace détaillé"""
        attack_config = self.config.ATTACK_TYPES[attack_type]
        
        # Score de base selon type d'attaque
        base_score = attack_config['base_score']
        
        # Ajustement selon volume de trafic
        volume_factor = 0
        if packets > attack_config['packets_range'][1]:
            volume_factor = 10
        elif packets > attack_config['packets_range'][1] * 0.7:
            volume_factor = 5
        
        # Ajustement selon la confiance
        confidence_factor = confidence / 100 * 15
        
        # Score final
        final_score = min(100, base_score + volume_factor + confidence_factor)
        
        # Niveau de sévérité
        if final_score >= 80:
            severity = 'Critique'
        elif final_score >= 60:
            severity = 'Haute'
        elif final_score >= 40:
            severity = 'Moyenne'
        elif final_score >= 20:
            severity = 'Basse'
        else:
            severity = 'Info'
        
        return {
            'score': round(final_score, 1),
            'severity': severity,
            'base_score': base_score,
            'confidence_impact': round(confidence_factor, 1)
        }
    
    def generate_malicious_ips(self, num_ips: int = 50) -> List[str]:
        """Génère une liste d'IP malveillantes connues (threat intelligence)"""
        malicious_ips = []
        for _ in range(num_ips):
            country = random.choice(list(self.config.COUNTRIES.keys()))
            ip = self.ip_gen.generate_ip(country)
            malicious_ips.append(ip)
        return malicious_ips
    
    def generate_row(self, malicious_ips: List[str] = None) -> Dict:
        """Génère une ligne de log complète"""
        
        # Sélection du type d'attaque
        attack_types = list(self.config.ATTACK_TYPES.keys())
        probabilities = [self.config.ATTACK_TYPES[a]['probability'] for a in attack_types]
        attack_type = random.choices(attack_types, weights=probabilities)[0]
        attack_config = self.config.ATTACK_TYPES[attack_type]
        
        # Génération des données
        timestamp = self.generate_timestamp()
        
        # Pays et IP sources
        if attack_type == 'Normal':
            src_country = random.choice(['TN', 'FR', 'DE', 'US', 'GB'])
        else:
            src_country = random.choice(['RU', 'CN', 'BR', 'IN', 'US', 'NL'])
        
        src_ip = self.ip_gen.generate_ip(src_country)
        dst_country = 'TN'  # Cible principale : Tunisie
        dst_ip = self.ip_gen.generate_ip(dst_country)
        
        # Ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(attack_config['ports'])
        
        # Protocole
        protocol = random.choices(
            self.config.PROTOCOLS,
            weights=[0.35, 0.20, 0.05, 0.15, 0.15, 0.05, 0.03, 0.02]
        )[0]
        
        # Volume de trafic
        bytes_sent = random.randint(attack_config['bytes_range'][0], attack_config['bytes_range'][1])
        packets = random.randint(attack_config['packets_range'][0], attack_config['packets_range'][1])
        
        # Durée
        duration = round(random.uniform(attack_config['duration_range'][0], attack_config['duration_range'][1]), 2)
        
        # Flags TCP
        tcp_flags = random.choice(['SYN', 'ACK', 'SYN-ACK', 'RST', 'FIN', 'PSH', 'URG', 'RST-ACK'])
        
        # Confiance
        confidence_source = random.randint(60, 100) if attack_type != 'Normal' else random.randint(10, 40)
        
        # Source de menace
        threat_source = random.choice(self.config.THREAT_SOURCES)
        
        # Message d'alerte
        alert_messages = {
            'DDoS': f'Trafic anormal détecté : {packets} paquets en {duration}s depuis {src_ip}',
            'Brute Force': f'Tentatives d\'authentification répétées depuis {src_ip} sur port {dst_port}',
            'Port Scan': f'Exploration de ports depuis {src_ip} - {packets} ports scannés',
            'Malware': f'Communication suspecte détectée entre {src_ip} et {dst_ip}',
            'Phishing': f'URL de phishing détectée provenant de {src_ip}',
            'Normal': f'Trafic régulier entre {src_ip} et {dst_ip}'
        }
        
        raw_alert = alert_messages.get(attack_type, f'Alerte de sécurité: {attack_type}')
        
        # Calcul du score de menace
        threat_info = self.calculate_threat_score(attack_type, packets, bytes_sent, confidence_source)
        
        # Vérification IP malveillante
        if malicious_ips and src_ip in malicious_ips:
            threat_info['score'] = min(100, threat_info['score'] + 15)
            threat_info['severity'] = 'Critique' if threat_info['score'] >= 80 else threat_info['severity']
        
        # Construction du dictionnaire
        row = {
            # Format unifié minimal
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'bytes': bytes_sent,
            'packets': packets,
            'threat_source': threat_source,
            'raw_alert': raw_alert,
            
            # Format étendu
            'duration': duration,
            'flags': tcp_flags,
            'attack_label': attack_type,
            'confidence_source': confidence_source,
            
            # Enrichissement
            'src_country': src_country,
            'src_country_name': self.config.COUNTRIES.get(src_country, 'Unknown'),
            'dst_country': dst_country,
            'dst_country_name': self.config.COUNTRIES.get(dst_country, 'Unknown'),
            'threat_score': threat_info['score'],
            'severity': threat_info['severity'],
            'attack_description': attack_config['description'],
            'bytes_per_packet': round(bytes_sent / packets, 2) if packets > 0 else 0,
            'packets_per_second': round(packets / duration, 2) if duration > 0 else 0
        }
        
        return row
    
    def generate_dataset(self, num_samples: int = 50000, 
                        campaign_density: float = 0.3) -> pd.DataFrame:
        """
        Génère un dataset complet
        
        Args:
            num_samples: Nombre d'échantillons
            campaign_density: Densité des campagnes d'attaque (0-1)
        
        Returns:
            DataFrame avec les données générées
        """
        print(f"\n{'='*70}")
        print(f" GÉNÉRATION DU DATASET DE SÉCURITÉ")
        print(f"{'='*70}")
        print(f"📊 Échantillons demandés : {num_samples:,}")
        print(f"🎲 Campaign density : {campaign_density}")
        print(f"{'='*70}\n")
        
        # Génération des IP malveillantes
        malicious_ips = self.generate_malicious_ips(100)
        
        # Génération des données
        data = []
        attack_counts = {attack: 0 for attack in self.config.ATTACK_TYPES.keys()}
        
        # Pour simuler des campagnes, on génère des séquences d'attaques liées
        campaign_id = 0
        current_campaign = None
        campaign_remaining = 0
        
        for i in range(num_samples):
            if i % 10000 == 0 and i > 0:
                print(f"  → Progression : {i:,}/{num_samples:,} échantillons ({i*100//num_samples}%)")
            
            # Gestion des campagnes
            if campaign_remaining <= 0 and random.random() < campaign_density:
                # Début d'une nouvelle campagne
                campaign_id += 1
                campaign_type = random.choice(['DDoS', 'Brute Force', 'Port Scan', 'Malware'])
                campaign_length = random.randint(3, 15)
                campaign_remaining = campaign_length
                current_campaign = {
                    'id': campaign_id,
                    'type': campaign_type,
                    'src_ip': self.ip_gen.generate_ip('RU'),
                    'remaining': campaign_length
                }
            
            if campaign_remaining > 0 and current_campaign:
                # Générer une attaque de la campagne
                row = self.generate_row(malicious_ips)
                row['attack_label'] = current_campaign['type']
                row['src_ip'] = current_campaign['src_ip']
                row['campaign_id'] = f"CAMP_{current_campaign['id']}"
                campaign_remaining -= 1
                # Recalculer le score pour cette attaque de campagne
                attack_config = self.config.ATTACK_TYPES[current_campaign['type']]
                threat_info = self.calculate_threat_score(
                    current_campaign['type'], 
                    row['packets'], 
                    row['bytes'],
                    row['confidence_source']
                )
                row['threat_score'] = threat_info['score']
                row['severity'] = threat_info['severity']
            else:
                # Génération normale
                row = self.generate_row(malicious_ips)
                row['campaign_id'] = None
                current_campaign = None
            
            data.append(row)
            attack_counts[row['attack_label']] += 1
        
        # Conversion en DataFrame
        df = pd.DataFrame(data)
        
        # Statistiques de génération
        print(f"\n{'='*70}")
        print(f" RÉSUMÉ DE LA GÉNÉRATION")
        print(f"{'='*70}")
        print(f"✅ Total généré : {len(df):,} échantillons")
        print(f"\n📈 Distribution par type d'attaque :")
        for attack, count in attack_counts.items():
            pct = count / len(df) * 100
            bar = '█' * int(pct / 2)
            print(f"   {attack:15s} : {count:6,} ({pct:5.1f}%) {bar}")
        
        # Colonnes
        print(f"\n📋 Colonnes générées : {len(df.columns)}")
        print(f"   {', '.join(df.columns[:10])}...")
        
        return df
    
    def save_datasets(self, base_dir: str = 'data2'):
        """Génère et sauvegarde tous les datasets nécessaires"""
        
        # Création du dossier
        os.makedirs(base_dir, exist_ok=True)
        
        # Dataset principal (50k lignes)
        print("\n🔵 Génération du dataset principal...")
        df_main = self.generate_dataset(50000, campaign_density=0.3)
        main_path = os.path.join(base_dir, 'network_logs.csv')
        df_main.to_csv(main_path, index=False)
        print(f"   💾 Sauvegardé : {main_path} ({len(df_main):,} lignes, {df_main.memory_usage(deep=True).sum() / 1024 / 1024:.1f} MB)")
        
        # Dataset d'entraînement (20k lignes)
        print("\n🟢 Génération du dataset d'entraînement...")
        df_train = self.generate_dataset(20000, campaign_density=0.2)
        train_path = os.path.join(base_dir, 'train_logs.csv')
        df_train.to_csv(train_path, index=False)
        print(f"   💾 Sauvegardé : {train_path} ({len(df_train):,} lignes)")
        
        # Dataset de test (10k lignes)
        print("\n🟡 Génération du dataset de test...")
        df_test = self.generate_dataset(10000, campaign_density=0.15)
        test_path = os.path.join(base_dir, 'test_logs.csv')
        df_test.to_csv(test_path, index=False)
        print(f"   💾 Sauvegardé : {test_path} ({len(df_test):,} lignes)")
        
        # Dataset d'attaques récentes (7 derniers jours)
        print("\n🔴 Génération du dataset d'attaques récentes...")
        df_recent = self.generate_dataset(5000, campaign_density=0.5)
        recent_path = os.path.join(base_dir, 'recent_attacks.csv')
        df_recent.to_csv(recent_path, index=False)
        print(f"   💾 Sauvegardé : {recent_path} ({len(df_recent):,} lignes)")
        
        # Métadonnées du dataset
        metadata = {
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_samples': len(df_main),
            'attack_distribution': df_main['attack_label'].value_counts().to_dict(),
            'severity_distribution': df_main['severity'].value_counts().to_dict(),
            'columns': list(df_main.columns),
            'date_range': {
                'min': df_main['timestamp'].min(),
                'max': df_main['timestamp'].max()
            }
        }
        
        import json
        metadata_path = os.path.join(base_dir, 'dataset_metadata.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Métadonnées sauvegardées : {metadata_path}")
        
        print(f"\n{'='*70}")
        print(f" GÉNÉRATION TERMINÉE AVEC SUCCÈS !")
        print(f"{'='*70}")
        print(f"\n📁 Dossier : {os.path.abspath(base_dir)}/")
        print(f"\n📊 Fichiers générés :")
        print(f"   ├── network_logs.csv    (Dataset principal - {len(df_main):,} lignes)")
        print(f"   ├── train_logs.csv      (Entraînement - {len(df_train):,} lignes)")
        print(f"   ├── test_logs.csv       (Test - {len(df_test):,} lignes)")
        print(f"   ├── recent_attacks.csv  (Attaques récentes - {len(df_recent):,} lignes)")
        print(f"   └── dataset_metadata.json (Métadonnées)")
        
        return {
            'main': df_main,
            'train': df_train,
            'test': df_test,
            'recent': df_recent
        }


# ============================================================================
# VISUALISATION RAPIDE (optionnelle)
# ============================================================================

def quick_analysis(df: pd.DataFrame):
    """Affiche une analyse rapide du dataset"""
    print("\n" + "="*70)
    print(" ANALYSE RAPIDE DU DATASET")
    print("="*70)
    
    print(f"\n📊 Statistiques générales :")
    print(f"   - Total lignes : {len(df):,}")
    print(f"   - Colonnes : {len(df.columns)}")
    print(f"   - Période : {df['timestamp'].min()} → {df['timestamp'].max()}")
    
    print(f"\n🎯 Distribution des attaques :")
    for attack, count in df['attack_label'].value_counts().items():
        pct = count / len(df) * 100
        print(f"   - {attack:15s} : {count:6,} ({pct:5.1f}%)")
    
    print(f"\n⚠️ Distribution des sévérités :")
    for severity, count in df['severity'].value_counts().items():
        pct = count / len(df) * 100
        print(f"   - {severity:10s} : {count:6,} ({pct:5.1f}%)")
    
    print(f"\n🌍 Top 5 IPs sources malveillantes :")
    malicious_df = df[df['attack_label'] != 'Normal']
    top_ips = malicious_df['src_ip'].value_counts().head(5)
    for ip, count in top_ips.items():
        print(f"   - {ip:15s} : {count:5,} attaques")


# ============================================================================
# EXÉCUTION PRINCIPALE
# ============================================================================

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     GÉNÉRATEUR DE DONNÉES DE SÉCURITÉ - PLATEFORME IA SOC             ║
    ║                                                                       ║
    ║     Projet de Fin d'Études - Mastère en Cybersécurité                ║
    ║     Tunisie Telecom                                                   ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialisation du générateur
    generator = SecurityDataGenerator(seed=42)
    
    # Génération des datasets
    datasets = generator.save_datasets('data2')
    
    # Analyse rapide du dataset principal
    quick_analysis(datasets['main'])
    
    print("\n✅ Prêt à utiliser avec l'application Streamlit !")
    print("   Lancez : streamlit run main.py\n")