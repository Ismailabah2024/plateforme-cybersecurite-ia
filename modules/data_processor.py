#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MODULE DE PRÉTRAITEMENT DES DONNÉES - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Normalisation des CSV multi-formats
    - Feature engineering automatique
    - Nettoyage et validation des données
    - Gestion des valeurs manquantes
    - Encodage des variables catégorielles
================================================================================
"""

import pandas as pd
import numpy as np
from datetime import datetime
import re
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')


class DataProcessor:
    """Classe pour le prétraitement et la normalisation des données de sécurité"""
    
    def __init__(self):
        """Initialise le processeur de données"""
        self.required_columns = [
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'bytes', 'packets'
        ]
        self.optional_columns = [
            'duration', 'flags', 'attack_label', 'confidence_source', 'threat_source'
        ]
        self.column_mappings = {}
        
    def detect_format(self, df: pd.DataFrame) -> str:
        """
        Détecte le format du fichier CSV entrant
        
        Returns:
            'minimal', 'extended', ou 'unknown'
        """
        cols = set(df.columns.str.lower())
        
        # Format minimal requis
        minimal_set = {'timestamp', 'src_ip', 'dst_ip', 'protocol'}
        extended_set = minimal_set.union({'duration', 'flags', 'attack_label'})
        
        if extended_set.issubset(cols):
            return 'extended'
        elif minimal_set.issubset(cols):
            return 'minimal'
        else:
            return 'unknown'
    
    def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalise les noms de colonnes vers un format standard
        """
        # Mapping des noms de colonnes possibles
        column_mapping = {
            # Timestamp
            'timestamp': 'timestamp', 'time': 'timestamp', 'date': 'timestamp',
            'datetime': 'timestamp', 'log_time': 'timestamp',
            
            # IPs
            'src_ip': 'src_ip', 'source_ip': 'src_ip', 'src': 'src_ip',
            'ip_src': 'src_ip', 'source': 'src_ip',
            'dst_ip': 'dst_ip', 'dest_ip': 'dst_ip', 'destination_ip': 'dst_ip',
            'dst': 'dst_ip', 'ip_dst': 'dst_ip',
            
            # Ports
            'src_port': 'src_port', 'source_port': 'src_port', 'sport': 'src_port',
            'dst_port': 'dst_port', 'dest_port': 'dst_port', 'dport': 'dst_port',
            
            # Protocole
            'protocol': 'protocol', 'proto': 'protocol', 'prot': 'protocol',
            
            # Métriques
            'bytes': 'bytes', 'byte': 'bytes', 'size': 'bytes', 'length': 'bytes',
            'packets': 'packets', 'packet': 'packets', 'pkt': 'packets',
            'duration': 'duration', 'dur': 'duration', 'time_taken': 'duration',
            
            # Flags
            'flags': 'flags', 'flag': 'flags', 'tcp_flags': 'flags',
            
            # Labels
            'attack_label': 'attack_label', 'label': 'attack_label',
            'attack_type': 'attack_label', 'threat': 'attack_label',
            'confidence': 'confidence_source', 'conf': 'confidence_source',
            'threat_source': 'threat_source', 'source_type': 'threat_source'
        }
        
        # Renommer les colonnes
        new_columns = {}
        for col in df.columns:
            col_lower = col.lower().strip()
            if col_lower in column_mapping:
                new_columns[col] = column_mapping[col_lower]
            else:
                new_columns[col] = col
        
        df = df.rename(columns=new_columns)
        return df
    
    def parse_timestamp(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Parse et normalise les timestamps
        """
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return df
        
        # Formats de timestamp supportés
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%d-%m-%Y %H:%M:%S'
        ]
        
        def parse_single(ts):
            if pd.isna(ts):
                return datetime.now()
            ts_str = str(ts)
            for fmt in formats:
                try:
                    return datetime.strptime(ts_str, fmt)
                except:
                    continue
            return datetime.now()
        
        df['timestamp'] = df['timestamp'].apply(parse_single)
        return df
    
    def validate_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Valide et nettoie les adresses IP
        """
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        def clean_ip(ip):
            if pd.isna(ip):
                return '0.0.0.0'
            ip_str = str(ip).strip()
            if ip_pattern.match(ip_str):
                octets = ip_str.split('.')
                if all(0 <= int(o) <= 255 for o in octets):
                    return ip_str
            return '0.0.0.0'
        
        if 'src_ip' in df.columns:
            df['src_ip'] = df['src_ip'].apply(clean_ip)
        if 'dst_ip' in df.columns:
            df['dst_ip'] = df['dst_ip'].apply(clean_ip)
        
        return df
    
    def validate_ports(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Valide et nettoie les numéros de ports
        """
        def clean_port(port):
            if pd.isna(port):
                return 0
            try:
                port_int = int(port)
                if 0 <= port_int <= 65535:
                    return port_int
            except:
                pass
            return 0
        
        if 'src_port' in df.columns:
            df['src_port'] = df['src_port'].apply(clean_port)
        if 'dst_port' in df.columns:
            df['dst_port'] = df['dst_port'].apply(clean_port)
        
        return df
    
    def handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Gère les valeurs manquantes
        """
        # Colonnes numériques: remplacer par 0
        numeric_cols = ['bytes', 'packets', 'duration', 'src_port', 'dst_port']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        # Colonnes textuelles: remplacer par 'unknown'
        text_cols = ['protocol', 'flags', 'attack_label', 'threat_source']
        for col in text_cols:
            if col in df.columns:
                df[col] = df[col].fillna('unknown')
        
        return df
    
    def encode_protocols(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Encode les protocoles réseau en valeurs numériques
        """
        protocol_map = {
            'TCP': 6, 'UDP': 17, 'ICMP': 1, 'HTTP': 80, 'HTTPS': 443,
            'DNS': 53, 'SSH': 22, 'FTP': 21, 'SMTP': 25, 'unknown': 0
        }
        
        if 'protocol' in df.columns:
            df['protocol_code'] = df['protocol'].str.upper().map(
                lambda x: protocol_map.get(x, 0)
            )
        
        return df
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Crée des features supplémentaires pour l'analyse IA
        """
        # Bytes par paquet
        if 'bytes' in df.columns and 'packets' in df.columns:
            df['bytes_per_packet'] = df['bytes'] / df['packets'].replace(0, 1)
            df['bytes_per_packet'] = df['bytes_per_packet'].clip(0, 10000)
        
        # Paquets par seconde
        if 'packets' in df.columns and 'duration' in df.columns:
            df['packets_per_second'] = df['packets'] / df['duration'].replace(0, 0.001)
            df['packets_per_second'] = df['packets_per_second'].clip(0, 100000)
        
        # Score de risque basé sur le port
        dangerous_ports = [22, 23, 3389, 445, 1433, 3306, 5900, 5800]
        if 'dst_port' in df.columns:
            df['is_dangerous_port'] = df['dst_port'].isin(dangerous_ports).astype(int)
        
        # Flag anormal
        if 'flags' in df.columns:
            dangerous_flags = ['SYN', 'NULL', 'FIN', 'XMAS']
            df['is_dangerous_flag'] = df['flags'].str.upper().isin(dangerous_flags).astype(int)
        
        # Heure de la journée
        if 'timestamp' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            df['is_night_hour'] = ((df['hour'] < 6) | (df['hour'] > 22)).astype(int)
        
        return df
    
    def filter_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Filtre les colonnes pour garder uniquement celles utiles
        """
        useful_columns = [
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'protocol_code', 'bytes', 'packets', 'duration',
            'flags', 'bytes_per_packet', 'packets_per_second',
            'is_dangerous_port', 'is_dangerous_flag', 'hour', 'is_night_hour',
            'attack_label', 'confidence_source', 'threat_source'
        ]
        
        existing_columns = [col for col in useful_columns if col in df.columns]
        return df[existing_columns]
    
    def process(self, df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
        """
        Pipeline complet de prétraitement
        
        Args:
            df: DataFrame brut
            verbose: Afficher les logs
        
        Returns:
            DataFrame prétraité et normalisé
        """
        if verbose:
            print("=" * 60)
            print(" PRÉTRAITEMENT DES DONNÉES")
            print("=" * 60)
            print(f"📊 Données initiales: {len(df)} lignes, {len(df.columns)} colonnes")
        
        # 1. Détection du format
        format_type = self.detect_format(df)
        if verbose:
            print(f"📁 Format détecté: {format_type}")
        
        # 2. Normalisation des colonnes
        df = self.normalize_columns(df)
        if verbose:
            print(f"✓ Colonnes normalisées")
        
        # 3. Parsing des timestamps
        df = self.parse_timestamp(df)
        if verbose:
            print(f"✓ Timestamps parsés")
        
        # 4. Validation des IPs
        df = self.validate_ips(df)
        if verbose:
            print(f"✓ IPs validées")
        
        # 5. Validation des ports
        df = self.validate_ports(df)
        if verbose:
            print(f"✓ Ports validés")
        
        # 6. Gestion des valeurs manquantes
        df = self.handle_missing_values(df)
        if verbose:
            missing_before = df.isnull().sum().sum()
            print(f"✓ Valeurs manquantes traitées")
        
        # 7. Encodage des protocoles
        df = self.encode_protocols(df)
        if verbose:
            print(f"✓ Protocoles encodés")
        
        # 8. Feature engineering
        df = self.engineer_features(df)
        if verbose:
            new_features = [col for col in df.columns if col not in ['timestamp', 'src_ip', 'dst_ip']]
            print(f"✓ Features créées: {len(new_features)} colonnes numériques")
        
        # 9. Filtrage des colonnes
        df = self.filter_columns(df)
        
        if verbose:
            print("=" * 60)
            print(f"✅ Prétraitement terminé: {len(df)} lignes, {len(df.columns)} colonnes")
            print("=" * 60)
        
        return df
    
    def process_batch(self, file_paths: List[str], verbose: bool = True) -> pd.DataFrame:
        """
        Traite plusieurs fichiers CSV en batch
        """
        all_dfs = []
        
        for path in file_paths:
            if verbose:
                print(f"\n📂 Traitement de: {path}")
            
            try:
                df = pd.read_csv(path)
                df = self.process(df, verbose=False)
                df['source_file'] = path.split('/')[-1]
                all_dfs.append(df)
            except Exception as e:
                print(f"❌ Erreur sur {path}: {e}")
        
        if all_dfs:
            result = pd.concat(all_dfs, ignore_index=True)
            if verbose:
                print(f"\n✅ Batch terminé: {len(result)} lignes au total")
            return result
        
        return pd.DataFrame()


class DataValidator:
    """Validateur de données pour vérifier l'intégrité des datasets"""
    
    @staticmethod
    def validate_dataset(df: pd.DataFrame) -> Dict:
        """
        Valide un dataset et retourne un rapport
        """
        report = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'stats': {}
        }
        
        # Vérifier les colonnes requises
        required = ['timestamp', 'src_ip', 'dst_ip']
        missing = [col for col in required if col not in df.columns]
        if missing:
            report['is_valid'] = False
            report['errors'].append(f"Colonnes manquantes: {missing}")
        
        # Vérifier les lignes vides
        empty_rows = df.isnull().all(axis=1).sum()
        if empty_rows > 0:
            report['warnings'].append(f"{empty_rows} lignes vides détectées")
        
        # Vérifier les doublons
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            report['warnings'].append(f"{duplicates} lignes dupliquées")
        
        # Statistiques
        report['stats']['rows'] = len(df)
        report['stats']['columns'] = len(df.columns)
        report['stats']['memory_mb'] = df.memory_usage(deep=True).sum() / 1024 / 1024
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            report['stats']['date_min'] = df['timestamp'].min()
            report['stats']['date_max'] = df['timestamp'].max()
            report['stats']['date_range_days'] = (df['timestamp'].max() - df['timestamp'].min()).days
        
        return report


def quick_process(file_path: str) -> pd.DataFrame:
    """Fonction rapide pour traiter un fichier CSV"""
    processor = DataProcessor()
    df = pd.read_csv(file_path)
    return processor.process(df)


if __name__ == "__main__":
    # Test du module
    test_data = pd.DataFrame({
        'timestamp': ['2024-01-01 10:00:00', '2024-01-01 10:05:00'],
        'src_ip': ['192.168.1.1', '10.0.0.1'],
        'dst_ip': ['8.8.8.8', '1.1.1.1'],
        'src_port': [12345, 54321],
        'dst_port': [80, 443],
        'protocol': ['TCP', 'TCP'],
        'bytes': [1500, 800],
        'packets': [10, 5],
        'duration': [0.5, 0.3],
        'attack_label': ['Normal', 'DDoS']
    })
    
    processor = DataProcessor()
    processed = processor.process(test_data, verbose=True)
    print("\n📊 Résultat:")
    print(processed.head())