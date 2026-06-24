#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MODULE DE THREAT INTELLIGENCE - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Enrichissement des alertes avec Threat Intelligence
    - Base de données locale d'IOCs
    - Vérification des IPs/domaines malveillants
    - Mise à jour périodique des listes de confiance
    - Simulation d'API externes (AbuseIPDB, VirusTotal, AlienVault)
    - Scoring de confiance et catégorisation des menaces
================================================================================
"""

import pandas as pd
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')


class ThreatIntelligence:
    """
    Moteur de Threat Intelligence pour enrichir les alertes
    """
    
    def __init__(self, local_db_path: str = "data/threat_intel.json"):
        """
        Initialise le moteur de Threat Intelligence
        
        Args:
            local_db_path: Chemin vers la base de données locale
        """
        self.local_db_path = local_db_path
        self.threat_db = self._load_threat_db()
        
        # Données intégrées (simulation d'API externe)
        self.malicious_ips = self._init_malicious_ips()
        self.malicious_domains = self._init_malicious_domains()
        self.malicious_hashes = self._init_malicious_hashes()
        
        # Feeds de Threat Intelligence (simulation)
        self.ti_feeds = {
            'abuseipdb': self._get_abuseipdb_sample,
            'virustotal': self._get_virustotal_sample,
            'alienvault': self._get_alienvault_sample
        }
    
    def _load_threat_db(self) -> dict:
        """Charge la base de données locale"""
        if os.path.exists(self.local_db_path):
            try:
                with open(self.local_db_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'last_update': None, 'iocs': {}}
    
    def _save_threat_db(self):
        """Sauvegarde la base de données locale"""
        os.makedirs(os.path.dirname(self.local_db_path), exist_ok=True)
        with open(self.local_db_path, 'w') as f:
            json.dump(self.threat_db, f, indent=2)
    
    def _init_malicious_ips(self) -> Dict:
        """Initialise une liste d'IPs malveillantes connues (simulation)"""
        return {
            '185.130.5.253': {'category': 'malware', 'confidence': 95, 'source': 'AbuseIPDB'},
            '45.155.205.233': {'category': 'ddos', 'confidence': 90, 'source': 'AlienVault'},
            '94.102.61.78': {'category': 'bruteforce', 'confidence': 85, 'source': 'AbuseIPDB'},
            '185.244.8.194': {'category': 'scanner', 'confidence': 80, 'source': 'Shodan'},
            '51.79.155.5': {'category': 'malware', 'confidence': 92, 'source': 'VirusTotal'},
            '194.87.155.190': {'category': 'c2', 'confidence': 98, 'source': 'AlienVault'},
            '5.188.206.14': {'category': 'ddos', 'confidence': 88, 'source': 'AbuseIPDB'},
            '185.165.29.120': {'category': 'scanner', 'confidence': 75, 'source': 'Greynoise'},
            '45.142.213.7': {'category': 'malware', 'confidence': 91, 'source': 'VirusTotal'},
            '193.93.60.50': {'category': 'bruteforce', 'confidence': 82, 'source': 'AbuseIPDB'},
            '103.120.88.34': {'category': 'c2', 'confidence': 87, 'source': 'AlienVault'},
            '185.163.45.120': {'category': 'ransomware', 'confidence': 94, 'source': 'VirusTotal'},
            '45.146.164.100': {'category': 'scanner', 'confidence': 72, 'source': 'Greynoise'},
            '193.42.96.15': {'category': 'malware', 'confidence': 89, 'source': 'AbuseIPDB'},
            '91.242.162.23': {'category': 'ddos', 'confidence': 83, 'source': 'AlienVault'}
        }
    
    def _init_malicious_domains(self) -> Dict:
        """Initialise une liste de domaines malveillants (simulation)"""
        return {
            'malware-domain.com': {'category': 'malware', 'confidence': 95, 'source': 'VirusTotal'},
            'phishing-site.net': {'category': 'phishing', 'confidence': 90, 'source': 'PhishTank'},
            'c2-server.org': {'category': 'c2', 'confidence': 98, 'source': 'AlienVault'},
            'ddos-botnet.com': {'category': 'ddos', 'confidence': 85, 'source': 'AbuseIPDB'},
            'ransomware-payment.com': {'category': 'ransomware', 'confidence': 92, 'source': 'VirusTotal'},
            'scanner-bot.net': {'category': 'scanner', 'confidence': 78, 'source': 'Greynoise'},
            'malicious-update.com': {'category': 'malware', 'confidence': 96, 'source': 'VirusTotal'},
            'fake-login.xyz': {'category': 'phishing', 'confidence': 88, 'source': 'PhishTank'},
            'command-control.net': {'category': 'c2', 'confidence': 97, 'source': 'AlienVault'}
        }
    
    def _init_malicious_hashes(self) -> Dict:
        """Initialise une liste de hashs malveillants (simulation)"""
        return {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 
                {'category': 'malware', 'confidence': 96, 'source': 'VirusTotal', 'file': 'ransomware.exe'},
            '5d41402abc4b2a76b9719d911017c592': 
                {'category': 'trojan', 'confidence': 88, 'source': 'AlienVault', 'file': 'trojan.dll'},
            '7d793037a0760186574b0282f2f435e7': 
                {'category': 'backdoor', 'confidence': 91, 'source': 'AbuseIPDB', 'file': 'backdoor.php'},
            '098f6bcd4621d373cade4e832627b4f6': 
                {'category': 'worm', 'confidence': 84, 'source': 'VirusTotal', 'file': 'worm.exe'},
            '5eb63bbbe01eeed093cb22bb8f5acdc3': 
                {'category': 'keylogger', 'confidence': 79, 'source': 'AlienVault', 'file': 'keylogger.exe'}
        }
    
    def _get_abuseipdb_sample(self, ip: str) -> Optional[Dict]:
        """Simule une requête à AbuseIPDB"""
        if ip in self.malicious_ips and self.malicious_ips[ip]['source'] == 'AbuseIPDB':
            return {
                'source': 'AbuseIPDB',
                'confidence': self.malicious_ips[ip]['confidence'],
                'category': self.malicious_ips[ip]['category'],
                'reports': 25,
                'last_reported': datetime.now().strftime('%Y-%m-%d'),
                'country': 'RU',
                'isp': 'Malicious Hosting Corp',
                'domain': 'abuseipdb.com'
            }
        return None
    
    def _get_virustotal_sample(self, ip: str = None, domain: str = None, hash_val: str = None) -> Optional[Dict]:
        """Simule une requête à VirusTotal"""
        if ip and ip in self.malicious_ips and self.malicious_ips[ip]['source'] == 'VirusTotal':
            return {
                'source': 'VirusTotal',
                'confidence': self.malicious_ips[ip]['confidence'],
                'category': self.malicious_ips[ip]['category'],
                'detection_ratio': '15/65',
                'total_scanners': 65,
                'first_seen': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
                'last_analysis': datetime.now().strftime('%Y-%m-%d')
            }
        if domain and domain in self.malicious_domains:
            return {
                'source': 'VirusTotal',
                'confidence': self.malicious_domains[domain]['confidence'],
                'category': self.malicious_domains[domain]['category'],
                'detection_ratio': '12/70',
                'total_scanners': 70,
                'first_seen': (datetime.now() - timedelta(days=15)).strftime('%Y-%m-%d')
            }
        if hash_val and hash_val in self.malicious_hashes:
            return {
                'source': 'VirusTotal',
                'confidence': self.malicious_hashes[hash_val]['confidence'],
                'category': self.malicious_hashes[hash_val]['category'],
                'file': self.malicious_hashes[hash_val].get('file', 'unknown'),
                'detection_ratio': '45/70',
                'total_scanners': 70,
                'signature': f'{self.malicious_hashes[hash_val]["category"]}.generic'
            }
        return None
    
    def _get_alienvault_sample(self, ip: str = None, domain: str = None) -> Optional[Dict]:
        """Simule une requête à AlienVault OTX"""
        if ip and ip in self.malicious_ips and self.malicious_ips[ip]['source'] == 'AlienVault':
            return {
                'source': 'AlienVault OTX',
                'confidence': self.malicious_ips[ip]['confidence'],
                'category': self.malicious_ips[ip]['category'],
                'pulse_count': 5,
                'activity': 'malicious',
                'related_ips': ['10.0.0.1', '192.168.1.100']
            }
        if domain and domain in self.malicious_domains:
            return {
                'source': 'AlienVault OTX',
                'confidence': self.malicious_domains[domain]['confidence'],
                'category': self.malicious_domains[domain]['category'],
                'pulse_count': 3,
                'activity': 'suspicious'
            }
        return None
    
    def check_ip(self, ip: str) -> Dict:
        """
        Vérifie une IP via les différents feeds TI
        
        Args:
            ip: Adresse IP à vérifier
        
        Returns:
            Dict avec les résultats d'enrichissement
        """
        result = {
            'ip': ip,
            'is_malicious': False,
            'confidence': 0,
            'categories': [],
            'sources': [],
            'details': {},
            'recommendation': None
        }
        
        # Vérifier dans la base locale
        if ip in self.malicious_ips:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], self.malicious_ips[ip]['confidence'])
            result['categories'].append(self.malicious_ips[ip]['category'])
            result['sources'].append(self.malicious_ips[ip]['source'])
            result['details']['local'] = self.malicious_ips[ip]
        
        # Vérifier via AbuseIPDB
        abuse_data = self._get_abuseipdb_sample(ip)
        if abuse_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], abuse_data['confidence'])
            result['categories'].append(abuse_data['category'])
            result['sources'].append('AbuseIPDB')
            result['details']['abuseipdb'] = abuse_data
        
        # Vérifier via VirusTotal
        vt_data = self._get_virustotal_sample(ip=ip)
        if vt_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], vt_data['confidence'])
            result['categories'].append(vt_data['category'])
            result['sources'].append('VirusTotal')
            result['details']['virustotal'] = vt_data
        
        # Vérifier via AlienVault
        av_data = self._get_alienvault_sample(ip=ip)
        if av_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], av_data['confidence'])
            result['categories'].append(av_data['category'])
            result['sources'].append('AlienVault')
            result['details']['alienvault'] = av_data
        
        # Générer une recommandation basée sur la confiance
        if result['is_malicious']:
            if result['confidence'] >= 90:
                result['recommendation'] = "BLOQUER IMMÉDIATEMENT cette IP"
            elif result['confidence'] >= 70:
                result['recommendation'] = "SURVEILLER activement cette IP"
            else:
                result['recommendation'] = "Analyser plus en profondeur"
        else:
            result['recommendation'] = "Aucune action requise"
        
        return result
    
    def check_domain(self, domain: str) -> Dict:
        """
        Vérifie un domaine via les différents feeds TI
        
        Args:
            domain: Nom de domaine à vérifier
        
        Returns:
            Dict avec les résultats d'enrichissement
        """
        result = {
            'domain': domain,
            'is_malicious': False,
            'confidence': 0,
            'categories': [],
            'sources': [],
            'details': {},
            'recommendation': None
        }
        
        # Vérifier dans la base locale
        if domain in self.malicious_domains:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], self.malicious_domains[domain]['confidence'])
            result['categories'].append(self.malicious_domains[domain]['category'])
            result['sources'].append(self.malicious_domains[domain]['source'])
            result['details']['local'] = self.malicious_domains[domain]
        
        # Vérifier via VirusTotal
        vt_data = self._get_virustotal_sample(domain=domain)
        if vt_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], vt_data['confidence'])
            result['categories'].append(vt_data['category'])
            result['sources'].append('VirusTotal')
            result['details']['virustotal'] = vt_data
        
        # Vérifier via AlienVault
        av_data = self._get_alienvault_sample(domain=domain)
        if av_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], av_data['confidence'])
            result['categories'].append(av_data['category'])
            result['sources'].append('AlienVault')
            result['details']['alienvault'] = av_data
        
        # Générer une recommandation
        if result['is_malicious']:
            if result['confidence'] >= 90:
                result['recommendation'] = "AJOUTER à la liste noire DNS"
            elif result['confidence'] >= 70:
                result['recommendation'] = "SURVEILLER le trafic vers ce domaine"
            else:
                result['recommendation'] = "Vérifier les logs DNS"
        else:
            result['recommendation'] = "Aucune action requise"
        
        return result
    
    def check_hash(self, hash_val: str) -> Dict:
        """
        Vérifie un hash de fichier via VirusTotal
        
        Args:
            hash_val: Hash MD5, SHA1 ou SHA256 à vérifier
        
        Returns:
            Dict avec les résultats d'enrichissement
        """
        result = {
            'hash': hash_val,
            'hash_type': self._detect_hash_type(hash_val),
            'is_malicious': False,
            'confidence': 0,
            'categories': [],
            'sources': [],
            'details': {},
            'recommendation': None
        }
        
        # Vérifier dans la base locale
        if hash_val in self.malicious_hashes:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], self.malicious_hashes[hash_val]['confidence'])
            result['categories'].append(self.malicious_hashes[hash_val]['category'])
            result['sources'].append(self.malicious_hashes[hash_val]['source'])
            result['details']['local'] = self.malicious_hashes[hash_val]
        
        # Vérifier via VirusTotal
        vt_data = self._get_virustotal_sample(hash_val=hash_val)
        if vt_data:
            result['is_malicious'] = True
            result['confidence'] = max(result['confidence'], vt_data['confidence'])
            result['categories'].append(vt_data['category'])
            result['sources'].append('VirusTotal')
            result['details']['virustotal'] = vt_data
        
        # Générer une recommandation
        if result['is_malicious']:
            if result['confidence'] >= 90:
                result['recommendation'] = "METTRE EN QUARANTAINE le fichier"
            elif result['confidence'] >= 70:
                result['recommendation'] = "SCANNER le système pour ce hash"
            else:
                result['recommendation'] = "Analyser en sandbox"
        else:
            result['recommendation'] = "Hash non malveillant connu"
        
        return result
    
    def _detect_hash_type(self, hash_val: str) -> str:
        """Détecte le type de hash (MD5, SHA1, SHA256)"""
        hash_len = len(hash_val)
        if hash_len == 32:
            return 'MD5'
        elif hash_len == 40:
            return 'SHA1'
        elif hash_len == 64:
            return 'SHA256'
        else:
            return 'Unknown'
    
    def enrich_alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Enrichit un DataFrame d'alertes avec des données TI
        
        Args:
            df: DataFrame avec colonnes 'src_ip', 'dst_ip'
        
        Returns:
            DataFrame enrichi avec colonnes TI
        """
        if df.empty:
            return df
        
        df = df.copy()
        
        # Enrichir les IPs sources
        df['src_ip_malicious'] = False
        df['src_ip_confidence'] = 0
        df['src_ip_categories'] = ''
        df['src_ip_ti_sources'] = ''
        df['src_ip_recommendation'] = ''
        
        for idx, row in df.iterrows():
            src_ip = row.get('src_ip')
            if src_ip:
                result = self.check_ip(src_ip)
                df.at[idx, 'src_ip_malicious'] = result['is_malicious']
                df.at[idx, 'src_ip_confidence'] = result['confidence']
                df.at[idx, 'src_ip_categories'] = ', '.join(result['categories'])
                df.at[idx, 'src_ip_ti_sources'] = ', '.join(result['sources'])
                df.at[idx, 'src_ip_recommendation'] = result['recommendation']
        
        # Enrichir les IPs destinations
        df['dst_ip_malicious'] = False
        df['dst_ip_confidence'] = 0
        df['dst_ip_categories'] = ''
        df['dst_ip_ti_sources'] = ''
        df['dst_ip_recommendation'] = ''
        
        for idx, row in df.iterrows():
            dst_ip = row.get('dst_ip')
            if dst_ip:
                result = self.check_ip(dst_ip)
                df.at[idx, 'dst_ip_malicious'] = result['is_malicious']
                df.at[idx, 'dst_ip_confidence'] = result['confidence']
                df.at[idx, 'dst_ip_categories'] = ', '.join(result['categories'])
                df.at[idx, 'dst_ip_ti_sources'] = ', '.join(result['sources'])
                df.at[idx, 'dst_ip_recommendation'] = result['recommendation']
        
        # Calculer un score TI global
        df['ti_boost'] = (df['src_ip_confidence'] + df['dst_ip_confidence']) / 2
        
        # Niveau de risque TI
        df['ti_risk_level'] = df['ti_boost'].apply(
            lambda x: 'Critique' if x >= 80 else 'Haute' if x >= 60 else 
                      'Moyenne' if x >= 40 else 'Basse' if x >= 20 else 'Info'
        )
        
        # Ajuster le score de confiance si IP malveillante
        if 'confidence_score' in df.columns:
            df['enhanced_confidence'] = df.apply(
                lambda x: min(100, x['confidence_score'] + x['ti_boost'] * 0.2),
                axis=1
            )
        
        return df
    
    def get_threat_intel_summary(self, df: pd.DataFrame) -> Dict:
        """
        Génère un résumé des informations TI pour un dataset
        """
        if df.empty:
            return {
                'total_ips_analyzed': 0,
                'malicious_ips': 0,
                'threat_summary': {},
                'top_threat_categories': {},
                'ti_sources': {},
                'avg_confidence': 0,
                'recommendations': []
            }
        
        summary = {
            'total_ips_analyzed': 0,
            'malicious_ips': 0,
            'threat_summary': {},
            'top_threat_categories': {},
            'ti_sources': {},
            'avg_confidence': 0,
            'recommendations': []
        }
        
        # Collecter toutes les IPs
        all_ips = set()
        if 'src_ip' in df.columns:
            all_ips.update(df['src_ip'].dropna().unique())
        if 'dst_ip' in df.columns:
            all_ips.update(df['dst_ip'].dropna().unique())
        
        summary['total_ips_analyzed'] = len(all_ips)
        
        total_confidence = 0
        
        # Analyser chaque IP
        for ip in all_ips:
            result = self.check_ip(ip)
            total_confidence += result['confidence']
            
            if result['is_malicious']:
                summary['malicious_ips'] += 1
                
                for category in result['categories']:
                    summary['threat_summary'][category] = summary['threat_summary'].get(category, 0) + 1
                    summary['top_threat_categories'][category] = summary['top_threat_categories'].get(category, 0) + 1
                
                for source in result['sources']:
                    summary['ti_sources'][source] = summary['ti_sources'].get(source, 0) + 1
                
                if result['recommendation']:
                    summary['recommendations'].append(result['recommendation'])
        
        # Calculer la confiance moyenne
        summary['avg_confidence'] = total_confidence / len(all_ips) if all_ips else 0
        
        # Trier les catégories
        summary['top_threat_categories'] = dict(sorted(
            summary['top_threat_categories'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5])
        
        # Dédupliquer les recommandations
        summary['recommendations'] = list(set(summary['recommendations']))
        
        return summary
    
    def update_feeds(self):
        """Simule une mise à jour des feeds TI"""
        self.threat_db['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.threat_db['iocs'] = {
            'ips': len(self.malicious_ips),
            'domains': len(self.malicious_domains),
            'hashes': len(self.malicious_hashes)
        }
        self._save_threat_db()
        return {
            'status': 'updated',
            'timestamp': self.threat_db['last_update'],
            'iocs_count': self.threat_db['iocs']
        }
    
    def get_ioc_report(self) -> Dict:
        """
        Retourne un rapport complet sur les IOCs disponibles
        """
        return {
            'malicious_ips': self.malicious_ips,
            'malicious_domains': self.malicious_domains,
            'malicious_hashes': self.malicious_hashes,
            'total_count': {
                'ips': len(self.malicious_ips),
                'domains': len(self.malicious_domains),
                'hashes': len(self.malicious_hashes)
            },
            'last_updated': self.threat_db.get('last_update')
        }
    
    def add_custom_ioc(self, ioc_type: str, ioc_value: str, category: str, confidence: int, source: str):
        """
        Ajoute un IOC personnalisé à la base de données
        """
        if ioc_type == 'ip':
            self.malicious_ips[ioc_value] = {
                'category': category,
                'confidence': confidence,
                'source': source,
                'added_by': 'user',
                'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        elif ioc_type == 'domain':
            self.malicious_domains[ioc_value] = {
                'category': category,
                'confidence': confidence,
                'source': source,
                'added_by': 'user',
                'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        elif ioc_type == 'hash':
            self.malicious_hashes[ioc_value] = {
                'category': category,
                'confidence': confidence,
                'source': source,
                'added_by': 'user',
                'added_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        # Sauvegarder dans la base de données
        self._save_threat_db()
        
        return {'status': 'added', 'ioc_type': ioc_type, 'ioc_value': ioc_value}


# Fonction utilitaire pour un enrichissement rapide
def quick_enrich(ip: str) -> Dict:
    """Enrichit rapidement une IP"""
    ti = ThreatIntelligence()
    return ti.check_ip(ip)


def batch_enrich(ips: List[str]) -> List[Dict]:
    """Enrichit un lot d'IPs"""
    ti = ThreatIntelligence()
    results = []
    for ip in ips:
        results.append(ti.check_ip(ip))
    return results


if __name__ == "__main__":
    print("=" * 70)
    print(" TEST DU MODULE THREAT INTELLIGENCE")
    print("=" * 70)
    
    # Initialisation
    ti = ThreatIntelligence()
    
    # Tester une IP malveillante
    print("\n📊 Test IP malveillante: 185.130.5.253")
    result = ti.check_ip('185.130.5.253')
    print(f"   - Malveillante: {result['is_malicious']}")
    print(f"   - Confiance: {result['confidence']}%")
    print(f"   - Catégories: {result['categories']}")
    print(f"   - Sources: {result['sources']}")
    print(f"   - Recommandation: {result['recommendation']}")
    
    # Tester une IP normale
    print("\n📊 Test IP normale: 8.8.8.8")
    result = ti.check_ip('8.8.8.8')
    print(f"   - Malveillante: {result['is_malicious']}")
    print(f"   - Confiance: {result['confidence']}%")
    print(f"   - Recommandation: {result['recommendation']}")
    
    # Tester un domaine malveillant
    print("\n📊 Test domaine malveillant: c2-server.org")
    result = ti.check_domain('c2-server.org')
    print(f"   - Malveillant: {result['is_malicious']}")
    print(f"   - Confiance: {result['confidence']}%")
    print(f"   - Catégories: {result['categories']}")
    
    # Afficher le résumé des IOCs
    print("\n📊 Résumé de la base IOC:")
    ioc_report = ti.get_ioc_report()
    print(f"   - IPs malveillantes: {ioc_report['total_count']['ips']}")
    print(f"   - Domaines malveillants: {ioc_report['total_count']['domains']}")
    print(f"   - Hashs malveillants: {ioc_report['total_count']['hashes']}")
    
    print("\n" + "=" * 70)
    print("✅ Module Threat Intelligence chargé avec succès!")
    print("=" * 70)