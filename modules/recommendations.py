#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MOTEUR DE RECOMMANDATIONS - PLATEFORME SOC
================================================================================
Fonctionnalités :
    - Génération automatique d'actions correctives
    - Suggestions de règles firewall (iptables, ufw, nftables)
    - Playbooks de réponse automatisés
    - Recommandations d'isolation
    - Export en checklist et PDF
================================================================================
"""

import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional
import json


class RecommendationEngine:
    """Moteur de recommandations pour la réponse aux incidents"""
    
    # Base de connaissances des menaces
    THREAT_KNOWLEDGE_BASE = {
        'DDoS': {
            'severity': 'Critique',
            'sla_minutes': 15,
            'playbook': 'ddos_response',
            'tags': ['network', 'volumetric', 'availability']
        },
        'Brute Force': {
            'severity': 'Haute',
            'sla_minutes': 30,
            'playbook': 'bruteforce_response',
            'tags': ['authentication', 'credential', 'repeated']
        },
        'Port Scan': {
            'severity': 'Moyenne',
            'sla_minutes': 120,
            'playbook': 'portscan_response',
            'tags': ['reconnaissance', 'discovery', 'scanning']
        },
        'Malware': {
            'severity': 'Critique',
            'sla_minutes': 10,
            'playbook': 'malware_response',
            'tags': ['malware', 'ransomware', 'infection']
        },
        'Phishing': {
            'severity': 'Haute',
            'sla_minutes': 60,
            'playbook': 'phishing_response',
            'tags': ['social_engineering', 'email', 'fraud']
        },
        'SQL Injection': {
            'severity': 'Haute',
            'sla_minutes': 45,
            'playbook': 'sqli_response',
            'tags': ['injection', 'database', 'web']
        },
        'XSS': {
            'severity': 'Moyenne',
            'sla_minutes': 240,
            'playbook': 'xss_response',
            'tags': ['injection', 'web', 'client_side']
        },
        'Normal': {
            'severity': 'Info',
            'sla_minutes': None,
            'playbook': None,
            'tags': ['normal', 'benign']
        }
    }
    
    # Actions par type de menace
    IMMEDIATE_ACTIONS = {
        'DDoS': [
            "🚨 Activer immédiatement la protection anti-DDoS du FAI",
            "📊 Mettre en place des règles de rate limiting sur le pare-feu",
            "🌍 Bloquer les IPs sources identifiées (si possible)",
            "🔄 Rediriger le trafic vers un service de scrubbing",
            "📈 Contacter le NOC pour augmenter la bande passante"
        ],
        'Brute Force': [
            "🔒 Désactiver temporairement le compte utilisateur ciblé",
            "🔑 Forcer une réinitialisation de mot de passe immédiate",
            "📝 Mettre en place une politique de verrouillage après 3 échecs",
            "🌍 Bloquer l'IP source via fail2ban ou équivalent",
            "📊 Activer la journalisation détaillée des connexions"
        ],
        'Port Scan': [
            "🔍 Analyser les logs pour identifier les ports scannés",
            "🛡️ Activer le mode furtif sur les services exposés",
            "📡 Déployer un honeypot pour identifier l'attaquant",
            "📊 Réaliser un audit des ports ouverts inutiles",
            "🔒 Renforcer la configuration du pare-feu"
        ],
        'Malware': [
            "⚠️ ISOLER IMMÉDIATEMENT la machine infectée du réseau",
            "🔬 Capturer la mémoire vive pour analyse forensique",
            "🔄 Désactiver les comptes de service compromis",
            "🔍 Scanner les systèmes adjacents pour détection de propagation",
            "📞 Notifier immédiatement l'équipe de réponse aux incidents"
        ],
        'Phishing': [
            "📧 Bloquer l'expéditeur au niveau de la passerelle email",
            "🔗 Désactiver les URLs malveillantes sur le proxy",
            "👥 Informer les utilisateurs ayant reçu le mail",
            "🗑️ Supprimer les emails malveillants des boîtes",
            "🔑 Forcer la réinitialisation des mots de passe des victimes"
        ],
        'SQL Injection': [
            "🛡️ Activer immédiatement le WAF (Web Application Firewall)",
            "🔍 Analyser les logs d'accès pour identifier la requête",
            "📝 Corriger la vulnérabilité (requêtes paramétrées)",
            "🗄️ Vérifier l'intégrité des données en base",
            "🔒 Restreindre les privilèges de la base de données"
        ],
        'XSS': [
            "📝 Échapper les caractères spéciaux dans les entrées",
            "🛡️ Mettre en place CSP (Content Security Policy)",
            "🔍 Scanner l'application pour identifier toutes les XSS",
            "📊 Valider et assainir toutes les entrées utilisateur",
            "🔒 Activer le mode HttpOnly sur les cookies"
        ],
        'Normal': [
            "✅ Aucune action requise - trafic normal",
            "📊 Continuer la surveillance de routine",
            "📈 Mettre à jour les modèles avec le trafic normal"
        ]
    }
    
    @classmethod
    def get_firewall_rules(cls, threat_type: str, src_ip: str = None, dst_ip: str = None) -> List[str]:
        """Génère des règles firewall pour un type de menace donné"""
        
        rules = []
        
        if threat_type == 'DDoS':
            rules = [
                f"# Rate limiting sur les ports web",
                f"iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 50 -j ACCEPT",
                f"iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 50 -j ACCEPT",
                f"# Limiter les connexions SYN",
                f"iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT"
            ]
        
        elif threat_type == 'Brute Force':
            rules = [
                f"# Bloquer l'IP source {src_ip if src_ip else 'X.X.X.X'}",
                f"iptables -A INPUT -s {src_ip if src_ip else 'X.X.X.X'} -j DROP",
                f"# fail2ban configuration",
                f"fail2ban-client set ssh banip {src_ip if src_ip else 'X.X.X.X'}"
            ]
        
        elif threat_type == 'Port Scan':
            rules = [
                f"# Détection et blocage de port scan",
                f"iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP",
                f"iptables -A INPUT -p tcp --tcp-flags ALL SYN -m limit --limit 1/s -j ACCEPT"
            ]
        
        elif threat_type == 'Malware':
            rules = [
                f"# Isolation immédiate de la machine infectée",
                f"iptables -A OUTPUT -s {src_ip if src_ip else 'X.X.X.X'} -j DROP",
                f"iptables -A FORWARD -s {src_ip if src_ip else 'X.X.X.X'} -j DROP"
            ]
        
        elif threat_type == 'SQL Injection':
            rules = [
                f"# ModSecurity - Activer les règles SQLi",
                f"iptables -A INPUT -p tcp --dport 80 -m string --string 'union select' --algo bm -j DROP"
            ]
        
        return rules
    
    @classmethod
    def get_isolation_recommendation(cls, threat_type: str, src_ip: str = None) -> Dict:
        """Recommande des actions d'isolation"""
        
        recommendations = {
            'DDoS': {
                'isolate': False,
                'action': "Isoler le serveur cible du réseau de production",
                'priority': 'Haute',
                'steps': [
                    "Rediriger le trafic vers un honeypot",
                    "Activer le mode maintenance",
                    "Notifier les administrateurs système"
                ]
            },
            'Brute Force': {
                'isolate': False,
                'action': "Isoler la machine source compromise",
                'priority': 'Moyenne',
                'steps': [
                    "Désactiver les comptes suspects",
                    "Forcer la réinitialisation des mots de passe",
                    "Analyser les logs d'authentification"
                ]
            },
            'Malware': {
                'isolate': True,
                'action': "ISOLEMENT IMMÉDIAT de la machine infectée",
                'priority': 'Critique',
                'steps': [
                    "Débrancher physiquement le câble réseau",
                    "Capturer la mémoire vive",
                    "Mettre en quarantaine le disque dur",
                    "Scanner les machines adjacentes"
                ]
            }
        }
        
        return recommendations.get(threat_type, {
            'isolate': False,
            'action': "Aucune isolation requise",
            'priority': 'Basse',
            'steps': ["Surveillance continue"]
        })
    
    @classmethod
    def generate_playbook(cls, threat_type: str, context: Dict = None) -> str:
        """Génère un playbook de réponse complet"""
        
        context = context or {}
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        playbook = f"""
# ============================================================================
# PLAYBOOK DE RÉPONSE AUX INCIDENTS - {threat_type.upper()}
# ============================================================================
# Généré le : {timestamp}
# SLA : {cls.THREAT_KNOWLEDGE_BASE.get(threat_type, {}).get('sla_minutes', 'N/A')} minutes
# Sévérité : {cls.THREAT_KNOWLEDGE_BASE.get(threat_type, {}).get('severity', 'Unknown')}
# ============================================================================

## 1. PHASE DE DÉTECTION ET QUALIFICATION

### 1.1 Vérification de l'alerte
- [ ] Vérifier l'authenticité de l'alerte
- [ ] Confirmer la présence de la menace
- [ ] Évaluer l'impact potentiel

### 1.2 Informations de contexte
- IP Source : {context.get('src_ip', 'À identifier')}
- IP Destination : {context.get('dst_ip', 'À identifier')}
- Timestamp : {context.get('timestamp', timestamp)}
- Score de confiance : {context.get('confidence', 'N/A')}%

## 2. PHASE DE CONTAINEMENT

### 2.1 Actions immédiates
"""
        
        for i, action in enumerate(cls.IMMEDIATE_ACTIONS.get(threat_type, cls.IMMEDIATE_ACTIONS['Normal']), 1):
            playbook += f"- [ ] {action}\n"
        
        playbook += """
### 2.2 Règles firewall
```bash
"""
        
        for rule in cls.get_firewall_rules(threat_type, context.get('src_ip'), context.get('dst_ip')):
            playbook += f"{rule}\n"
        
        playbook += "```\n\n## 3. PHASE D'INVESTIGATION\n\n"
        
        playbook += """
### 3.1 Collecte des preuves
- [ ] Exporter les logs système
- [ ] Capturer le trafic réseau (PCAP)
- [ ] Sauvegarder les fichiers critiques
- [ ] Documenter la chronologie

## 4. PHASE D'ÉRADICATION

### 4.1 Nettoyage
- [ ] Supprimer les fichiers malveillants
- [ ] Tuer les processus suspects
- [ ] Restaurer les configurations

## 5. PHASE DE RÉTABLISSEMENT

### 5.1 Restauration
- [ ] Restaurer les services
- [ ] Reconnecter les systèmes isolés
- [ ] Vérifier l'intégrité des données

---
**Signatures**
- Analyste : __________________
- Superviseur : __________________
- Date de clôture : __________________
"""
        
        return playbook
    
    @classmethod
    def generate_checklist(cls, threats: List[Dict]) -> str:
        """Génère une checklist à partir des menaces détectées"""
        
        checklist = f"""
# CHECKLIST DE RÉPONSE AUX INCIDENTS
# ============================================================================
# Générée le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Nombre de menaces à traiter : {len(threats)}
# ============================================================================

## ACTIONS GLOBALES À VALIDER

### Préparation
- [ ] Équipe de réponse aux incidents notifiée
- [ ] Outils d'investigation prêts

### Exécution
- [ ] Toutes les actions immédiates exécutées
- [ ] Règles firewall appliquées
- [ ] Systèmes isolés si nécessaire
- [ ] Preuves collectées

### Finalisation
- [ ] Rapport d'incident rédigé
- [ ] Leçons apprises documentées
- [ ] Clôture du ticket

---
**Statut final** : [ ] RÉSOLU [ ] EN COURS [ ] TRANSFÉRÉ
"""
        
        return checklist
    
    @classmethod
    def get_recommendations_for_alert(cls, alert: pd.Series) -> Dict:
        """Génère des recommandations pour une alerte spécifique"""
        
        threat_type = alert.get('predicted_threat', alert.get('attack_label', 'Normal'))
        
        recommendations = {
            'threat_type': threat_type,
            'severity': cls.THREAT_KNOWLEDGE_BASE.get(threat_type, {}).get('severity', 'Info'),
            'sla_minutes': cls.THREAT_KNOWLEDGE_BASE.get(threat_type, {}).get('sla_minutes'),
            'immediate_actions': cls.IMMEDIATE_ACTIONS.get(threat_type, cls.IMMEDIATE_ACTIONS['Normal']),
            'firewall_rules': cls.get_firewall_rules(threat_type, alert.get('src_ip'), alert.get('dst_ip')),
            'isolation': cls.get_isolation_recommendation(threat_type, alert.get('src_ip')),
            'playbook': cls.generate_playbook(threat_type, {
                'src_ip': alert.get('src_ip'),
                'dst_ip': alert.get('dst_ip'),
                'timestamp': alert.get('timestamp'),
                'confidence': alert.get('confidence_score')
            }),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return recommendations


if __name__ == "__main__":
    # Test
    test_alert = pd.Series({
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'predicted_threat': 'DDoS',
        'confidence_score': 85.5,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    rec = RecommendationEngine.get_recommendations_for_alert(test_alert)
    print(f"Recommandations pour {rec['threat_type']}:")
    for action in rec['immediate_actions'][:3]:
        print(f"  - {action}")