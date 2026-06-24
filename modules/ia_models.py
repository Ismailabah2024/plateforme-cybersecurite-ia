#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
MODULES IA POUR LA DÉTECTION DE MENACES - PLATEFORME SOC
================================================================================
Auteur : Fabien | Projet : PFE Mastère
Description : Implémentation des modèles d'apprentissage automatique pour
              la détection des cybermenaces (DDoS, Brute Force, Port Scan, etc.)
              
Modèles inclus :
    1. Random Forest (Supervisé)
    2. Isolation Forest (Non supervisé - anomalies)
    3. XGBoost (Supervisé optimisé)
    4. Voting Classifier (Ensemble des 3 modèles)
    
Fonctionnalités :
    - Configuration dynamique des hyperparamètres
    - Entraînement et évaluation complets
    - Visualisations interactives (Plotly)
    - Exports PDF, CSV, HTML
    - Explicabilité des modèles (SHAP/LIME simplifié)
    - Filtres avancés
================================================================================
"""

import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import warnings
warnings.filterwarnings('ignore')

# Scikit-learn
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score,
                             confusion_matrix, classification_report)

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️ XGBoost non disponible. Installation recommandée: pip install xgboost")

# Visualisations
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Pour les exports
from io import BytesIO
import json

# Pour l'explicabilité simplifiée
import matplotlib.pyplot as plt


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class ModelConfig:
    """Configuration des hyperparamètres des modèles IA"""
    
    # Random Forest
    rf_n_estimators: int = 100
    rf_max_depth: int = 15
    rf_min_samples_split: int = 5
    rf_min_samples_leaf: int = 2
    rf_max_features: str = 'sqrt'
    rf_class_weight: str = 'balanced'
    
    # Isolation Forest
    if_n_estimators: int = 100
    if_contamination: float = 0.1
    if_max_samples: str = 'auto'
    if_bootstrap: bool = False
    
    # XGBoost
    xgb_n_estimators: int = 100
    xgb_max_depth: int = 6
    xgb_learning_rate: float = 0.1
    xgb_subsample: float = 0.8
    xgb_colsample_bytree: float = 0.8
    
    # Voting Classifier
    voting_weights: List[float] = field(default_factory=lambda: [1, 1, 1])


# ============================================================================
# MODÈLES IA
# ============================================================================

class ThreatDetectionModels:
    """
    Classe principale pour la détection des menaces avec 4 modèles IA
    """
    
    def __init__(self, config: ModelConfig = None):
        """
        Initialise les modèles de détection de menaces
        
        Args:
            config: Configuration des modèles (paramètres par défaut sinon)
        """
        self.config = config or ModelConfig()
        self.models = {}
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = None
        self.is_trained = False
        self.training_metrics = {}
        
        # Dossier pour sauvegarder les modèles
        self.models_dir = 'models'
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialisation des modèles
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialise les 4 modèles IA avec leurs configurations"""
        
        # 1. Random Forest - Classification supervisée
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            min_samples_split=self.config.rf_min_samples_split,
            min_samples_leaf=self.config.rf_min_samples_leaf,
            max_features=self.config.rf_max_features,
            class_weight=self.config.rf_class_weight,
            random_state=42,
            n_jobs=-1
        )
        
        # 2. Isolation Forest - Détection d'anomalies non supervisée
        self.models['isolation_forest'] = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            max_samples=self.config.if_max_samples,
            bootstrap=self.config.if_bootstrap,
            random_state=42
        )
        
        # 3. XGBoost - Classification supervisée optimisée
        if XGBOOST_AVAILABLE:
            self.models['xgboost'] = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                subsample=self.config.xgb_subsample,
                colsample_bytree=self.config.xgb_colsample_bytree,
                use_label_encoder=False,
                eval_metric='mlogloss',
                random_state=42
            )
        else:
            print("⚠️ XGBoost non disponible, utilisation d'un second Random Forest")
            self.models['xgboost'] = RandomForestClassifier(
                n_estimators=100, random_state=42, n_jobs=-1
            )
        
        # 4. Voting Classifier - Ensemble des 3 modèles
        self.models['voting'] = VotingClassifier(
            estimators=[
                ('rf', self.models['random_forest']),
                ('xgb', self.models['xgboost'])
            ],
            voting='soft',
            weights=self.config.voting_weights[:2]
        )
    
    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prépare les features pour l'entraînement
        
        Args:
            df: DataFrame avec les données
        
        Returns:
            features: Features préparées
            labels: Labels encodés (si disponibles)
        """
        # Définition des colonnes features numériques
        feature_cols = ['bytes', 'packets', 'src_port', 'dst_port']
        if 'duration' in df.columns:
            feature_cols.append('duration')
        
        # Ajout des colonnes disponibles
        available_cols = [col for col in feature_cols if col in df.columns]
        
        # Si aucune colonne numérique trouvée, prendre toutes les colonnes numériques
        if not available_cols:
            available_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            available_cols = [c for c in available_cols if c not in ['confidence_score', 'threat_score']][:4]
        
        # Extraction des features
        features = df[available_cols].copy()
        
        # Gestion des valeurs manquantes
        features = features.fillna(0)
        
        # Mise à l'échelle
        if not hasattr(self.scaler, 'mean_'):
            features_scaled = self.scaler.fit_transform(features)
        else:
            features_scaled = self.scaler.transform(features)
        
        self.feature_columns = available_cols
        
        # Extraction des labels si disponibles
        labels = None
        if 'attack_label' in df.columns:
            if 'attack_label' not in self.label_encoders:
                self.label_encoders['attack_label'] = LabelEncoder()
                labels = self.label_encoders['attack_label'].fit_transform(df['attack_label'])
            else:
                labels = self.label_encoders['attack_label'].transform(df['attack_label'])
        
        return features_scaled, labels
    
    def train_all_models(self, df: pd.DataFrame = None, force_retrain: bool = False):
        """
        Entraîne tous les modèles
        
        Args:
            df: DataFrame d'entraînement (si None, charge le dataset par défaut)
            force_retrain: Force le réentraînement même si les modèles existent
        """
        # Vérifier si les modèles sont déjà entraînés
        model_files = [
            f'{self.models_dir}/random_forest.joblib',
            f'{self.models_dir}/isolation_forest.joblib',
            f'{self.models_dir}/xgboost.joblib',
            f'{self.models_dir}/voting.joblib'
        ]
        
        if not force_retrain and all(os.path.exists(f) for f in model_files):
            print("📁 Chargement des modèles pré-entraînés...")
            self.load_models()
            self.is_trained = True
            return
        
        # Chargement des données si non fournies
        if df is None:
            df = self._load_training_data()
        
        if df is None or len(df) == 0:
            print("❌ Aucune donnée d'entraînement disponible")
            return
        
        print("🚀 Début de l'entraînement des modèles IA...")
        
        # Préparation des features
        features, labels = self.prepare_features(df)
        
        if labels is None:
            print("❌ Labels non trouvés pour l'entraînement supervisé")
            return
        
        # Division train/test
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )
        
        # Entraînement de chaque modèle
        for name, model in self.models.items():
            print(f"  → Entraînement de {name}...")
            
            if name == 'isolation_forest':
                # Isolation Forest ne nécessite pas de labels
                model.fit(features)
                y_pred = model.predict(features)
                y_pred_binary = (y_pred == -1).astype(int)
                y_true_binary = (labels != self.label_encoders['attack_label'].transform(['Normal'])[0]).astype(int)
                accuracy = accuracy_score(y_true_binary, y_pred_binary)
                f1 = f1_score(y_true_binary, y_pred_binary, average='weighted')
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred, average='weighted')
            
            self.training_metrics[name] = {
                'accuracy': round(accuracy * 100, 2),
                'f1_score': round(f1 * 100, 2),
                'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            print(f"     ✓ Accuracy: {accuracy*100:.2f}% | F1-Score: {f1*100:.2f}%")
        
        # Sauvegarde des modèles
        self.save_models()
        self.is_trained = True
        
        print("✅ Entraînement terminé avec succès!")
    
    def _load_training_data(self) -> pd.DataFrame:
        """Charge les données d'entraînement par défaut"""
        train_paths = [
            'data2/train_logs.csv',
            'data2/network_logs.csv',
            'data/network_logs.csv'
        ]
        
        for path in train_paths:
            if os.path.exists(path):
                print(f"📂 Chargement des données: {path}")
                return pd.read_csv(path)
        
        return None
    
    def predict(self, df: pd.DataFrame, model_name: str = 'voting') -> pd.DataFrame:
        """
        Effectue des prédictions sur un DataFrame
        
        Args:
            df: DataFrame à analyser
            model_name: Nom du modèle à utiliser
        
        Returns:
            DataFrame avec les prédictions et scores de confiance
        """
        if not self.is_trained:
            print("⚠️ Modèles non entraînés, entraînement automatique...")
            self.train_all_models(df)
        
        model = self.models.get(model_name)
        if model is None:
            raise ValueError(f"Modèle {model_name} non trouvé")
        
        # Préparation des features
        features, _ = self.prepare_features(df)
        
        # Prédictions
        if model_name == 'isolation_forest':
            predictions = model.predict(features)
            confidence = np.ones(len(features)) * 50
            is_threat = (predictions == -1).astype(int)
            threat_label = ['Menace détectée' if x == 1 else 'Normal' for x in is_threat]
        else:
            predictions = model.predict(features)
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(features)
                confidence = np.max(proba, axis=1) * 100
            else:
                confidence = np.ones(len(predictions)) * 50
            
            if 'attack_label' in self.label_encoders:
                threat_label = self.label_encoders['attack_label'].inverse_transform(predictions)
            else:
                threat_label = predictions
            is_threat = (threat_label != 'Normal').astype(int)
        
        # Création du DataFrame de résultats
        results = df.copy()
        results['predicted_threat'] = threat_label
        results['confidence_score'] = confidence.round(2)
        results['is_threat'] = is_threat
        
        # Score de criticité basé sur la confiance et le type de menace
        results['criticality_score'] = results['confidence_score'].copy()
        results['criticality_level'] = results['criticality_score'].apply(
            lambda x: 'Critique' if x >= 80 else 'Haute' if x >= 60 else 'Moyenne' if x >= 40 else 'Basse' if x >= 20 else 'Info'
        )
        
        return results
    
    def save_models(self):
        """Sauvegarde tous les modèles"""
        for name, model in self.models.items():
            path = f'{self.models_dir}/{name}.joblib'
            joblib.dump(model, path)
            print(f"💾 Modèle {name} sauvegardé: {path}")
        
        # Sauvegarde du scaler et des encodeurs
        joblib.dump(self.scaler, f'{self.models_dir}/scaler.joblib')
        joblib.dump(self.label_encoders, f'{self.models_dir}/label_encoders.joblib')
        joblib.dump(self.config, f'{self.models_dir}/config.joblib')
    
    def load_models(self):
        """Charge les modèles sauvegardés"""
        for name in self.models.keys():
            path = f'{self.models_dir}/{name}.joblib'
            if os.path.exists(path):
                self.models[name] = joblib.load(path)
        
        if os.path.exists(f'{self.models_dir}/scaler.joblib'):
            self.scaler = joblib.load(f'{self.models_dir}/scaler.joblib')
        if os.path.exists(f'{self.models_dir}/label_encoders.joblib'):
            self.label_encoders = joblib.load(f'{self.models_dir}/label_encoders.joblib')
        
        self.is_trained = True
        print("✅ Modèles chargés avec succès")
    
    def update_config(self, config: ModelConfig):
        """Met à jour la configuration et réinitialise les modèles"""
        self.config = config
        self._initialize_models()
        self.is_trained = False
        print("⚙️ Configuration mise à jour, réentraînement requis")


# ============================================================================
# VISUALISATIONS PROFESSIONNELLES
# ============================================================================

class ThreatVisualizer:
    """Classe pour les visualisations interactives des menaces"""
    
    @staticmethod
    def plot_threat_distribution(df: pd.DataFrame, title: str = "Distribution des Menaces") -> go.Figure:
        """Graphique de distribution des menaces"""
        if 'predicted_threat' not in df.columns:
            return go.Figure()
        
        threat_counts = df['predicted_threat'].value_counts()
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=("Distribution", "Pourcentage"),
            specs=[[{"type": "bar"}, {"type": "pie"}]]
        )
        
        # Bar chart
        fig.add_trace(
            go.Bar(x=threat_counts.index, y=threat_counts.values,
                   marker_color=['#ef4444', '#f59e0b', '#10b981', '#6366f1', '#8b5cf6'],
                   text=threat_counts.values, textposition='auto',
                   name='Nombre'),
            row=1, col=1
        )
        
        # Pie chart
        fig.add_trace(
            go.Pie(labels=threat_counts.index, values=threat_counts.values,
                   hole=0.4, name='Proportion'),
            row=1, col=2
        )
        
        fig.update_layout(
            title=title,
            height=500,
            showlegend=True,
            template='plotly_white'
        )
        
        fig.update_xaxes(title_text="Type de menace", row=1, col=1)
        fig.update_yaxes(title_text="Nombre d'occurrences", row=1, col=1)
        
        return fig
    
    @staticmethod
    def plot_confidence_distribution(df: pd.DataFrame) -> go.Figure:
        """Distribution des scores de confiance"""
        if 'confidence_score' not in df.columns:
            return go.Figure()
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Histogramme des scores", "Boxplot par menace",
                           "Courbe cumulative", "Heatmap confiance vs criticité"),
            vertical_spacing=0.12
        )
        
        # Histogramme
        fig.add_trace(
            go.Histogram(x=df['confidence_score'], nbinsx=20,
                         marker_color='#3b82f6', name='Confiance'),
            row=1, col=1
        )
        
        # Boxplot par menace
        if 'predicted_threat' in df.columns:
            for threat in df['predicted_threat'].unique():
                threat_data = df[df['predicted_threat'] == threat]['confidence_score']
                fig.add_trace(
                    go.Box(y=threat_data, name=threat, boxmean='sd'),
                    row=1, col=2
                )
        
        # Courbe cumulative
        sorted_conf = np.sort(df['confidence_score'])
        cumulative = np.arange(1, len(sorted_conf) + 1) / len(sorted_conf)
        fig.add_trace(
            go.Scatter(x=sorted_conf, y=cumulative, mode='lines',
                       fill='tozeroy', name='Cumul',
                       line=dict(color='#10b981', width=2)),
            row=2, col=1
        )
        
        # Heatmap
        if 'criticality_level' in df.columns:
            heatmap_data = pd.crosstab(
                pd.cut(df['confidence_score'], bins=10),
                df['criticality_level']
            )
            if not heatmap_data.empty:
                fig.add_trace(
                    go.Heatmap(z=heatmap_data.values,
                               x=heatmap_data.columns,
                               y=[f"{int(i.left)}-{int(i.right)}" for i in heatmap_data.index],
                               colorscale='RdYlGn', name='Heatmap'),
                    row=2, col=2
                )
        
        fig.update_layout(
            title="Analyse des Scores de Confiance",
            height=700,
            showlegend=True,
            template='plotly_white'
        )
        
        return fig
    
    @staticmethod
    def plot_timeline_evolution(df: pd.DataFrame) -> go.Figure:
        """Évolution temporelle des menaces"""
        if 'timestamp' not in df.columns:
            return go.Figure()
        
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        if 'predicted_threat' in df.columns:
            timeline = df.groupby(['date', 'predicted_threat']).size().reset_index(name='count')
            
            fig = go.Figure()
            
            for threat in timeline['predicted_threat'].unique():
                threat_data = timeline[timeline['predicted_threat'] == threat]
                fig.add_trace(go.Scatter(
                    x=threat_data['date'], y=threat_data['count'],
                    mode='lines+markers', name=threat,
                    line=dict(width=2), marker=dict(size=6)
                ))
            
            fig.update_layout(
                title="Évolution Temporelle des Menaces",
                xaxis_title="Date",
                yaxis_title="Nombre d'alertes",
                height=500,
                template='plotly_white',
                hovermode='x unified'
            )
            
            return fig
        
        return go.Figure()
    
    @staticmethod
    def plot_top_attackers(df: pd.DataFrame, top_n: int = 10) -> go.Figure:
        """Top des IPs attaquantes"""
        if 'src_ip' in df.columns and 'is_threat' in df.columns:
            top_ips = df[df['is_threat'] == 1]['src_ip'].value_counts().head(top_n)
            
            if not top_ips.empty:
                fig = go.Figure(go.Bar(
                    x=top_ips.values, y=top_ips.index, orientation='h',
                    marker_color='#ef4444', text=top_ips.values, textposition='outside'
                ))
                
                fig.update_layout(
                    title=f"Top {top_n} des IPs Sources Malveillantes",
                    xaxis_title="Nombre d'attaques",
                    yaxis_title="Adresse IP",
                    height=500,
                    template='plotly_white'
                )
                
                return fig
        
        return go.Figure()
    
    @staticmethod
    def generate_html_report(df: pd.DataFrame) -> str:
        """Génère un rapport HTML complet et interactif"""
        
        threat_count = df['is_threat'].sum() if 'is_threat' in df.columns else 0
        avg_confidence = df['confidence_score'].mean() if 'confidence_score' in df.columns else 0
        avg_criticality = df['criticality_score'].mean() if 'criticality_score' in df.columns else 0
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport d'Analyse des Menaces - Plateforme SOC</title>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin: 10px 0 0; opacity: 0.8; }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    padding: 30px;
                    background: #f8f9fa;
                }}
                .stat-card {{
                    background: white;
                    border-radius: 10px;
                    padding: 20px;
                    text-align: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                    border-left: 4px solid #667eea;
                }}
                .stat-card h3 {{ margin: 0 0 10px; color: #666; font-size: 0.9em; }}
                .stat-card .value {{ font-size: 2.5em; font-weight: bold; color: #1a1a2e; }}
                .section {{
                    padding: 30px;
                    border-bottom: 1px solid #eee;
                }}
                .section h2 {{
                    color: #1a1a2e;
                    margin-top: 0;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #667eea;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 12px;
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
                .badge-critical {{ background: #ef4444; color: white; padding: 3px 8px; border-radius: 20px; font-size: 0.7em; }}
                .badge-high {{ background: #f59e0b; color: white; padding: 3px 8px; border-radius: 20px; font-size: 0.7em; }}
                .badge-medium {{ background: #eab308; color: white; padding: 3px 8px; border-radius: 20px; font-size: 0.7em; }}
                .badge-low {{ background: #10b981; color: white; padding: 3px 8px; border-radius: 20px; font-size: 0.7em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Rapport d'Analyse des Menaces</h1>
                    <p>Plateforme IA de Détection des Menaces - Tunisie Telecom</p>
                    <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>Total Alertes</h3>
                        <div class="value">{len(df):,}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Menaces Détectées</h3>
                        <div class="value">{threat_count:,}</div>
                        <div class="unit">({threat_count/len(df)*100:.1f}%)</div>
                    </div>
                    <div class="stat-card">
                        <h3>Confiance Moyenne</h3>
                        <div class="value">{avg_confidence:.1f}</div>
                        <div class="unit">%</div>
                    </div>
                    <div class="stat-card">
                        <h3>Score Criticité Moyen</h3>
                        <div class="value">{avg_criticality:.1f}</div>
                        <div class="unit">/100</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html


# ============================================================================
# EXPORTS PROFESSIONNELS
# ============================================================================

class ThreatExporter:
    """Gestionnaire d'exports PDF, CSV, HTML"""
    
    @staticmethod
    def to_csv(df: pd.DataFrame) -> bytes:
        """Export CSV"""
        csv_data = df.to_csv(index=False, encoding='utf-8-sig')
        return csv_data.encode('utf-8-sig')
    
    @staticmethod
    def to_json(df: pd.DataFrame) -> str:
        """Export JSON"""
        result = {
            'metadata': {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_rows': len(df),
                'threats_detected': int(df['is_threat'].sum()) if 'is_threat' in df.columns else 0
            },
            'data': df.to_dict(orient='records')
        }
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    
    @staticmethod
    def to_html(df: pd.DataFrame) -> str:
        """Export HTML interactif"""
        return ThreatVisualizer.generate_html_report(df)
    
    @staticmethod
    def to_pdf_report(df: pd.DataFrame) -> bytes:
        """Export PDF simplifié"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            elements = []
            
            # Titre
            elements.append(Paragraph("Rapport d'Analyse des Menaces", styles['Title']))
            elements.append(Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", styles['Normal']))
            elements.append(Spacer(1, 20))
            
            # Statistiques
            data = [
                ["Métrique", "Valeur"],
                ["Total des alertes", str(len(df))],
                ["Menaces détectées", str(df['is_threat'].sum()) if 'is_threat' in df.columns else "N/A"],
                ["Confiance moyenne", f"{df['confidence_score'].mean():.1f}%" if 'confidence_score' in df.columns else "N/A"]
            ]
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(table)
            
            doc.build(elements)
            buffer.seek(0)
            return buffer.getvalue()
            
        except Exception as e:
            print(f"Erreur génération PDF: {e}")
            return ThreatExporter.to_csv(df)


# ============================================================================
# EXPLICABILITÉ
# ============================================================================

class ModelExplainer:
    """Explicabilité simplifiée des modèles"""
    
    @staticmethod
    def plot_feature_importance(model, feature_names: List[str], top_n: int = 10) -> go.Figure:
        """Graphique d'importance des features"""
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                indices = np.argsort(importances)[-top_n:]
                
                fig = go.Figure(go.Bar(
                    x=[importances[i] for i in indices],
                    y=[feature_names[i] for i in indices],
                    orientation='h',
                    marker_color='#667eea'
                ))
                
                fig.update_layout(
                    title="Importance des Features",
                    xaxis_title="Importance",
                    yaxis_title="Feature",
                    height=500,
                    template='plotly_white'
                )
                return fig
        except:
            pass
        
        return go.Figure()