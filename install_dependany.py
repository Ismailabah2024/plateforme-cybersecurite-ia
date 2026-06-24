#!/usr/bin/env python3
"""
Script d'installation automatique des dépendances pour le projet
Exécutez ce script avec: python install_dependencies.py
"""

import subprocess
import sys
import platform
import os
from typing import List, Tuple

# Liste des dépendances à installer
DEPENDENCIES = [
    # Core dependencies
    "streamlit>=1.28.0",
    "pandas>=1.5.0",
    "numpy>=1.23.0",
    
    # Machine Learning
    "scikit-learn>=1.2.0",
    "xgboost>=1.7.0",
    "joblib>=1.2.0",
    
    # Visualizations
    "plotly>=5.13.0",
    "matplotlib>=3.6.0",
    "seaborn>=0.12.0",
    "pydeck>=0.8.0",
    
    # Data processing
    "openpyxl>=3.0.0",
    "xlsxwriter>=3.0.0",
    
    # PDF generation
    "reportlab>=3.6.0",
    "fpdf>=1.7.2",
    
    # Network and security
    "ipaddress>=1.0.0",
    "networkx>=2.8.0",
    
    # Utilities
    "python-dateutil>=2.8.0",
    "pytz>=2022.0",
]

def get_python_command() -> str:
    """Détecte la commande Python correcte selon le système"""
    if platform.system() == "Windows":
        return "python"
    return "python3"

def run_command(cmd: List[str], description: str) -> Tuple[bool, str]:
    """Exécute une commande système et retourne le résultat"""
    print(f"\n📦 {description}...")
    print(f"🔧 Commande: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=False,
            encoding='utf-8'
        )
        
        if result.returncode == 0:
            print(f"✅ {description} - Succès!")
            return True, result.stdout
        else:
            print(f"❌ {description} - Échec!")
            if result.stderr:
                print(f"   Erreur: {result.stderr[:200]}")
            return False, result.stderr
    except Exception as e:
        print(f"❌ {description} - Exception: {str(e)}")
        return False, str(e)

def check_pip() -> bool:
    """Vérifie si pip est installé"""
    python_cmd = get_python_command()
    success, _ = run_command(
        [python_cmd, "-m", "pip", "--version"],
        "Vérification de pip"
    )
    return success

def upgrade_pip() -> bool:
    """Met à jour pip vers la dernière version"""
    python_cmd = get_python_command()
    success, _ = run_command(
        [python_cmd, "-m", "pip", "install", "--upgrade", "pip"],
        "Mise à jour de pip"
    )
    return success

def install_dependencies(method: str = "batch") -> dict:
    """
    Installe toutes les dépendances
    
    Args:
        method: "batch" (une seule commande) ou "individual" (un par un)
    
    Returns:
        Dictionnaire avec les résultats d'installation
    """
    python_cmd = get_python_command()
    results = {"success": [], "failed": []}
    
    if method == "batch":
        print("\n" + "="*60)
        print("🔧 INSTALLATION GROUPÉE DE TOUTES LES DÉPENDANCES")
        print("="*60)
        
        cmd = [python_cmd, "-m", "pip", "install"] + DEPENDENCIES
        success, output = run_command(cmd, "Installation groupée")
        
        if success:
            results["success"].extend(DEPENDENCIES)
        else:
            print("\n⚠️ L'installation groupée a échoué. Passage à l'installation individuelle...")
            results = install_dependencies(method="individual")
    
    else:  # individual
        print("\n" + "="*60)
        print("🔧 INSTALLATION INDIVIDUELLE DES DÉPENDANCES")
        print("="*60)
        
        for i, dependency in enumerate(DEPENDENCIES, 1):
            print(f"\n[{i}/{len(DEPENDENCIES)}] Installation de {dependency}")
            cmd = [python_cmd, "-m", "pip", "install", dependency]
            success, _ = run_command(cmd, f"Installation de {dependency}")
            
            if success:
                results["success"].append(dependency)
            else:
                results["failed"].append(dependency)
    
    return results

def create_requirements_file():
    """Crée un fichier requirements.txt"""
    with open("requirements.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(DEPENDENCIES))
    print("\n✅ Fichier requirements.txt créé avec succès!")
    print("   Vous pouvez aussi installer avec: pip install -r requirements.txt")

def verify_installations() -> List[str]:
    """Vérifie que tous les packages sont bien installés"""
    python_cmd = get_python_command()
    missing_packages = []
    
    print("\n" + "="*60)
    print("🔍 VÉRIFICATION DES INSTALLATIONS")
    print("="*60)
    
    for dependency in DEPENDENCIES:
        # Extraire le nom du package (sans la version)
        package_name = dependency.split('>=')[0].split('==')[0]
        
        cmd = [python_cmd, "-c", f"import {package_name.replace('-', '_')}"]
        success, _ = run_command(cmd, f"Vérification de {package_name}")
        
        if not success:
            missing_packages.append(dependency)
    
    return missing_packages

def main():
    """Fonction principale"""
    print("\n" + "="*60)
    print("🚀 SCRIPT D'INSTALLATION AUTOMATIQUE DES DÉPENDANCES")
    print("="*60)
    
    # Informations système
    print(f"\n💻 Système: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {platform.python_version()}")
    print(f"📦 Nombre de dépendances: {len(DEPENDENCIES)}")
    
    # Vérification de pip
    if not check_pip():
        print("\n❌ pip n'est pas installé ou n'est pas accessible!")
        print("   Veuillez installer pip avant de continuer.")
        sys.exit(1)
    
    # Option de mise à jour de pip
    print("\n" + "-"*60)
    choice = input("Voulez-vous mettre à jour pip ? (o/N): ").lower()
    if choice == 'o':
        upgrade_pip()
    
    # Choix de la méthode d'installation
    print("\n" + "-"*60)
    print("Choisissez la méthode d'installation:")
    print("1 - Installation groupée (plus rapide, recommandée)")
    print("2 - Installation individuelle (plus lente, mais plus fiable)")
    
    method_choice = input("\nVotre choix (1/2): ").strip()
    method = "batch" if method_choice == "1" else "individual"
    
    # Installation
    results = install_dependencies(method)
    
    # Création du fichier requirements.txt
    print("\n" + "-"*60)
    create_req = input("Voulez-vous créer un fichier requirements.txt ? (O/n): ").lower()
    if create_req != 'n':
        create_requirements_file()
    
    # Vérification
    missing = verify_installations()
    
    # Résumé final
    print("\n" + "="*60)
    print("📊 RÉSUMÉ DE L'INSTALLATION")
    print("="*60)
    
    if results["success"]:
        print(f"\n✅ Installés avec succès: {len(results['success'])} packages")
        for pkg in results["success"]:
            print(f"   • {pkg}")
    
    if results["failed"]:
        print(f"\n❌ Échec d'installation: {len(results['failed'])} packages")
        for pkg in results["failed"]:
            print(f"   • {pkg}")
    
    if missing:
        print(f"\n⚠️ Packages manquants après vérification: {len(missing)}")
        for pkg in missing:
            print(f"   • {pkg}")
        print("\n💡 Suggestions:")
        print("   - Vérifiez votre connexion internet")
        print("   - Essayez avec: pip install --user <package>")
        print("   - Ou utilisez un environnement virtuel")
    else:
        print("\n🎉 Tous les packages sont correctement installés!")
        print("   Vous pouvez maintenant lancer votre application.")
    
    print("\n" + "="*60)
    print("✨ Installation terminée!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Installation interrompue par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {str(e)}")
        sys.exit(1)