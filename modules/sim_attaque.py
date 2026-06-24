import streamlit as st
import time
import random
import pandas as pd
import ipaddress

def display():
    st.title("⚔️ Simulation d’Attaque avec Plage IP Personnalisée")

    # Choix type d'attaque simulée
    attaque_type = st.selectbox("Choisir le type d'attaque simulée", [
        "Brute Force",
        "Injection SQL",
        "DDoS",
        "Phishing",
        "Malware"
    ])

    st.markdown("### 🎯 Définissez la plage d’adresses IP sources à simuler")

    ip_debut = st.text_input("IP Source Début", value="192.168.1.1")
    ip_fin = st.text_input("IP Source Fin", value="192.168.1.254")
    masque = st.text_input("Masque sous-réseau (ex : 24)", value="24")

    # Valider IP et plage
    plage_ips = []
    erreur_ip = ""
    try:
        ip_start = ipaddress.IPv4Address(ip_debut)
        ip_end = ipaddress.IPv4Address(ip_fin)
        masque_int = int(masque)

        if ip_start > ip_end:
            erreur_ip = "L'adresse IP de début doit être inférieure ou égale à l'adresse IP de fin."
        elif masque_int < 0 or masque_int > 32:
            erreur_ip = "Le masque doit être un entier entre 0 et 32."
        else:
            # Créer la plage IP limitée par ip_start et ip_end et masque
            réseau = ipaddress.IPv4Network(f"{ip_debut}/{masque}", strict=False)
            plage_ips = [str(ip) for ip in réseau.hosts() if ip_start <= ip <= ip_end]
            if not plage_ips:
                erreur_ip = "Aucune IP valide dans la plage/mask spécifiée."
    except Exception as e:
        erreur_ip = f"Erreur dans la saisie des IP ou masque : {e}"

    if erreur_ip:
        st.error(erreur_ip)
        return

    nombre_alertes = st.slider("Nombre d'alertes à générer", min_value=10, max_value=100, value=30)

    if st.button("🚀 Lancer la simulation"):
        st.info(f"Lancement de la simulation : {attaque_type} avec {nombre_alertes} alertes.")
        if not plage_ips:
            st.warning("La plage d’IP sources est vide. Veuillez corriger les paramètres.")
            return

        progress_bar = st.progress(0)
        alertes = []

        for i in range(nombre_alertes):
            time.sleep(0.05)  # Simuler temps de traitement

            alerte = generer_alerte(attaque_type, i+1, plage_ips)
            alertes.append(alerte)

            # Afficher uniquement toutes les 5 alertes pour ne pas saturer l'UI
            if (i + 1) % 5 == 0 or (i + 1) == nombre_alertes:
                st.dataframe(pd.DataFrame(alertes), use_container_width=True)

            progress_bar.progress((i + 1) / nombre_alertes)

        st.success("Simulation terminée !")

        # Résumé synthétique
        df_alertes = pd.DataFrame(alertes)
        st.markdown(f"### 📊 Résumé des alertes générées")
        st.write(df_alertes.groupby("IP_Source").size().rename("Nombre d'alertes").sort_values(ascending=False).head(10))

        # Export CSV
        csv_data = df_alertes.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Télécharger les alertes (CSV)", csv_data, f"simulation_{attaque_type}.csv", "text/csv")


def generer_alerte(type_attaque, id_alerte, plage_ips):
    ip_dests = ["10.0.0." + str(i) for i in range(1, 255)]
    ports = [22, 80, 443, 8080, 3306, 3389]

    alerte = {
        "ID_Alerte": id_alerte,
        "Type_Attaquant": type_attaque,
        "IP_Source": random.choice(plage_ips),
        "IP_Destination": random.choice(ip_dests),
        "Port_Cible": random.choice(ports),
        "Heure": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Description": ""
    }

    descriptions = {
        "Brute Force": "Tentative répétée de connexion échouée.",
        "Injection SQL": "Injection détectée dans une requête base de données.",
        "DDoS": "Trafic anormalement élevé sur un service.",
        "Phishing": "Email suspect détecté avec lien malveillant.",
        "Malware": "Activité malveillante suspectée sur le réseau."
    }
    alerte["Description"] = descriptions.get(type_attaque, "Alerte inconnue")

    return alerte


if __name__ == "__main__":
    display()
