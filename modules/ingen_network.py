import streamlit as st
import pandas as pd
import pydeck as pdk
import plotly.express as px

def display(df):
    st.header("🌐 Tableau de bord de l'Ingénieur Réseau")

    # ----------------------
    # Cartographie réseau
    # ----------------------
    st.subheader("📍 Cartographie des incidents réseau")

    if not df.empty:
        df_map = df.copy()

        # Géolocalisation fictive (plausible) selon IP
        df_map['lat'] = df_map['IP_Source'].apply(lambda x: 30 + int(x.split('.')[0]) * 0.2)
        df_map['lon'] = df_map['IP_Source'].apply(lambda x: 10 + int(x.split('.')[1]) * 0.2)

        layer = pdk.Layer(
            'ScatterplotLayer',
            data=df_map,
            get_position='[lon, lat]',
            get_color='[200, 30, 0, 160]',
            get_radius=10000,
            pickable=True
        )

        view_state = pdk.ViewState(
            latitude=df_map['lat'].mean(),
            longitude=df_map['lon'].mean(),
            zoom=4
        )

        st.pydeck_chart(pdk.Deck(
            layers=[layer],
            initial_view_state=view_state,
            tooltip={"text": "🛑 IP: {IP_Source}\n🚨 Menace: {Type_Menace}"}
        ))
    else:
        st.info("Aucune donnée disponible pour la cartographie réseau.")

    # ----------------------
    # Analyse des ports
    # ----------------------
    st.subheader("📊 Analyse des ports attaqués")

    if 'Ports' in df.columns:
        port_counts = df['Ports'].value_counts().reset_index()
        port_counts.columns = ['Port', 'Count']
        fig_port = px.bar(
            port_counts.head(10),
            x='Port', y='Count',
            title="Top 10 des ports les plus attaqués",
            labels={'Port': 'Port', 'Count': 'Nombre d’attaques'},
            color='Port',
            template='plotly_dark'
        )
        st.plotly_chart(fig_port, use_container_width=True)
    else:
        st.warning("⚠️ Colonne 'Ports' absente du jeu de données.")

    # ----------------------
    # Blocage réseau
    # ----------------------
    st.subheader("🛡️ Gestion des blocages réseau")

    if 'IP_Source' in df.columns and not df.empty:
        selected_ip = st.selectbox("🔌 IP à bloquer", df['IP_Source'].unique())

        # Initialisation de la liste d'IP bloquées
        if 'blocked_ips' not in st.session_state:
            st.session_state.blocked_ips = []

        if st.button(f"🚫 Bloquer {selected_ip}"):
            if selected_ip not in st.session_state.blocked_ips:
                st.session_state.blocked_ips.append(selected_ip)
                st.success(f"✅ IP {selected_ip} bloquée (simulation).")
            else:
                st.info(f"ℹ️ L’IP {selected_ip} est déjà bloquée.")

        st.write("📋 IP bloquées :")
        st.code('\n'.join(st.session_state.blocked_ips) if st.session_state.blocked_ips else "Aucune")
    else:
        st.info("Aucune IP disponible pour blocage.")

    # ----------------------
    # Export PCAP simulé
    # ----------------------
    st.subheader("📤 Export pour analyse PCAP")

    if 'ID_Incident' in df.columns:
        selected_incident = st.selectbox("🗂️ Sélectionner un incident", df['ID_Incident'].unique())

        if st.button("💾 Générer un fichier PCAP simulé"):
            st.success(f"Fichier PCAP généré pour l'incident {selected_incident} (simulation).")
            st.caption("🔧 Commande simulée : `tcpdump -i eth0 -w incident_{selected_incident}.pcap`")
    else:
        st.warning("⚠️ Colonne 'ID_Incident' manquante dans les données.")
