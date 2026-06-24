import streamlit as st
import pandas as pd
import plotly.express as px

def display(df):
    st.header("📊 Tableau de bord de l'Administrateur")

    # -----------------------
    # Statistiques globales
    # -----------------------
    st.subheader("📈 Statistiques globales")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Répartition par type de menace**")
        type_counts = df['Type_Menace'].value_counts().reset_index()
        type_counts.columns = ['Type_Menace', 'count']
        fig1 = px.bar(
            type_counts,
            x='Type_Menace', y='count',
            labels={'Type_Menace': 'Type de menace', 'count': 'Nombre'},
            color='Type_Menace',
            template='plotly_white'
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        st.write("**Répartition par statut**")
        statut_counts = df['Statut'].value_counts().reset_index()
        statut_counts.columns = ['Statut', 'count']
        fig2 = px.pie(
            statut_counts,
            names='Statut', values='count',
            title="Répartition par statut",
            template='plotly_white'
        )
        st.plotly_chart(fig2, use_container_width=True)

    # -----------------------
    # Gestion des utilisateurs
    # -----------------------
    st.subheader("👤 Gestion des utilisateurs")

    # Initialiser la liste des utilisateurs
    if 'user_db' not in st.session_state:
        st.session_state.user_db = [
            {'username': 'admin', 'password': 'admin123', 'role': 'Administrateur'},
            {'username': 'superviseur1', 'password': 'test123', 'role': 'Superviseur'}
        ]

    st.write("### 🔐 Utilisateurs actifs")
    users_df = pd.DataFrame(st.session_state.user_db)
    st.dataframe(users_df[['username', 'role']])

    st.write("### ➕ Ajouter un nouvel utilisateur")

    with st.form("add_user_form"):
        new_username = st.text_input("Nom d'utilisateur")
        new_password = st.text_input("Mot de passe", type="password")
        new_role = st.selectbox("Rôle", ["Administrateur", "Superviseur", "Ingénieur", "Technicien", "Réseau"])
        submitted = st.form_submit_button("Créer l'utilisateur")

        if submitted:
            if any(user['username'] == new_username for user in st.session_state.user_db):
                st.warning("⚠️ Utilisateur déjà existant.")
            elif new_username and new_password:
                st.session_state.user_db.append({
                    'username': new_username,
                    'password': new_password,
                    'role': new_role
                })
                st.success(f"✅ Utilisateur '{new_username}' ajouté avec succès.")
            else:
                st.error("❌ Veuillez remplir tous les champs.")

    # -----------------------
    # Configuration système
    # -----------------------
    st.subheader("⚙️ Configuration du système")

    st.markdown("**Notifications**")
    email_notify = st.checkbox("📧 Activer les notifications email", True)
    sms_notify = st.checkbox("📱 Activer les notifications SMS", False)
    slack_notify = st.checkbox("💬 Activer les notifications Slack/Teams", True)

    escalation_time = st.slider(
        "⏱️ Délai d'escalade automatique (minutes)",
        min_value=5, max_value=120, value=30
    )

    if st.button("💾 Enregistrer les configurations"):
        st.success("✅ Configurations enregistrées avec succès.")
