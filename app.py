import streamlit as st
import firebase_admin
from firebase_admin import credentials, db
import pandas as pd
from datetime import datetime
from fpdf import FPDF
import json
import requests

# Initialize Firebase (only once)
if not firebase_admin._apps:
    firebase_config = st.secrets["firebase"]
    cred_dict = {
        "type": firebase_config["type"],
        "project_id": firebase_config["project_id"],
        "private_key_id": firebase_config["private_key_id"],
        "private_key": firebase_config["private_key"],
        "client_email": firebase_config["client_email"],
        "client_id": firebase_config["client_id"],
        "auth_uri": firebase_config["auth_uri"],
        "token_uri": firebase_config["token_uri"],
        "auth_provider_x509_cert_url": firebase_config["auth_provider_x509_cert_url"],
        "client_x509_cert_url": firebase_config["client_x509_cert_url"]
    }
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred, {
        'databaseURL': firebase_config["databaseURL"]
    })

# Session state for user
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None
if "id_token" not in st.session_state:
    st.session_state.id_token = None

# Helper functions
def get_role(uid):
    user_data = db.reference("users").child(uid).get()
    return user_data["role"] if user_data else None

def log_audit(action, details):
    uid = st.session_state.user["uid"] if st.session_state.user else "anonymous"
    audit_data = {
        "action": action,
        "by": uid,
        "timestamp": datetime.now().isoformat(),
        "details": json.dumps(details, default=str)
    }
    db.reference("audit").push(audit_data)

def sign_in_with_email_and_password(email, password):
    """Sign in using Firebase REST API."""
    api_key = st.secrets["firebase"]["apiKey"]
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(response.json().get("error", {}).get("message", "Login failed"))

def create_user_with_email_and_password(email, password):
    """Create user using Firebase Admin SDK."""
    try:
        user = firebase_admin.auth.create_user(email=email, password=password)
        return user
    except Exception as e:
        raise Exception(f"Sign-up failed: {str(e)}")

# Authentication pages
def login():
    st.subheader("Login")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_button"):
        try:
            user_data = sign_in_with_email_and_password(email, password)
            st.session_state.user = {
                "uid": user_data["localId"],
                "email": user_data["email"]
            }
            st.session_state.id_token = user_data["idToken"]
            st.session_state.role = get_role(user_data["localId"])
            st.success("Logged in successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Login failed: {str(e)}")

def signup():
    st.subheader("Sign Up")
    email = st.text_input("Email", key="signup_email")
    password = st.text_input("Password", type="password", key="signup_password")
    role = st.selectbox("Role", ["user", "admin"], key="signup_role")  # Restrict admin in production
    if st.button("Sign Up", key="signup_button"):
        try:
            user = create_user_with_email_and_password(email, password)
            db.reference("users").child(user.uid).set({"email": email, "role": role})
            st.success("Account created! Please log in.")
        except Exception as e:
            st.error(f"Sign-up failed: {str(e)}")

def logout():
    st.session_state.user = None
    st.session_state.role = None
    st.session_state.id_token = None
    st.success("Logged out")
    st.rerun()

# Main app
if not st.session_state.user:
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    with tab1:
        login()
    with tab2:
        signup()
else:
    st.sidebar.button("Logout", on_click=logout)
    uid = st.session_state.user["uid"]
    role = st.session_state.role
    st.title("Tourism Office Payment Record System")
    st.sidebar.title("Menu")
    menu = st.sidebar.selectbox("Select Function", ["Add Payment", "Search/View Payments", "Edit Payment", "Delete Payment", "Reports", "Audit Trail"])

    payment_types = [
        "accreditation fee",
        "entrance fee",
        "environmental fee & presentation fee",
        "environmental protection fee"
    ]

    # Fetch all payments
    @st.cache_data(ttl=60)
    def get_payments():
        payments = db.reference("payments").get()
        return payments if payments else {}

    payments = get_payments()
    df = pd.DataFrame.from_dict(payments, orient="index") if payments else pd.DataFrame()

    if menu == "Add Payment":
        st.subheader("Add Payment")
        payment_type = st.selectbox("Payment Type", payment_types)
        amount = st.number_input("Amount", min_value=0.0)
        payer = st.text_input("Payer Name")
        date = st.date_input("Date", value=datetime.today())
        if st.button("Add"):
            data = {
                "type": payment_type,
                "amount": amount,
                "payer": payer,
                "date": date.isoformat(),
                "added_by": uid
            }
            new_id = db.reference("payments").push(data).key
            log_audit("add", data)
            st.success("Payment added!")
            st.rerun()

    elif menu == "Search/View Payments":
        st.subheader("Search/View Payments")
        query = st.text_input("Search by Payer or Type")
        if not df.empty:
            df['date'] = pd.to_datetime(df['date'])
            filtered = df[
                df['payer'].str.contains(query, case=False, na=False) |
                df['type'].str.contains(query, case=False, na=False)
            ]
            if role == "user":
                filtered = filtered[filtered["added_by"] == uid]
            st.dataframe(filtered)
            csv = filtered.to_csv(index=True)
            st.download_button("Download as CSV", csv, "payments.csv", "text/csv")

    elif menu == "Edit Payment":
        st.subheader("Edit Payment")
        if not df.empty:
            options = {f"{row['payer']} - {row['type']} ({row['date']})": idx for idx, row in df.iterrows()}
            selected = st.selectbox("Select Payment to Edit", list(options.keys()))
            if selected:
                pid = options[selected]
                payment = df.loc[pid]
                if role == "user" and payment["added_by"] != uid:
                    st.error("You can only edit your own payments")
                else:
                    payment_type = st.selectbox("Payment Type", payment_types, index=payment_types.index(payment["type"]))
                    amount = st.number_input("Amount", value=float(payment["amount"]))
                    payer = st.text_input("Payer Name", value=payment["payer"])
                    date = st.date_input("Date", value=pd.to_datetime(payment["date"]))
                    if st.button("Update"):
                        updated_data = {
                            "type": payment_type,
                            "amount": amount,
                            "payer": payer,
                            "date": date.isoformat(),
                            "added_by": payment["added_by"]
                        }
                        db.reference("payments").child(pid).set(updated_data)
                        log_audit("edit", {"old": payment.to_dict(), "new": updated_data})
                        st.success("Payment updated!")
                        st.rerun()

    elif menu == "Delete Payment":
        if role != "admin":
            st.error("Only admins can delete payments")
        else:
            st.subheader("Delete Payment")
            if not df.empty:
                options = {f"{row['payer']} - {row['type']} ({row['date']})": idx for idx, row in df.iterrows()}
                selected = st.selectbox("Select Payment to Delete", list(options.keys()))
                if selected:
                    pid = options[selected]
                    if st.button("Delete"):
                        details = df.loc[pid].to_dict()
                        db.reference("payments").child(pid).delete()
                        log_audit("delete", details)
                        st.success("Payment deleted!")
                        st.rerun()

    elif menu == "Reports":
        st.subheader("Reports")
        report_type = st.selectbox("Report Type", ["Monthly", "Yearly"])
        if not df.empty:
            df['date'] = pd.to_datetime(df['date'])
            if report_type == "Yearly":
                year = st.number_input("Year", min_value=2000, max_value=2100, value=datetime.now().year)
                filtered = df[df['date'].dt.year == year]
            else:  # Monthly
                year = st.number_input("Year", min_value=2000, max_value=2100, value=datetime.now().year)
                month = st.number_input("Month", min_value=1, max_value=12, value=datetime.now().month)
                filtered = df[(df['date'].dt.year == year) & (df['date'].dt.month == month)]
            
            if role == "user":
                filtered = filtered[filtered["added_by"] == uid]
            
            if not filtered.empty:
                summary = filtered.groupby("type")["amount"].agg(["sum", "count"]).reset_index()
                summary.loc[len(summary)] = ["Total", filtered["amount"].sum(), len(filtered)]
                st.table(summary)
                
                csv = summary.to_csv(index=False)
                st.download_button("Download Report as CSV", csv, f"{report_type.lower()}_report.csv", "text/csv")
                
                if st.button("Generate PDF Report"):
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", size=12)
                    pdf.cell(200, 10, txt=f"{report_type} Report", ln=1, align="C")
                    for i, row in summary.iterrows():
                        pdf.cell(200, 10, txt=f"{row['type']}: Sum={row['sum']}, Count={row['count']}", ln=1)
                    pdf_output = f"{report_type.lower()}_report.pdf"
                    pdf.output(pdf_output)
                    with open(pdf_output, "rb") as f:
                        st.download_button("Download PDF", f, pdf_output, "application/pdf")

    elif menu == "Audit Trail":
        if role != "admin":
            st.error("Only admins can view audit trail")
        else:
            st.subheader("Audit Trail")
            audits = db.reference("audit").get()
            if audits:
                audit_df = pd.DataFrame.from_dict(audits, orient="index")
                st.dataframe(audit_df)
                csv = audit_df.to_csv(index=True)
                st.download_button("Download Audit as CSV", csv, "audit.csv", "text/csv")