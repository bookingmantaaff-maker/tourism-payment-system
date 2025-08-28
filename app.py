import streamlit as st
import pyrebase
import pandas as pd
from datetime import datetime
from fpdf import FPDF  # For PDF generation (optional)

# Initialize Firebase
config = st.secrets["firebase"]
firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()

# Session state for user
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# Helper functions
def get_role(uid):
    user_data = db.child("users").child(uid).get().val()
    return user_data["role"] if user_data else None

def log_audit(action, details):
    uid = st.session_state.user["localId"]
    audit_data = {
        "action": action,
        "by": uid,
        "timestamp": datetime.now().isoformat(),
        "details": details
    }
    db.child("audit").push(audit_data)

# Authentication pages
def login():
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            st.session_state.user = user
            st.session_state.role = get_role(user["localId"])
            st.success("Logged in successfully!")
            st.rerun()  # Refresh app
        except:
            st.error("Invalid email or password")

def signup():
    st.subheader("Sign Up")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["user", "admin"])  # For demo; in production, restrict admin creation
    if st.button("Sign Up"):
        try:
            user = auth.create_user_with_email_and_password(email, password)
            uid = user["localId"]
            db.child("users").child(uid).set({"email": email, "role": role})
            st.success("Account created! Please log in.")
        except:
            st.error("Email already exists or invalid input")

def logout():
    st.session_state.user = None
    st.session_state.role = None
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
    uid = st.session_state.user["localId"]
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
    @st.cache_data(ttl=60)  # Cache for 1 min
    def get_payments():
        payments = db.child("payments").get().val()
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
            new_id = db.child("payments").push(data)["name"]  # Get generated ID
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
                filtered = filtered[filtered["added_by"] == uid]  # Users see only their own
            st.dataframe(filtered)
            # Download as CSV
            csv = filtered.to_csv(index=True)
            st.download_button("Download as CSV", csv, "payments.csv", "text/csv")

    elif menu == "Edit Payment":
        st.subheader("Edit Payment")
        if not df.empty:
            options = {row["payer"] + " - " + row["type"] + " (" + row["date"] + ")": idx for idx, row in df.iterrows()}
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
                        db.child("payments").child(pid).update(updated_data)
                        log_audit("edit", {"old": payment.to_dict(), "new": updated_data})
                        st.success("Payment updated!")
                        st.rerun()

    elif menu == "Delete Payment":
        if role != "admin":
            st.error("Only admins can delete payments")
        else:
            st.subheader("Delete Payment")
            if not df.empty:
                options = {row["payer"] + " - " + row["type"] + " (" + row["date"] + ")": idx for idx, row in df.iterrows()}
                selected = st.selectbox("Select Payment to Delete", list(options.keys()))
                if selected:
                    pid = options[selected]
                    if st.button("Delete"):
                        details = df.loc[pid].to_dict()
                        db.child("payments").child(pid).remove()
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
                summary.loc["Total"] = ["", filtered["amount"].sum(), len(filtered)]
                st.table(summary)
                
                # Download as CSV
                csv = summary.to_csv(index=False)
                st.download_button("Download Report as CSV", csv, f"{report_type.lower()}_report.csv", "text/csv")
                
                # Optional: Generate PDF
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
            audits = db.child("audit").get().val()
            if audits:
                audit_df = pd.DataFrame.from_dict(audits, orient="index")
                st.dataframe(audit_df)
                csv = audit_df.to_csv(index=True)
                st.download_button("Download Audit as CSV", csv, "audit.csv", "text/csv")