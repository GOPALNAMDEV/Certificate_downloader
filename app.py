import os
import sqlite3
import random
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import (
    Flask, request, render_template,
    redirect, url_for, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# ============================================================
# LOAD ENV (local only – Render uses dashboard env vars)
# ============================================================
load_dotenv()

# ============================================================
# FLASK SETUP
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")

# ============================================================
# ADMIN
# ============================================================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "recruitplusindia")
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASSWORD", "admin_password")
)

# ============================================================
# SMTP2GO CONFIG  (RENDER SAFE)
# ============================================================
SMTP_HOST = "mail.smtp2go.com"
SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")   # MUST be: apikey
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")   # SMTP2GO API KEY
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")     # no-reply@domain.com

# ============================================================
# DATABASE
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")

# ============================================================
# OTP STORE (IN-MEMORY)
# ============================================================
otp_store = {}  # {email: {"otp": int, "expires": datetime, "last_sent": datetime}}

# ============================================================
# DATABASE HELPERS
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            gmail TEXT NOT NULL,
            name TEXT NOT NULL,
            course TEXT NOT NULL,
            title TEXT NOT NULL,
            certificate_name TEXT NOT NULL,
            certificate_data TEXT NOT NULL,
            PRIMARY KEY (gmail, title)
        )
    """)
    db.commit()

def get_all_candidates():
    return get_db().execute(
        "SELECT gmail, name, course, title, certificate_name, certificate_data FROM candidates"
    ).fetchall()

def get_candidate_certificates(gmail):
    return get_db().execute(
        "SELECT title, name, course FROM candidates WHERE gmail=?",
        (gmail,)
    ).fetchall()

# ============================================================
# SMTP EMAIL (RENDER SAFE – NO THREADS)
# ============================================================
def send_email(msg):
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            print(f"✅ Email sent to {msg['To']}")
    except Exception as e:
        print("❌ SMTP2GO ERROR:", e)

# ============================================================
# OTP LOGIC
# ============================================================
def send_otp(email):
    now = datetime.utcnow()

    if email in otp_store:
        if (now - otp_store[email]["last_sent"]).total_seconds() < 60:
            return

    otp = random.randint(100000, 999999)
    otp_store[email] = {
        "otp": otp,
        "expires": now + timedelta(minutes=10),
        "last_sent": now
    }

    msg = EmailMessage()
    msg["From"] = f"RecruitPlus <{SENDER_EMAIL}>"
    msg["To"] = email
    msg["Subject"] = "Your Certificate Verification Code"

    msg.set_content(f"Your OTP is {otp}")

    msg.add_alternative(f"""
    <html>
    <body style="font-family:Arial;background:#f4f6fb;padding:20px;">
      <div style="max-width:520px;margin:auto;background:#fff;padding:30px;border-radius:10px;">
        <h2 style="color:#2563eb;">Certificate Verification Code</h2>
        <p>Your OTP is:</p>
        <h1 style="letter-spacing:4px;">{otp}</h1>
        <p>This code is valid for 10 minutes.</p>
        <hr>
        <p style="font-size:12px;color:#777;">© 2025 RecruitPlus India</p>
      </div>
    </body>
    </html>
    """, subtype="html")

    send_email(msg)

# ============================================================
# OTP CLEANUP (LIGHTWEIGHT)
# ============================================================
@app.before_request
def cleanup_otps():
    now = datetime.utcnow()
    expired = [e for e, d in otp_store.items() if now > d["expires"]]
    for e in expired:
        otp_store.pop(e, None)

# ============================================================
# INIT DB
# ============================================================
with app.app_context():
    init_db()

# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def index():
    return render_template("index.html", certificates=None, status="info")

@app.route("/check-certificate", methods=["POST"])
def check_certificate():
    gmail = request.form.get("gmail")
    certificates = get_candidate_certificates(gmail)

    if certificates:
        send_otp(gmail)
        session["pending_gmail"] = gmail
        return render_template("verify_otp.html", gmail=gmail)

    return render_template("index.html", status="error", gmail=gmail)

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    gmail = session.get("pending_gmail")
    entered_otp = request.form.get("otp")

    record = otp_store.get(gmail)
    if not record:
        return render_template("verify_otp.html", gmail=gmail, error="OTP expired")

    if datetime.utcnow() > record["expires"]:
        otp_store.pop(gmail, None)
        return render_template("verify_otp.html", gmail=gmail, error="OTP expired")

    if str(record["otp"]) != entered_otp:
        return render_template("verify_otp.html", gmail=gmail, error="Invalid OTP")

    otp_store.pop(gmail, None)
    session.pop("pending_gmail", None)

    certificates = get_candidate_certificates(gmail)
    return render_template("index.html", certificates=certificates, status="success", gmail=gmail)

# ============================================================
# ADMIN
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME and
            check_password_hash(ADMIN_PASSWORD_HASH, request.form["password"])
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", candidates=get_all_candidates())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
