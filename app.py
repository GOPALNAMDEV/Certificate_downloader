import os
import sqlite3
import base64
import random
import io
from datetime import datetime, timedelta

import requests
from flask import (
    Flask, request, render_template,
    redirect, url_for, session,
    send_file, Response, g
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
# SMTP2GO HTTP API (SENDGRID-LIKE)
# ============================================================
SMTP2GO_API_KEY = os.environ.get("SMTP2GO_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")

# ============================================================
# DATABASE
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")

# ============================================================
# OTP STORE (IN-MEMORY – SAME AS SENDGRID VERSION)
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

def get_certificate_data(gmail, title):
    return get_db().execute(
        "SELECT certificate_name, certificate_data FROM candidates WHERE gmail=? AND title=?",
        (gmail, title)
    ).fetchone()

# ============================================================
# SMTP2GO HTTP EMAIL (NO SMTP, NO THREADS)
# ============================================================
def send_email_api(to_email, subject, html_body):
    url = "https://api.smtp2go.com/v3/email/send"
    payload = {
        "api_key": SMTP2GO_API_KEY,
        "to": [to_email],
        "sender": SENDER_EMAIL,
        "subject": subject,
        "html_body": html_body,
        "text_body": "Your email client does not support HTML"
    }

    try:
        r = requests.post(url, json=payload, timeout=10)
        print("📩 SMTP2GO:", r.json())
    except Exception as e:
        print("❌ SMTP2GO ERROR:", e)

# ============================================================
# OTP LOGIC (SENDGRID-STYLE SAFE)
# ============================================================
def send_otp(email):
    now = datetime.utcnow()

    if email in otp_store and (now - otp_store[email]["last_sent"]).total_seconds() < 60:
        return

    otp = random.randint(100000, 999999)
    otp_store[email] = {
        "otp": otp,
        "expires": now + timedelta(minutes=10),
        "last_sent": now
    }

    html = f"""
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
    """

    send_email_api(
        to_email=email,
        subject="Your Certificate Verification Code",
        html_body=html
    )

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
    now = datetime.utcnow()

    if not gmail:
        return render_template(
            "verify_otp.html",
            error="Session expired. Please try again."
        )

    otp_entry = otp_store.get(gmail)

    if otp_entry:
        if now > otp_entry["expires"]:
            otp_store.pop(gmail, None)
            session.pop("pending_gmail", None)
            return render_template(
                "verify_otp.html",
                gmail=gmail,
                error="OTP expired. Please request a new one."
            )

        if str(otp_entry["otp"]) == entered_otp:
            certificates = get_candidate_certificates(gmail)
            otp_store.pop(gmail, None)
            session.pop("pending_gmail", None)
            return render_template(
                "index.html",
                certificates=certificates,
                status="success",
                gmail=gmail
            )

    return render_template(
        "verify_otp.html",
        gmail=gmail,
        error="Invalid OTP. Please try again."
    )

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

@app.route("/upload-certificate", methods=["POST"])
def upload_certificate():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

    gmail = request.form.get("gmail")
    name = request.form.get("name")
    course = request.form.get("course")
    title = request.form.get("title")
    file = request.files.get("certificate")

    if not all([gmail, name, course, title, file]):
        return "All fields required", 400

    encoded = base64.b64encode(file.read()).decode("utf-8")

    db = get_db()
    db.execute("""
        INSERT OR REPLACE INTO candidates
        (gmail, name, course, title, certificate_name, certificate_data)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (gmail, name, course, title, file.filename, encoded))
    db.commit()

    return redirect(url_for("dashboard"))

@app.route("/download-certificate/<gmail>/<title>")
def download_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if not cert:
        return "Certificate not found", 404

    name, data = cert
    decoded = base64.b64decode(data.encode("utf-8"))
    return send_file(io.BytesIO(decoded), as_attachment=True, download_name=name)

@app.route("/view-certificate/<gmail>/<title>")
def view_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if cert:
        name, encoded = cert
        pdf = base64.b64decode(encoded.encode("utf-8"))
        return Response(pdf, mimetype="application/pdf")
    return "Certificate not found", 404

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
