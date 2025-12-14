import os
import sqlite3
import base64
import random
import io
import time
import ssl
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, request, render_template, redirect,
    url_for, session, send_file, Response, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

# ============================================================
# LOAD ENV
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
    os.environ.get("ADMIN_PASSWORD", "Satendra@369N")
)

# ============================================================
# DATABASE
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")

# ============================================================
# OTP STORE (in-memory, fast)
# ============================================================
otp_store = {}

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
    try:
        return get_db().execute("""
            SELECT gmail, name, course, title,
                   certificate_name, certificate_data
            FROM candidates
        """).fetchall()
    except Exception as e:
        print("❌ DB ERROR:", e)
        return []

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
# SMTP (FAST + SAFE + RENDER-PROOF)
# ============================================================
def send_email_smtp(to_email, subject, html_content):
    """
    Guaranteed behaviour:
    - Fails fast (no worker timeout)
    - Uses STARTTLS (Hostinger-safe)
    - Explicit TLS context
    """

    msg = EmailMessage()
    msg["From"] = f"Recruit Plus India <{os.environ['SMTP_USER']}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("Please view this email in HTML format.")
    msg.add_alternative(html_content, subtype="html")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with smtplib.SMTP(
            os.environ["SMTP_HOST"],
            int(os.environ.get("SMTP_PORT", 587)),
            timeout=12      # 🔥 critical: prevents gunicorn timeout
        ) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(
                os.environ["SMTP_USER"],
                os.environ["SMTP_PASS"]
            )
            server.send_message(msg)

        print(f"✅ OTP EMAIL SENT → {to_email}")

    except Exception as e:
        # Never crash request
        print("❌ SMTP EMAIL ERROR:", repr(e))

# ============================================================
# OTP LOGIC (SYNCHRONOUS – RENDER SAFE)
# ============================================================
def send_otp(email):
    now = datetime.now(timezone.utc)

    # rate limit
    if email in otp_store:
        if (now - otp_store[email]["last_sent"]).total_seconds() < 60:
            print(f"⏳ OTP rate-limited for {email}")
            return

    otp = random.randint(100000, 999999)
    otp_store[email] = {
        "otp": otp,
        "expires": now + timedelta(minutes=10),
        "last_sent": now
    }

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#f3f4f6;font-family:Segoe UI,Roboto,Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="padding:30px;">
        <tr>
          <td align="center">
            <table width="600" style="background:#ffffff;border-radius:12px;padding:30px;
                   box-shadow:0 10px 25px rgba(0,0,0,0.1);">
              <tr>
                <td align="center">
                  <h2 style="color:#2563eb;">Certificate Verification Code</h2>
                  <p>Your OTP is:</p>
                  <div style="font-size:30px;font-weight:bold;letter-spacing:6px;color:#1d4ed8;">
                    {otp}
                  </div>
                  <p>Valid for 10 minutes.</p>
                  <hr>
                  <p style="font-size:12px;color:#6b7280;">
                    © {datetime.now().year} Recruit Plus India
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

    # 🔥 MUST be synchronous on Render
    send_email_smtp(
        email,
        "Your Certificate Verification Code",
        html_content
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
    certs = get_candidate_certificates(gmail)

    if certs:
        send_otp(gmail)
        session["pending_gmail"] = gmail
        return render_template("verify_otp.html", gmail=gmail)

    return render_template("index.html", status="error", gmail=gmail)

@app.route("/verify-otp", methods=["POST"])
def verify_otp_route():
    gmail = session.get("pending_gmail")
    entered = request.form.get("otp")
    entry = otp_store.get(gmail)

    if entry:
        if datetime.now(timezone.utc) > entry["expires"]:
            otp_store.pop(gmail, None)
            return render_template("verify_otp.html", gmail=gmail, error="OTP expired.")

        if str(entry["otp"]) == entered:
            certs = get_candidate_certificates(gmail)
            otp_store.pop(gmail, None)
            session.pop("pending_gmail", None)
            return render_template(
                "index.html",
                certificates=certs,
                status="success",
                gmail=gmail
            )

    return render_template("verify_otp.html", gmail=gmail, error="Invalid OTP.")

# ============================================================
# ADMIN
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME
            and check_password_hash(
                ADMIN_PASSWORD_HASH,
                request.form.get("password")
            )
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "admin_logged_in" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", candidates=get_all_candidates())

@app.route("/delete-candidate/<gmail>")
def delete_candidate(gmail):
    if "admin_logged_in" not in session:
        return redirect(url_for("login"))
    db = get_db()
    db.execute("DELETE FROM candidates WHERE gmail=?", (gmail,))
    db.commit()
    return redirect(url_for("dashboard"))

@app.route("/upload-certificate", methods=["POST"])
def upload_certificate():
    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    gmail = request.form.get("gmail")
    name = request.form.get("name")
    course = request.form.get("course")
    title = request.form.get("title")
    file = request.files.get("certificate")

    encoded = base64.b64encode(file.read()).decode()
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO candidates VALUES (?, ?, ?, ?, ?, ?)",
        (gmail, name, course, title, file.filename, encoded)
    )
    db.commit()
    return redirect(url_for("dashboard"))

@app.route("/download-certificate/<gmail>/<title>")
def download_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if not cert:
        return "Certificate not found", 404
    name, data = cert
    return send_file(
        io.BytesIO(base64.b64decode(data)),
        as_attachment=True,
        download_name=name
    )

@app.route("/view-certificate/<gmail>/<title>")
def view_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if cert:
        _, data = cert
        return Response(
            base64.b64decode(data),
            mimetype="application/pdf"
        )
    return "Certificate not found", 404

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ============================================================
# RUN (LOCAL ONLY)
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
