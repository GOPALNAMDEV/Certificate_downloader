import os
import sqlite3
import base64
import random
import io
import time
from datetime import datetime, timedelta
from threading import Thread
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, send_file, Response, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

# ================= LOAD ENV =================
load_dotenv()

# ================= FLASK SETUP =================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "unsafe-dev-key")

# ================= ADMIN =================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "recruitplusindia")
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASSWORD", "admin")
)

# ================= SMTP CONFIG =================
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")

# ================= DATABASE =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")

# ================= OTP STORE (IN-MEMORY) =================
otp_store = {}  # {email: {otp, expires, last_sent}}

# ================= DATABASE HELPERS =================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
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

# ================= SMTP SENDER =================
def send_email_smtp(to_email, subject, html):
    try:
        msg = EmailMessage()
        msg["From"] = f"Recruit Plus India <{SMTP_USER}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content("Please view this email in HTML format.")
        msg.add_alternative(html, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        print(f"✅ OTP sent to {to_email}")

    except Exception as e:
        print("❌ SMTP ERROR:", e)

# ================= OTP LOGIC =================
def send_otp(email):
    now = datetime.utcnow()

    if email in otp_store:
        if (now - otp_store[email]["last_sent"]).seconds < 60:
            return

    otp = random.randint(100000, 999999)
    otp_store[email] = {
        "otp": otp,
        "expires": now + timedelta(minutes=10),
        "last_sent": now
    }

    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#f3f4f6;font-family:Arial;padding:30px;">
      <table width="100%" align="center">
        <tr><td align="center">
          <table width="600" style="background:#fff;padding:30px;border-radius:10px;">
            <tr><td align="center">
              <h2 style="color:#2563eb;">Certificate Verification Code</h2>
              <p>Your OTP is:</p>
              <div style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#1d4ed8;">
                {otp}
              </div>
              <p>Valid for 10 minutes</p>
              <hr>
              <p style="font-size:12px;color:#777;">
                © {datetime.now().year} Recruit Plus India
              </p>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """

    Thread(
        target=send_email_smtp,
        args=(email, "Your Certificate Verification Code", html),
        daemon=True
    ).start()

# ================= OTP CLEANER =================
def cleanup_otps():
    while True:
        now = datetime.utcnow()
        expired = [k for k, v in otp_store.items() if now > v["expires"]]
        for k in expired:
            otp_store.pop(k, None)
        time.sleep(60)

Thread(target=cleanup_otps, daemon=True).start()

# ================= INIT DB =================
with app.app_context():
    init_db()

# ================= ROUTES =================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check-certificate", methods=["POST"])
def check_certificate():
    gmail = request.form.get("gmail")
    db = get_db()
    certs = db.execute(
        "SELECT title, name, course FROM candidates WHERE gmail=?",
        (gmail,)
    ).fetchall()

    if certs:
        send_otp(gmail)
        session["pending_gmail"] = gmail
        return render_template("verify_otp.html", gmail=gmail)

    return render_template("index.html", error="No certificate found")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    gmail = session.get("pending_gmail")
    otp_input = request.form.get("otp")
    data = otp_store.get(gmail)

    if not data:
        return render_template("verify_otp.html", error="OTP expired")

    if datetime.utcnow() > data["expires"]:
        otp_store.pop(gmail, None)
        return render_template("verify_otp.html", error="OTP expired")

    if str(data["otp"]) != otp_input:
        return render_template("verify_otp.html", error="Invalid OTP")

    otp_store.pop(gmail, None)
    session.pop("pending_gmail", None)

    db = get_db()
    certs = db.execute(
        "SELECT title, name, course FROM candidates WHERE gmail=?",
        (gmail,)
    ).fetchall()

    return render_template("index.html", certificates=certs, success=True)

# ================= ADMIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, request.form["password"])
        ):
            session["admin"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("login"))
    db = get_db()
    candidates = db.execute("SELECT * FROM candidates").fetchall()
    return render_template("dashboard.html", candidates=candidates)

@app.route("/upload-certificate", methods=["POST"])
def upload_certificate():
    if not session.get("admin"):
        return redirect(url_for("login"))

    f = request.files["certificate"]
    encoded = base64.b64encode(f.read()).decode()
    db = get_db()
    db.execute("""
        INSERT OR REPLACE INTO candidates
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        request.form["gmail"],
        request.form["name"],
        request.form["course"],
        request.form["title"],
        f.filename,
        encoded
    ))
    db.commit()
    return redirect(url_for("dashboard"))

@app.route("/download-certificate/<gmail>/<title>")
def download_certificate(gmail, title):
    db = get_db()
    row = db.execute("""
        SELECT certificate_name, certificate_data
        FROM candidates WHERE gmail=? AND title=?
    """, (gmail, title)).fetchone()

    if not row:
        return "Not found", 404

    data = base64.b64decode(row["certificate_data"])
    return send_file(io.BytesIO(data), download_name=row["certificate_name"], as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
