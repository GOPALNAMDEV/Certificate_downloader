import os
import sqlite3
import base64
import random
import io
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from threading import Thread
from flask import Flask, request, render_template, redirect, url_for, session, send_file, Response, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------
load_dotenv()

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")

# ---------------- ADMIN ----------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "recruitplusindia")
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASSWORD", "Satendra@369N")
)

# ---------------- SMTP2GO CONFIG ----------------
SMTP_HOST = "mail.smtp2go.com"
SMTP_PORT = 587
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")   # recruitplusindia.in
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")     # no-reply@recruitplusindia.in

# ---------------- DATABASE PATH ----------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "candidates.db")

# ---------------- OTP STORE ----------------
otp_store = {}  # {email: {"otp": int, "expires": datetime, "last_sent": datetime}}

# ---------------- DATABASE FUNCTIONS ----------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS candidates (
                    gmail TEXT NOT NULL,
                    name TEXT NOT NULL,
                    course TEXT NOT NULL,
                    title TEXT NOT NULL,
                    certificate_name TEXT NOT NULL,
                    certificate_data TEXT NOT NULL,
                    PRIMARY KEY (gmail, title)
                  )''')
    db.commit()

def get_all_candidates():
    db = get_db()
    try:
        return db.execute(
            "SELECT gmail, name, course, title, certificate_name, certificate_data FROM candidates"
        ).fetchall()
    except sqlite3.OperationalError as e:
        print("DB Error:", e)
        return []

def get_candidate_certificates(gmail):
    db = get_db()
    return db.execute(
        "SELECT title, name, course FROM candidates WHERE gmail=?", (gmail,)
    ).fetchall()

def get_certificate_data(gmail, title):
    db = get_db()
    return db.execute(
        "SELECT certificate_name, certificate_data FROM candidates WHERE gmail=? AND title=?",
        (gmail, title)
    ).fetchone()

# ---------------- ASYNC SMTP EMAIL ----------------
def send_async_email(msg):
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("SMTP2GO error:", e)

def send_otp(email):
    now = datetime.utcnow()

    if email in otp_store and "last_sent" in otp_store[email]:
        if (now - otp_store[email]["last_sent"]).total_seconds() < 60:
            return

    otp = random.randint(100000, 999999)
    expires_at = now + timedelta(minutes=10)
    otp_store[email] = {"otp": otp, "expires": expires_at, "last_sent": now}

    html_content = f"""
    <html>
    <body style="font-family:'Poppins',sans-serif;background:#f0f4ff;padding:20px;text-align:center;">
        <div style="max-width:600px;margin:auto;background:#fff;padding:30px;border-radius:12px;
        box-shadow:0 8px 20px rgba(0,0,0,0.1);">
            <h2 style="color:#0072ff;">Certificate Verification Code</h2>
            <p>Use the following code to verify your email:</p>
            <div style="font-size:28px;font-weight:bold;color:#00c6ff;margin:20px 0;">
                {otp}
            </div>
            <p>This code is valid for 10 minutes.</p>
            <div style="margin-top:30px;font-size:12px;color:#888;">
                &copy; 2025 RecruitPlus India
            </div>
        </div>
    </body>
    </html>
    """

    msg = EmailMessage()
    msg["From"] = f"RecruitPlus <{SENDER_EMAIL}>"
    msg["To"] = email
    msg["Subject"] = "Your Certificate Verification Code"
    msg.set_content("Your email client does not support HTML.")
    msg.add_alternative(html_content, subtype="html")

    Thread(target=send_async_email, args=(msg,), daemon=True).start()

# ---------------- OTP CLEANUP ----------------
def cleanup_expired_otps(interval=60):
    while True:
        now = datetime.utcnow()
        expired = [e for e, d in otp_store.items() if now > d["expires"]]
        for e in expired:
            otp_store.pop(e)
        time.sleep(interval)

Thread(target=cleanup_expired_otps, daemon=True).start()

# ---------------- INIT DB ----------------
with app.app_context():
    init_db()

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template('index.html', certificates=None, status='info')

@app.route('/check-certificate', methods=['POST'])
def check_certificate():
    gmail = request.form.get('gmail')
    certificates = get_candidate_certificates(gmail)
    if certificates:
        send_otp(gmail)
        session['pending_gmail'] = gmail
        return render_template('verify_otp.html', gmail=gmail)
    return render_template('index.html', status='error', gmail=gmail)

@app.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    gmail = session.get('pending_gmail')
    entered_otp = request.form.get('otp')
    now = datetime.utcnow()

    otp_entry = otp_store.get(gmail)
    if otp_entry:
        if now > otp_entry["expires"]:
            otp_store.pop(gmail)
            return render_template('verify_otp.html', gmail=gmail, error="OTP expired.")
        elif str(otp_entry["otp"]) == entered_otp:
            certificates = get_candidate_certificates(gmail)
            otp_store.pop(gmail)
            session.pop('pending_gmail')
            return render_template('index.html', certificates=certificates, status='success', gmail=gmail)

    return render_template('verify_otp.html', gmail=gmail, error="Invalid OTP")

# ---------------- ADMIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USERNAME and \
           check_password_hash(ADMIN_PASSWORD_HASH, request.form['password']):
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if "admin_logged_in" not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', candidates=get_all_candidates())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=True)
