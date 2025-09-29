import os
import sqlite3
import base64
import random
import io
import time
from datetime import datetime, timedelta
from threading import Thread
from flask import Flask, request, render_template, redirect, url_for, session, send_file, Response, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------
load_dotenv()

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "Gopalnamdev@gmail.comGopal0369Namdev24012004")

# ---------------- ADMIN ----------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "recruitplusindia")
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "Satendra@369N"))

# ---------------- MAIL SETUP ----------------
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", 465))
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_USERNAME")
mail = Mail(app)

# ---------------- DATABASE PATH ----------------
DB_PATH = os.path.join(os.path.dirname(__file__), "candidates.db")

# ---------------- OTP STORE ----------------
# {email: {"otp": int, "expires": datetime, "last_sent": datetime}}
otp_store = {}

# ---------------- DATABASE FUNCTIONS WITH CONNECTION POOLING ----------------
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
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
                gmail TEXT NOT NULL,
                name TEXT NOT NULL,
                course TEXT NOT NULL,
                title TEXT NOT NULL,
                certificate_name TEXT NOT NULL,
                certificate_data TEXT NOT NULL,
                PRIMARY KEY (gmail, title)
            )
        ''')
        db.commit()
        print("✅ Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"⚠️ Database error: {e}")

def get_all_candidates():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT gmail, name, course, title, certificate_name, certificate_data FROM candidates")
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Error fetching candidates: {e}")
        return []

def get_candidate_certificates(gmail: str):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT title, name, course FROM candidates WHERE gmail = ?", (gmail,))
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Error fetching certificates: {e}")
        return []

def get_certificate_data(gmail: str, title: str):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT certificate_name, certificate_data FROM candidates WHERE gmail=? AND title=?", (gmail, title))
        return cursor.fetchone()
    except sqlite3.Error as e:
        print(f"Error fetching certificate data: {e}")
        return None

# ---------------- ASYNC EMAIL ----------------
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Error sending email: {e}")

# ---------------- SEND OTP WITH THROTTLE ----------------
def send_otp(email: str):
    now = datetime.utcnow()
    if email in otp_store and "last_sent" in otp_store[email]:
        if (now - otp_store[email]["last_sent"]).total_seconds() < 60:
            print(f"OTP recently sent to {email}, skipping re-send.")
            return

    otp = random.randint(100000, 999999)
    expires_at = now + timedelta(minutes=10)
    otp_store[email] = {"otp": otp, "expires": expires_at, "last_sent": now}

    html_body = f"""
    <html>
    <body style="font-family:'Poppins',sans-serif;background:#f0f4ff;padding:20px;text-align:center;">
        <div style="max-width:600px;margin:auto;background:#fff;padding:30px;border-radius:12px;box-shadow:0 8px 20px rgba(0,0,0,0.1);">
            <h2 style="color:#0072ff;">Certificate Verification Code</h2>
            <p>Hello,</p>
            <p>Use the following code to verify your email and download your certificate:</p>
            <div style="font-size:28px;font-weight:bold;color:#00c6ff;margin:20px 0;letter-spacing:4px;">{otp}</div>
            <p>This code is valid for 10 minutes.</p>
            <div style="margin-top:30px;font-size:12px;color:#888;">&copy; 2025 RecruitPlus India</div>
        </div>
    </body>
    </html>
    """
    msg = Message(subject="Your Certificate Verification Code", recipients=[email], html=html_body)
    Thread(target=send_async_email, args=(app, msg)).start()

# ---------------- OTP CLEANUP THREAD ----------------
def cleanup_expired_otps(interval_seconds: int = 60):
    while True:
        now = datetime.utcnow()
        expired = [email for email, data in otp_store.items() if now > data["expires"]]
        for email in expired:
            otp_store.pop(email)
        time.sleep(interval_seconds)

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
    else:
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
            return render_template('verify_otp.html', gmail=gmail, error="OTP expired. Please request a new one.")
        elif str(otp_entry["otp"]) == entered_otp:
            certificates = get_candidate_certificates(gmail)
            otp_store.pop(gmail)
            session.pop('pending_gmail')
            return render_template('index.html', certificates=certificates, status='success', gmail=gmail)

    return render_template('verify_otp.html', gmail=gmail, error="Invalid OTP. Please try again.")

# ---------------- ADMIN ROUTES ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if "admin_logged_in" not in session:
        return redirect(url_for('login'))
    candidates = get_all_candidates()
    return render_template('dashboard.html', candidates=candidates)

@app.route('/upload-certificate', methods=['POST'])
def upload_certificate():
    if "admin_logged_in" not in session:
        return redirect(url_for('login'))

    gmail = request.form.get('gmail')
    name = request.form.get('name')
    course = request.form.get('course')
    title = request.form.get('title')
    file = request.files.get('certificate')

    if not gmail or not name or not course or not title or not file:
        return "Error: All fields are required!", 400

    encoded_data = base64.b64encode(file.read()).decode('utf-8')

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''INSERT OR REPLACE INTO candidates 
            (gmail, name, course, title, certificate_name, certificate_data) 
            VALUES (?, ?, ?, ?, ?, ?)''',
                       (gmail, name, course, title, file.filename, encoded_data))
        db.commit()
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

    return redirect(url_for('dashboard'))

@app.route('/download-certificate/<gmail>/<title>')
def download_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if not cert:
        return "Certificate not found", 404
    name, data = cert
    decoded = base64.b64decode(data.encode('utf-8'))
    return send_file(io.BytesIO(decoded), as_attachment=True, download_name=name)

@app.route('/delete-candidate/<gmail>')
def delete_candidate(gmail):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM candidates WHERE gmail = ?", (gmail,))
        db.commit()
    except sqlite3.Error as e:
        print(f"Error deleting candidate: {e}")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route("/view-certificate/<gmail>/<title>")
def view_certificate(gmail, title):
    cert = get_certificate_data(gmail, title)
    if cert and cert[1]:
        name, encoded_data = cert
        pdf_data = base64.b64decode(encoded_data.encode("utf-8"))
        return Response(pdf_data, mimetype="application/pdf")
    return "Certificate not found", 404

# ---------------- RUN ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
