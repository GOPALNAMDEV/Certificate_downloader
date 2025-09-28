import os
import sqlite3
import uuid
import random
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------
load_dotenv()  # Load .env variables

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

UPLOAD_FOLDER = 'candidates'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "recruitplusindia")
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "Satendra@369N"))

# ---------------- MAIL SETUP ----------------
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", 465))
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# ---------------- OTP STORAGE ----------------
otp_store = {}

# ---------------- CREATE UPLOAD DIR ----------------
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ---------------- DATABASE FUNCTIONS ----------------
def get_all_candidates():
    try:
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT gmail, name, course, title, certificate_path FROM candidates")
            return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Error fetching candidates: {e}")
        return []

def get_candidate_certificates(gmail):
    try:
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT certificate_path, name, course, title FROM candidates WHERE gmail = ?", (gmail,))
            return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Error fetching certificates: {e}")
        return []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'jpg', 'jpeg', 'png'}

# ---------------- EMAIL OTP FUNCTION ----------------
def send_otp(email):
    otp = random.randint(100000, 999999)
    otp_store[email] = otp

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
    msg = Message(
        subject="Your Certificate Verification Code",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email],
        html=html_body
    )
    mail.send(msg)

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
def verify_otp():
    gmail = session.get('pending_gmail')
    entered_otp = request.form.get('otp')
    if gmail and otp_store.get(gmail) and str(otp_store[gmail]) == entered_otp:
        certificates = get_candidate_certificates(gmail)
        otp_store.pop(gmail)
        session.pop('pending_gmail')
        return render_template('index.html', certificates=certificates, status='success', gmail=gmail)
    else:
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
    if not allowed_file(file.filename):
        return "Error: Invalid file type!", 400
    filename = f"{uuid.uuid4().hex}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    try:
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO candidates (gmail, name, course, certificate_path, title) VALUES (?, ?, ?, ?, ?)", 
                           (gmail, name, course, filename, title))
            conn.commit()
    except sqlite3.Error as e:
        return f"Database error: {e}", 500
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/download-certificate/<filename>')
def download_certificate(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/view_certificate/<path:filename>')
def view_certificate(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete-candidate/<gmail>')
def delete_candidate(gmail):
    try:
        certificates = get_candidate_certificates(gmail)
        with sqlite3.connect('candidates.db') as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM candidates WHERE gmail = ?", (gmail,))
            conn.commit()
        for cert in certificates:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], cert[0])
            if os.path.exists(file_path):
                os.remove(file_path)
    except sqlite3.Error as e:
        print(f"Error deleting candidate: {e}")
    return redirect(url_for('dashboard'))

# ---------------- RUN ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
