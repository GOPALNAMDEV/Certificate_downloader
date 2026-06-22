import os
import sqlite3
import uuid
import random
import time

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    send_from_directory
)

from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from dotenv import load_dotenv

# ---------------- LOAD ENV ----------------
load_dotenv()

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "recruitplus-secret-key"
)

UPLOAD_FOLDER = "candidates"
DB_NAME = "candidates.db"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- ADMIN ----------------
ADMIN_USERNAME = os.environ.get(
    "ADMIN_USERNAME",
    "recruitplusindia"
)

ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get(
        "ADMIN_PASSWORD",
        "Satendra@369N"
    )
)

# ---------------- MAIL SETUP ----------------
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 465))
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True

mail = Mail(app)

# ---------------- OTP STORAGE ----------------
otp_store = {}
OTP_EXPIRY_SECONDS = 600

# ---------------- CREATE FOLDER ----------------
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- DATABASE INIT ----------------
def init_db():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                gmail TEXT NOT NULL,
                name TEXT NOT NULL,
                course TEXT NOT NULL,
                certificate_path TEXT NOT NULL,
                title TEXT NOT NULL,
                PRIMARY KEY (gmail, title)
            )
            """)

            conn.commit()

    except sqlite3.Error as e:
        print("Database Init Error:", e)

init_db()

# ---------------- DATABASE FUNCTIONS ----------------
def get_all_candidates():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute("""
            SELECT gmail, name, course, title, certificate_path
            FROM candidates
            ORDER BY gmail
            """)

            return cursor.fetchall()

    except sqlite3.Error as e:
        print("Error fetching candidates:", e)
        return []

def get_candidate_certificates(gmail):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute("""
            SELECT certificate_path, name, course, title
            FROM candidates
            WHERE gmail=?
            """, (gmail,))

            return cursor.fetchall()

    except sqlite3.Error as e:
        print("Error fetching certificates:", e)
        return []

def allowed_file(filename):
    allowed = {"pdf", "jpg", "jpeg", "png"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed

# ---------------- EMAIL OTP ----------------
def send_otp(email):
    otp = str(random.randint(100000, 999999))

    otp_store[email] = {
        "otp": otp,
        "created": time.time()
    }

    html_body = f"""
    <html>
    <body>
        <h2>Certificate Verification Code</h2>
        <p>Your OTP is:</p>
        <h1>{otp}</h1>
        <p>Valid for 10 minutes.</p>
    </body>
    </html>
    """

    try:
        msg = Message(
            subject="Certificate Verification Code",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email],
            html=html_body
        )

        mail.send(msg)

    except Exception as e:
        print("Mail Error:", e)

# ---------------- USER ROUTES ----------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        certificates=None,
        status="info"
    )

@app.route("/check-certificate", methods=["POST"])
def check_certificate():

    gmail = request.form.get("gmail", "").strip()

    certificates = get_candidate_certificates(gmail)

    if certificates:
        send_otp(gmail)
        session["pending_gmail"] = gmail

        return render_template(
            "verify_otp.html",
            gmail=gmail
        )

    return render_template(
        "index.html",
        status="error",
        gmail=gmail
    )

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    gmail = session.get("pending_gmail")
    entered_otp = request.form.get("otp", "").strip()

    if gmail not in otp_store:
        return render_template(
            "verify_otp.html",
            gmail=gmail,
            error="OTP expired."
        )

    otp_data = otp_store[gmail]

    if time.time() - otp_data["created"] > OTP_EXPIRY_SECONDS:
        otp_store.pop(gmail, None)

        return render_template(
            "verify_otp.html",
            gmail=gmail,
            error="OTP expired."
        )

    if otp_data["otp"] == entered_otp:

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
        error="Invalid OTP"
    )

# ---------------- ADMIN LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if (
            username == ADMIN_USERNAME
            and check_password_hash(
                ADMIN_PASSWORD_HASH,
                password
            )
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid credentials"
        )

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():

    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        candidates=get_all_candidates()
    )

@app.route("/upload-certificate", methods=["POST"])
def upload_certificate():

    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    gmail = request.form.get("gmail")
    name = request.form.get("name")
    course = request.form.get("course")
    title = request.form.get("title")
    file = request.files.get("certificate")

    if not all([gmail, name, course, title, file]):
        return "All fields are required", 400

    if not allowed_file(file.filename):
        return "Invalid file type", 400

    filename = f"{uuid.uuid4().hex}_{file.filename}"

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute("""
            INSERT OR REPLACE INTO candidates
            (gmail, name, course, certificate_path, title)
            VALUES (?, ?, ?, ?, ?)
            """, (
                gmail,
                name,
                course,
                filename,
                title
            ))

            conn.commit()

    except sqlite3.Error as e:
        return f"Database Error: {e}", 500

    return redirect(url_for("dashboard"))

@app.route("/view_certificate/<path:filename>")
def view_certificate(filename):

    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )

@app.route("/download-certificate/<path:filename>")
def download_certificate(filename):

    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )

@app.route("/delete-candidate/<gmail>")
def delete_candidate(gmail):

    if "admin_logged_in" not in session:
        return redirect(url_for("login"))

    try:
        certificates = get_candidate_certificates(gmail)

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            cursor.execute(
                "DELETE FROM candidates WHERE gmail=?",
                (gmail,)
            )

            conn.commit()

        for cert in certificates:
            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                cert[0]
            )

            if os.path.exists(filepath):
                os.remove(filepath)

    except Exception as e:
        print("Delete Error:", e)

    return redirect(url_for("dashboard"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )