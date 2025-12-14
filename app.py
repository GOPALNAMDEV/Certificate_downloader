import os, sqlite3, base64, random, io
from datetime import datetime, timedelta, timezone
from flask import Flask, request, render_template, redirect, url_for, session, send_file, Response, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests

# ---------------- LOAD ENV ----------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin123"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "candidates.db")

MAIL_SERVICE_URL = os.getenv("MAIL_SERVICE_URL")

otp_store = {}

# ---------------- DB ----------------
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
        gmail TEXT,
        name TEXT,
        course TEXT,
        title TEXT,
        certificate_name TEXT,
        certificate_data TEXT,
        PRIMARY KEY (gmail, title)
    )
    """)
    db.commit()

with app.app_context():
    init_db()

# ---------------- OTP ----------------
def send_otp(email):
    now = datetime.now(timezone.utc)

    if email in otp_store and (now - otp_store[email]["sent"]).total_seconds() < 60:
        return

    otp = random.randint(100000, 999999)
    otp_store[email] = {
        "otp": otp,
        "expires": now + timedelta(minutes=10),
        "sent": now
    }

    requests.post(
        MAIL_SERVICE_URL,
        json={"to": email, "otp": otp},
        timeout=5
    )

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check-certificate", methods=["POST"])
def check_certificate():
    gmail = request.form.get("gmail")
    certs = get_db().execute(
        "SELECT title, name, course FROM candidates WHERE gmail=?", (gmail,)
    ).fetchall()

    if certs:
        send_otp(gmail)
        session["pending"] = gmail
        return render_template("verify_otp.html", gmail=gmail)

    return render_template("index.html", error="No certificates found")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    gmail = session.get("pending")
    otp = request.form.get("otp")

    data = otp_store.get(gmail)
    if not data:
        return "OTP expired"

    if datetime.now(timezone.utc) > data["expires"]:
        return "OTP expired"

    if str(data["otp"]) == otp:
        certs = get_db().execute(
            "SELECT title, name, course FROM candidates WHERE gmail=?", (gmail,)
        ).fetchall()
        otp_store.pop(gmail)
        return render_template("index.html", certificates=certs)

    return "Invalid OTP"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, request.form["password"])
        ):
            session["admin"] = True
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect("/login")
    rows = get_db().execute("SELECT * FROM candidates").fetchall()
    return render_template("dashboard.html", candidates=rows)

@app.route("/upload-certificate", methods=["POST"])
def upload_certificate():
    if not session.get("admin"):
        return redirect("/login")

    f = request.files["certificate"]
    encoded = base64.b64encode(f.read()).decode()

    get_db().execute(
        "INSERT OR REPLACE INTO candidates VALUES (?, ?, ?, ?, ?, ?)",
        (
            request.form["gmail"],
            request.form["name"],
            request.form["course"],
            request.form["title"],
            f.filename,
            encoded,
        ),
    )
    get_db().commit()
    return redirect("/dashboard")

@app.route("/download/<gmail>/<title>")
def download(gmail, title):
    row = get_db().execute(
        "SELECT certificate_name, certificate_data FROM candidates WHERE gmail=? AND title=?",
        (gmail, title)
    ).fetchone()
    return send_file(
        io.BytesIO(base64.b64decode(row["certificate_data"])),
        as_attachment=True,
        download_name=row["certificate_name"]
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
