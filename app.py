"""
Secure Login System
-------------------
Features:
  * User registration + login with bcrypt-hashed passwords
  * Input validation + parameterized SQL queries (SQL injection protection)
  * Session management with secure cookies, timeout and logout
  * CSRF protection on every POST form
  * Brute-force protection (temporary account lockout)
  * Optional Two-Factor Authentication (TOTP - Google Authenticator etc.)
"""
import base64
import io
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import pyotp
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

try:
    import qrcode
except ImportError:  # QR is optional; secret key is shown as fallback
    qrcode = None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
SECRET_PATH = os.path.join(BASE_DIR, ".secret_key")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


def load_secret_key():
    """Use env var if set, else generate once and persist locally."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as f:
            f.write(secrets.token_hex(32))
    with open(SECRET_PATH) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,      # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",     # basic CSRF defence
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",  # set HTTPS=1 in production
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # session timeout
)


# --------------------------------------------------------------------------
# Database helpers (all queries are parameterized -> no SQL injection)
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL
            )
            """
        )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def validate_registration(username, email, password, confirm):
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username 3-30 characters ka hona chahiye (sirf letters, numbers, underscore).")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors.append("Valid email address daalo.")
    if len(password) < 8:
        errors.append("Password kam se kam 8 characters ka hona chahiye.")
    if len(password) > 72:
        errors.append("Password 72 characters se zyada nahi ho sakta (bcrypt limit).")
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
        errors.append("Password me ek uppercase, ek lowercase aur ek number hona chahiye.")
    if password != confirm:
        errors.append("Dono passwords match nahi karte.")
    return errors


# --------------------------------------------------------------------------
# CSRF protection
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Pehle login karo.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()


def finish_login(user_id, username):
    """Create a fresh session (prevents session fixation)."""
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username
    csrf_token()


# A dummy hash so login takes similar time whether or not the user exists
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = validate_registration(username, email, password, confirm)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email)

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, pw_hash, datetime.utcnow().isoformat()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username ya email already registered hai.", "error")
            return render_template("register.html", username=username, email=email)

        flash("Account ban gaya! Ab login karo.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generic_error = "Username ya password galat hai."

        if not USERNAME_RE.fullmatch(username) or len(password) > 72:
            bcrypt.checkpw(b"x", DUMMY_HASH)
            flash(generic_error, "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            bcrypt.checkpw(password.encode("utf-8"), DUMMY_HASH)
            flash(generic_error, "error")
            return render_template("login.html")

        # Lockout check
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                mins = int((locked_until - datetime.utcnow()).total_seconds() // 60) + 1
                flash(f"Bahut zyada galat attempts. {mins} minute baad try karo.", "error")
                return render_template("login.html")

        if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()
            if user["totp_enabled"]:
                session.clear()
                session["pending_2fa_user"] = user["id"]
                session["pending_2fa_name"] = user["username"]
                session["pending_2fa_tries"] = 0
                csrf_token()
                return redirect(url_for("verify_2fa"))
            finish_login(user["id"], user["username"])
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        # Wrong password -> count attempt
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            attempts = 0
        db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, user["id"]),
        )
        db.commit()
        flash(generic_error, "error")
    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        session["pending_2fa_tries"] = session.get("pending_2fa_tries", 0) + 1
        if session["pending_2fa_tries"] > 5:
            session.clear()
            flash("Bahut zyada galat codes. Dobara login karo.", "error")
            return redirect(url_for("login"))

        user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and re.fullmatch(r"\d{6}", code) and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            finish_login(user["id"], user["username"])
            flash("2FA verified. Login successful!", "success")
            return redirect(url_for("dashboard"))
        flash("Galat code. Dobara try karo.", "error")
    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user()
    if user["totp_enabled"]:
        flash("2FA already enabled hai.", "info")
        return redirect(url_for("dashboard"))

    db = get_db()
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        secret = session.get("totp_setup_secret")
        if secret and re.fullmatch(r"\d{6}", code) and pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            db.commit()
            session.pop("totp_setup_secret", None)
            flash("Two-Factor Authentication enable ho gaya!", "success")
            return redirect(url_for("dashboard"))
        flash("Galat code. Authenticator app ka current code daalo.", "error")

    secret = session.get("totp_setup_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["totp_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureLoginSystem")

    qr_data = None
    if qrcode:
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format="PNG")
        qr_data = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", secret=secret, qr_data=qr_data)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = current_user()
    password = request.form.get("password", "")
    if len(password) <= 72 and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        db = get_db()
        db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (user["id"],))
        db.commit()
        flash("2FA disable kar diya gaya.", "success")
    else:
        flash("Password galat hai. 2FA disable nahi hua.", "error")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Aap logout ho gaye.", "success")
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=e.description), 400


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page nahi mila."), 404


init_db()

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
