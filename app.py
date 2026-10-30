import os
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, make_response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_SECRET = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-secret")
DATABASE = os.environ.get("DATABASE_PATH", "zero_trust.db")
DEVICE_COOKIE = "zt_device"
OTP_LIFETIME_SECONDS = 300

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee',
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, token_hash),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
        """)
        if not con.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone():
            con.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", generate_password_hash("Admin@12345"), "admin", now())
            )
        if not con.execute("SELECT id FROM users WHERE username = ?", ("employee",)).fetchone():
            con.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("employee", generate_password_hash("Employee@12345"), "employee", now())
            )


def log_event(username, action, resource, decision, reason):
    with db() as con:
        con.execute("""
            INSERT INTO access_logs(username, action, resource, decision, reason, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            username, action, resource, decision, reason,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            now()
        ))


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "current_user": session.get("username")}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description="Invalid or missing CSRF token.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_device_is_trusted():
    token = request.cookies.get(DEVICE_COOKIE)
    user_id = session.get("user_id")
    if not token or not user_id:
        return False
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as con:
        row = con.execute(
            "SELECT id FROM devices WHERE user_id = ? AND token_hash = ?",
            (user_id, token_hash)
        ).fetchone()
    return row is not None


def trusted_device_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_device_is_trusted():
            log_event(session.get("username"), "RESOURCE_ACCESS", request.path,
                      "DENIED", "Device is not registered as trusted")
            flash("Access denied: this device is not trusted. Sign in and trust this device.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                log_event(session.get("username"), "RESOURCE_ACCESS", request.path,
                          "DENIED", "Insufficient role permissions")
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 30:
            flash("Username must be 3–30 characters.", "danger")
        elif len(password) < 10:
            flash("Password must contain at least 10 characters.", "danger")
        else:
            try:
                with db() as con:
                    con.execute(
                        "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, 'employee', ?)",
                        (username, generate_password_hash(password), now())
                    )
                flash("Account created. Sign in to continue.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            log_event(username or "unknown", "LOGIN", None, "DENIED", "Invalid username or password")
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        # Educational MFA simulation: the OTP is printed to the server terminal.
        otp = f"{secrets.randbelow(1000000):06d}"
        session.clear()
        session["pending_user_id"] = user["id"]
        session["pending_username"] = user["username"]
        session["pending_role"] = user["role"]
        session["otp_hash"] = hashlib.sha256(otp.encode()).hexdigest()
        session["otp_created"] = datetime.now(timezone.utc).timestamp()
        session["_csrf"] = secrets.token_urlsafe(32)
        print(f"\n[DEMO MFA] One-time code for {username}: {otp}\n")
        return redirect(url_for("verify_otp"))
    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("pending_user_id"):
        return redirect(url_for("login"))
    if request.method == "POST":
        supplied = request.form.get("otp", "").strip()
        created = session.get("otp_created", 0)
        valid_time = datetime.now(timezone.utc).timestamp() - created <= OTP_LIFETIME_SECONDS
        supplied_hash = hashlib.sha256(supplied.encode()).hexdigest()
        if valid_time and hmac.compare_digest(supplied_hash, session.get("otp_hash", "")):
            user_id = session["pending_user_id"]
            username = session["pending_username"]
            role = session["pending_role"]
            csrf = session.get("_csrf", secrets.token_urlsafe(32))
            session.clear()
            session.update(user_id=user_id, username=username, role=role, _csrf=csrf)
            log_event(username, "LOGIN_MFA", None, "ALLOWED", "Password and demo OTP verified")
            response = make_response(redirect(url_for("dashboard")))
            if request.form.get("trust_device") == "yes":
                token = secrets.token_urlsafe(48)
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                with db() as con:
                    con.execute(
                        "INSERT OR IGNORE INTO devices(user_id, token_hash, label, created_at) VALUES (?, ?, ?, ?)",
                        (user_id, token_hash, "Browser registered at login", now())
                    )
                response.set_cookie(
                    DEVICE_COOKIE, token, max_age=60 * 60 * 24 * 30,
                    httponly=True, secure=app.config["SESSION_COOKIE_SECURE"], samesite="Lax"
                )
            flash("Identity verified. You are signed in.", "success")
            return response

        log_event(session.get("pending_username"), "LOGIN_MFA", None, "DENIED",
                  "Invalid or expired one-time code")
        flash("Incorrect or expired code. Sign in again to request a new code.", "danger")
        session.clear()
        return redirect(url_for("login"))
    return render_template("verify_otp.html")


@app.route("/dashboard")
@login_required
def dashboard():
    trusted = current_device_is_trusted()
    resources = [
        {"name": "General Company Documents", "path": "documents", "roles": "Employee and Admin"},
        {"name": "Payroll Records", "path": "payroll", "roles": "Admin only"},
        {"name": "Security Reports", "path": "security", "roles": "Admin only"},
    ]
    return render_template("dashboard.html", trusted=trusted, resources=resources)


@app.route("/resource/<resource_name>")
@login_required
@trusted_device_required
def resource(resource_name):
    policies = {
        "documents": {"roles": ["employee", "admin"], "title": "General Company Documents",
                      "content": "Example internal documents. In a real deployment, retrieve protected files only after policy checks."},
        "payroll": {"roles": ["admin"], "title": "Payroll Records",
                    "content": "Confidential payroll information (demo placeholder)."},
        "security": {"roles": ["admin"], "title": "Security Reports",
                     "content": "Security monitoring reports (demo placeholder)."},
    }
    policy = policies.get(resource_name)
    if not policy:
        abort(404)
    if session.get("role") not in policy["roles"]:
        log_event(session.get("username"), "RESOURCE_ACCESS", resource_name,
                  "DENIED", "Role not authorized by resource policy")
        abort(403)
    log_event(session.get("username"), "RESOURCE_ACCESS", resource_name,
              "ALLOWED", "Trusted device and role policy verified")
    return render_template("resource.html", resource=policy)


@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    with db() as con:
        logs = con.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 100").fetchall()
        users = con.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    return render_template("admin.html", logs=logs, users=users)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username")
    log_event(username, "LOGOUT", None, "ALLOWED", "User signed out")
    session.clear()
    response = make_response(redirect(url_for("index")))
    response.delete_cookie(DEVICE_COOKIE)
    flash("You have signed out.", "success")
    return response


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="Your account does not have permission to access this resource."), 403


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request.")), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The requested page or resource was not found."), 404


if __name__ == "__main__":
    init_db()
    print("Zero Trust demo running at http://127.0.0.1:5000")
    print("Demo accounts: admin / Admin@12345 | employee / Employee@12345")
    print("The demo MFA code is printed in this terminal after password verification.")
    app.run(host="127.0.0.1", port=5000, debug=True)
