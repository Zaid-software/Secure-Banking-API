"""routes/auth.py — Login, Register, Logout, MFA"""

import re
from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from services import ApiClient
from functools import wraps

auth_bp = Blueprint("auth", __name__)


# ── Auth decorators ────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "jwt_token" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "jwt_token" not in session:
                return redirect(url_for("auth.login"))
            if session.get("role") not in roles:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard.index"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def sanitize_input(value: str, max_length: int = 200) -> str:
    """Basic input sanitization — strip whitespace, limit length."""
    if not value:
        return ""
    return value.strip()[:max_length]


# ── Routes ─────────────────────────────────────────────────────────────────

@auth_bp.route("/")
def index():
    if "jwt_token" in session:
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "jwt_token" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username  = sanitize_input(request.form.get("username", ""))
        password  = request.form.get("password", "")
        totp_code = sanitize_input(request.form.get("totp_code", ""), 6)

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("auth/login.html")

        api    = ApiClient()
        result = api.login(username, password, totp_code or None)

        if result.get("unauthorized"):
            return redirect(url_for("auth.login"))

        if not result.get("success"):
            flash(result.get("message", "Login failed."), "danger")
            return render_template("auth/login.html")

        data = result.get("data", {})

        # MFA required — show MFA input
        if data.get("mfaRequired"):
            session["pending_username"] = username
            session["pending_password"] = password
            return render_template("auth/mfa.html")

        # Store JWT and user info in session
        session["jwt_token"] = data.get("token")
        session["role"]      = data.get("role")
        session["username"]  = username
        session.permanent    = True

        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html")


@auth_bp.route("/login/mfa", methods=["POST"])
def login_mfa():
    username  = session.pop("pending_username", None)
    password  = session.pop("pending_password", None)
    totp_code = sanitize_input(request.form.get("totp_code", ""), 6)

    if not username or not password:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for("auth.login"))

    api    = ApiClient()
    result = api.login(username, password, totp_code)

    if not result.get("success"):
        flash(result.get("message", "Invalid MFA code."), "danger")
        return render_template("auth/mfa.html")

    data = result.get("data", {})
    session["jwt_token"] = data.get("token")
    session["role"]      = data.get("role")
    session["username"]  = username
    session.permanent    = True

    flash(f"Welcome back, {username}!", "success")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "jwt_token" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        email    = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Client-side validation (backend validates too)
        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("Invalid email address.")
        if len(password) < 12:
            errors.append("Password must be at least 12 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/register.html",
                                   username=username, email=email)

        api    = ApiClient()
        result = api.register(username, email, password)

        if not result.get("success"):
            flash(result.get("message", "Registration failed."), "danger")
            return render_template("auth/register.html",
                                   username=username, email=email)

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    api    = ApiClient()
    result = api.setup_mfa()

    if not result.get("success"):
        flash("Failed to set up MFA.", "danger")
        return redirect(url_for("dashboard.index"))

    data = result.get("data", {})
    return render_template("auth/mfa_setup.html",
                           qr_uri=data.get("qrCodeUri"),
                           manual_key=data.get("manualKey"))
