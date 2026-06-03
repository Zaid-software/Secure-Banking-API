"""
app.py — Secure Banking Flask Frontend
Communicates with the C# .NET Core Web API backend.
All sensitive logic stays in the backend — this layer handles UI only.
"""

import os
from flask import Flask
from dotenv import load_dotenv
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.transactions import transactions_bp
from routes.admin import admin_bp

load_dotenv()

app = Flask(__name__)

# ── Security config ────────────────────────────────────────────────────────
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-in-production-32chars")
app.config["SESSION_COOKIE_HTTPONLY"]  = True   # prevent JS access to cookie
app.config["SESSION_COOKIE_SECURE"]   = True    # HTTPS only
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 min session timeout
app.config["API_BASE_URL"] = os.getenv("API_BASE_URL", "https://localhost:7001")
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6MB max upload

# ── Register blueprints ────────────────────────────────────────────────────
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(transactions_bp)
app.register_blueprint(admin_bp)

# ── Security headers on every response ────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


@app.errorhandler(404)
def not_found(e):
    from flask import render_template
    return render_template("errors/404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    from flask import render_template
    return render_template("errors/403.html"), 403


@app.errorhandler(500)
def server_error(e):
    from flask import render_template
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    # Never run debug=True in production
    app.run(host="0.0.0.0", port=5001, debug=False)
