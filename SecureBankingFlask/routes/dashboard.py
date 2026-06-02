"""routes/dashboard.py — Main dashboard"""

from flask import Blueprint, render_template, session, redirect, url_for, flash
from routes.auth import login_required
from services import ApiClient

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def index():
    api = ApiClient()

    account_result = api.get_account()
    history_result = api.get_history()

    if account_result.get("unauthorized"):
        session.clear()
        return redirect(url_for("auth.login"))

    account     = account_result.get("data") if account_result.get("success") else None
    history     = history_result.get("data") if history_result.get("success") else []
    recent      = history[:5] if history else []

    return render_template("dashboard/index.html",
                           account=account,
                           recent_transactions=recent,
                           username=session.get("username"),
                           role=session.get("role"))
