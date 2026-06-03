"""routes/admin.py — Admin dashboard"""

from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from routes.auth import login_required, role_required
from services import ApiClient

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
@login_required
@role_required("Admin")
def index():
    api    = ApiClient()
    result = api.get_users()
    users  = result.get("data") if result.get("success") else []
    return render_template("admin/index.html", users=users)


@admin_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("Admin")
def update_role(user_id):
    role = request.form.get("role", "").strip()
    if role not in ("Customer", "Teller", "Admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("admin.index"))

    api    = ApiClient()
    result = api.update_role(user_id, role)

    if not result.get("success"):
        flash(result.get("message", "Role update failed."), "danger")
    else:
        flash(f"Role updated to {role}.", "success")

    return redirect(url_for("admin.index"))


@admin_bp.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@role_required("Admin")
def unlock_user(user_id):
    api    = ApiClient()
    result = api.unlock_user(user_id)

    if not result.get("success"):
        flash(result.get("message", "Unlock failed."), "danger")
    else:
        flash("User account unlocked.", "success")

    return redirect(url_for("admin.index"))


@admin_bp.route("/admin/audit-logs")
@login_required
@role_required("Admin")
def audit_logs():
    page   = request.args.get("page", 1, type=int)
    api    = ApiClient()
    result = api.get_audit_logs(page)
    logs   = result.get("data") if result.get("success") else []
    return render_template("admin/audit_logs.html", logs=logs, page=page)


@admin_bp.route("/admin/audit-logs/verify")
@login_required
@role_required("Admin")
def verify_integrity():
    api    = ApiClient()
    result = api.verify_integrity()
    data   = result.get("data", {})

    if data.get("integrityValid"):
        flash("✓ Audit log integrity verified. No tampering detected.", "success")
    else:
        flash("⚠ INTEGRITY VIOLATION DETECTED. Logs may have been tampered with.", "danger")

    return redirect(url_for("admin.audit_logs"))
