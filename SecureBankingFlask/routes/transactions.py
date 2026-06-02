"""routes/transactions.py — Deposit, Withdraw, Transfer, History, Upload"""

from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from routes.auth import login_required
from services import ApiClient

transactions_bp = Blueprint("transactions", __name__)


@transactions_bp.route("/transactions/history")
@login_required
def history():
    api    = ApiClient()
    result = api.get_history()
    txns   = result.get("data") if result.get("success") else []
    return render_template("transactions/history.html", transactions=txns)


@transactions_bp.route("/transactions/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        try:
            amount      = float(request.form.get("amount", 0))
            description = request.form.get("description", "").strip()[:200]
        except ValueError:
            flash("Invalid amount.", "danger")
            return render_template("transactions/deposit.html")

        if amount <= 0 or amount > 50000:
            flash("Amount must be between $0.01 and $50,000.", "danger")
            return render_template("transactions/deposit.html")

        api    = ApiClient()
        result = api.deposit(amount, description or None)

        if not result.get("success"):
            flash(result.get("message", "Deposit failed."), "danger")
            return render_template("transactions/deposit.html")

        flash(f"Successfully deposited ${amount:,.2f}.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("transactions/deposit.html")


@transactions_bp.route("/transactions/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    if request.method == "POST":
        try:
            amount      = float(request.form.get("amount", 0))
            description = request.form.get("description", "").strip()[:200]
        except ValueError:
            flash("Invalid amount.", "danger")
            return render_template("transactions/withdraw.html")

        if amount <= 0 or amount > 50000:
            flash("Amount must be between $0.01 and $50,000.", "danger")
            return render_template("transactions/withdraw.html")

        api    = ApiClient()
        result = api.withdraw(amount, description or None)

        if not result.get("success"):
            flash(result.get("message", "Withdrawal failed."), "danger")
            return render_template("transactions/withdraw.html")

        flash(f"Successfully withdrew ${amount:,.2f}.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("transactions/withdraw.html")


@transactions_bp.route("/transactions/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        try:
            amount      = float(request.form.get("amount", 0))
            destination = request.form.get("destination", "").strip()[:20]
            description = request.form.get("description", "").strip()[:200]
        except ValueError:
            flash("Invalid input.", "danger")
            return render_template("transactions/transfer.html")

        if amount <= 0 or amount > 50000:
            flash("Amount must be between $0.01 and $50,000.", "danger")
            return render_template("transactions/transfer.html")

        if not destination:
            flash("Destination account number is required.", "danger")
            return render_template("transactions/transfer.html")

        api    = ApiClient()
        result = api.transfer(amount, destination, description or None)

        if not result.get("success"):
            flash(result.get("message", "Transfer failed."), "danger")
            return render_template("transactions/transfer.html")

        flash(f"Successfully transferred ${amount:,.2f} to {destination}.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("transactions/transfer.html")


@transactions_bp.route("/transactions/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected.", "danger")
            return render_template("transactions/upload.html")

        file = request.files["file"]

        if file.filename == "":
            flash("No file selected.", "danger")
            return render_template("transactions/upload.html")

        # Validate extension client-side too
        allowed = {".jpg", ".jpeg", ".png"}
        import os
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in allowed:
            flash("Only JPG and PNG files are allowed.", "danger")
            return render_template("transactions/upload.html")

        file_bytes   = file.read()
        content_type = file.content_type or "application/octet-stream"

        api    = ApiClient()
        result = api.upload_file(file_bytes, file.filename, content_type)

        if not result.get("success"):
            flash(result.get("message", "Upload failed."), "danger")
            return render_template("transactions/upload.html")

        data = result.get("data", {})
        flash(f"File uploaded and scanned: {data.get('scanResult', 'Clean')}. "
              f"Stored encrypted on server.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("transactions/upload.html")
