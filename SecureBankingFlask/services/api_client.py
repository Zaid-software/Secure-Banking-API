"""
services/api_client.py
All HTTP calls to the C# backend go through this module.
Centralises error handling, token injection, and SSL config.
"""

import requests
from flask import current_app, session
import urllib3
"""
services/api_client.py
All HTTP calls to the C# backend go through this module.
"""

import requests
from flask import current_app, session
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Hardcoded for local development
API_BASE_URL = "http://localhost:5000"


class ApiClient:
    def __init__(self):
        self.base_url = API_BASE_URL
        self.verify_ssl = False

    def _headers(self, require_auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json"}
        if require_auth:
            token = session.get("jwt_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _handle_response(self, response: requests.Response) -> dict:
        try:
            data = response.json()
        except Exception:
            return {"success": False, "message": "Invalid response from server."}

        if response.status_code == 429:
            return {"success": False, "message": "Too many requests. Please wait."}

        if response.status_code == 401:
            session.clear()
            return {"success": False, "message": "Session expired. Please log in again.", "unauthorized": True}

        return data

    def register(self, username: str, email: str, password: str) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/register",
                json={"username": username, "email": email, "password": password},
                headers=self._headers(require_auth=False),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": "Cannot connect to banking server."}
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Request timed out."}

    def login(self, username: str, password: str, totp_code: str = None) -> dict:
        payload = {"username": username, "password": password}
        if totp_code:
            payload["totpCode"] = totp_code
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/login",
                json=payload,
                headers=self._headers(require_auth=False),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": "Cannot connect to banking server."}
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Request timed out."}

    def setup_mfa(self) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/mfa/setup",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "MFA setup failed."}

    def get_account(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/transaction/account",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load account."}

    def get_history(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/transaction/history",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load history."}

    def deposit(self, amount: float, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/deposit",
                json={"amount": amount, "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Deposit failed."}

    def withdraw(self, amount: float, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/withdraw",
                json={"amount": amount, "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Withdrawal failed."}

    def transfer(self, amount: float, destination: str, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/transfer",
                json={"amount": amount, "destinationAccount": destination,
                      "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Transfer failed."}

    def upload_file(self, file_bytes: bytes, filename: str, content_type: str) -> dict:
        try:
            headers = {"Authorization": f"Bearer {session.get('jwt_token', '')}"}
            resp = requests.post(
                f"{self.base_url}/api/fileupload/upload",
                files={"file": (filename, file_bytes, content_type)},
                headers=headers,
                verify=self.verify_ssl, timeout=30
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "File upload failed."}

    def get_users(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/users",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load users."}

    def update_role(self, user_id: int, role: str) -> dict:
        try:
            resp = requests.put(
                f"{self.base_url}/api/admin/users/{user_id}/role",
                json={"role": role},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Role update failed."}

    def unlock_user(self, user_id: int) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/admin/users/{user_id}/unlock",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Unlock failed."}

    def get_audit_logs(self, page: int = 1) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/audit-logs?page={page}&pageSize=50",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load audit logs."}

    def verify_integrity(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/audit-logs/verify",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=15
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Integrity check failed."}
# Disable SSL warnings for local dev (self-signed cert)
# Remove this in production with a real certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ApiClient:
    def __init__(self):
        self.base_url = current_app.config["API_BASE_URL"]
        self.verify_ssl = False  # Set True in production with valid cert

    def _headers(self, require_auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json"}
        if require_auth:
            token = session.get("jwt_token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _handle_response(self, response: requests.Response) -> dict:
        try:
            data = response.json()
        except Exception:
            return {"success": False, "message": "Invalid response from server."}

        if response.status_code == 429:
            return {"success": False, "message": "Too many requests. Please wait and try again."}

        if response.status_code == 401:
            session.clear()
            return {"success": False, "message": "Session expired. Please log in again.", "unauthorized": True}

        return data

    # ── Auth ───────────────────────────────────────────────────────────────

    def register(self, username: str, email: str, password: str) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/register",
                json={"username": username, "email": email, "password": password},
                headers=self._headers(require_auth=False),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": "Cannot connect to banking server."}
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Request timed out."}

    def login(self, username: str, password: str, totp_code: str = None) -> dict:
        payload = {"username": username, "password": password}
        if totp_code:
            payload["totpCode"] = totp_code
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/login",
                json=payload,
                headers=self._headers(require_auth=False),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": "Cannot connect to banking server."}
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Request timed out."}

    def setup_mfa(self) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/auth/mfa/setup",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "MFA setup failed."}

    # ── Account & Transactions ─────────────────────────────────────────────

    def get_account(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/transaction/account",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load account."}

    def get_history(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/transaction/history",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load history."}

    def deposit(self, amount: float, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/deposit",
                json={"amount": amount, "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Deposit failed."}

    def withdraw(self, amount: float, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/withdraw",
                json={"amount": amount, "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Withdrawal failed."}

    def transfer(self, amount: float, destination: str, description: str = None) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/transaction/transfer",
                json={"amount": amount, "destinationAccount": destination,
                      "description": description},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Transfer failed."}

    # ── File Upload ────────────────────────────────────────────────────────

    def upload_file(self, file_bytes: bytes, filename: str, content_type: str) -> dict:
        try:
            headers = {"Authorization": f"Bearer {session.get('jwt_token', '')}"}
            resp = requests.post(
                f"{self.base_url}/api/fileupload/upload",
                files={"file": (filename, file_bytes, content_type)},
                headers=headers,
                verify=self.verify_ssl, timeout=30
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "File upload failed."}

    # ── Admin ──────────────────────────────────────────────────────────────

    def get_users(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/users",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load users."}

    def update_role(self, user_id: int, role: str) -> dict:
        try:
            resp = requests.put(
                f"{self.base_url}/api/admin/users/{user_id}/role",
                json={"role": role},
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Role update failed."}

    def unlock_user(self, user_id: int) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/api/admin/users/{user_id}/unlock",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Unlock failed."}

    def get_audit_logs(self, page: int = 1) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/audit-logs?page={page}&pageSize=50",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Failed to load audit logs."}

    def verify_integrity(self) -> dict:
        try:
            resp = requests.get(
                f"{self.base_url}/api/admin/audit-logs/verify",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10
            )
            return self._handle_response(resp)
        except Exception:
            return {"success": False, "message": "Integrity check failed."}
