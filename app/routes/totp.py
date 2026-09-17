import re
import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from app.extensions import limiter
from app.utils.vault_client import VaultClient
from app.middleware.auth_guard import require_auth

totp_bp = Blueprint("totp", __name__, url_prefix="/api/v1/totp")

def _get_user_totp_path():
    if g.get("current_user"):
        return f"totp/{g.current_user.username}"
    elif g.get("current_api_key"):
        from app.models.user import User
        user = User.query.get(g.current_api_key.user_id)
        if user:
            return f"totp/{user.username}"
    return "totp/default"

@totp_bp.before_request
@require_auth()
def before_request():
    pass

@totp_bp.route("", methods=["GET"])
@limiter.limit("50 per minute")
def list_totp():
    """List all TOTP credentials for the current user."""
    vc = VaultClient()
    path = _get_user_totp_path()
    try:
        secrets_list = VaultClient.kv_list(path)
        
        # VaultClient.kv_list returns a list of keys, but we want to fetch the actual secrets (without secret_key)
        totps = []
        for key in secrets_list:
            data = VaultClient.kv_read(f"{path}/{key}")
            if data:
                data.pop("secret_key", None)
                totps.append(data)
                
        return jsonify({"status": "success", "totps": totps}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@totp_bp.route("/<totp_id>", methods=["GET"])
@limiter.limit("100 per minute")
def get_totp(totp_id):
    """Get a specific TOTP credential (with secret_key) if reveal=true."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", totp_id):
        return jsonify({"status": "error", "message": "Invalid TOTP ID"}), 400
        
    vc = VaultClient()
    path = f"{_get_user_totp_path()}/{totp_id}"
    
    try:
        data = VaultClient.kv_read(path)
        if not data:
            return jsonify({"status": "error", "message": "TOTP not found"}), 404
            
        reveal = request.args.get("reveal", "false").lower() == "true"
        if reveal:
            import pyotp
            if data.get("secret_key"):
                try:
                    data["current_code"] = pyotp.TOTP(data["secret_key"]).now()
                except Exception:
                    data["current_code"] = "Error"
        else:
            data.pop("secret_key", None)
            
        return jsonify({"status": "success", "totp": data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@totp_bp.route("", methods=["POST"])
@limiter.limit("20 per minute")
def create_totp():
    """Create a new TOTP credential."""
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No JSON payload"}), 400
        
    issuer = data.get("issuer", "").strip()
    name = data.get("name", "").strip()
    secret_key = data.get("secret_key", "").strip().replace(" ", "").upper()
    
    if not name or not secret_key:
        return jsonify({"status": "error", "message": "Name and secret_key are required"}), 400
        
    totp_id = str(uuid.uuid4())
    vc = VaultClient()
    path = f"{_get_user_totp_path()}/{totp_id}"
    
    new_totp = {
        "id": totp_id,
        "issuer": issuer,
        "name": name,
        "secret_key": secret_key,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        success = VaultClient.kv_write(path, new_totp)
        if success is not None:
            return jsonify({"status": "success", "message": "TOTP created", "id": totp_id}), 201
        return jsonify({"status": "error", "message": "Failed to store in Vault"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@totp_bp.route("/<totp_id>", methods=["DELETE"])
@limiter.limit("20 per minute")
def delete_totp(totp_id):
    """Delete a TOTP credential."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", totp_id):
        return jsonify({"status": "error", "message": "Invalid TOTP ID"}), 400
        
    vc = VaultClient()
    path = f"{_get_user_totp_path()}/{totp_id}"
    
    try:
        if VaultClient.kv_delete(path):
            return jsonify({"status": "success", "message": "Deleted successfully"}), 200
        return jsonify({"status": "error", "message": "Not found or delete failed"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
