import re
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from app.middleware.auth_guard import require_auth
from app.utils.vault_client import VaultClient
from app.models.audit_log import AuditLog
from app.extensions import limiter

other_secrets_bp = Blueprint("other_secrets", __name__)

def _get_user_vault_path() -> str:
    if g.get("current_user"):
        return f"others/{g.current_user.username}"
    elif g.get("current_api_key"):
        from app.models.user import User
        user = User.query.get(g.current_api_key.user_id)
        if user:
            return f"others/{user.username}"
    return "others/default"

def _slugify(text: str) -> str:
    """Convert a name into a URL-friendly slug."""
    text = text.lower()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    return text.strip('-')

def _ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def _safe_dict(secret: dict) -> dict:
    """Mask sensitive fields before returning to frontend."""
    safe = dict(secret)
    safe["password"] = "***HIDDEN***" if safe.get("password") else ""
    safe["totp_secret"] = "***HIDDEN***" if safe.get("totp_secret") else ""
    return safe

@other_secrets_bp.route("", methods=["GET"])
@require_auth("secrets:read")
def list_other_secrets():
    """List all other credentials."""
    tag_filter = request.args.get("tag", "").strip().lower()
    base_path = _get_user_vault_path()
    slugs = VaultClient.kv_list(path=base_path + "/")
    results = []

    for slug in slugs:
        slug_clean = slug.rstrip("/")
        data = VaultClient.kv_read(f"{base_path}/{slug_clean}")
        if data is None:
            continue
        if tag_filter:
            tags = [t.lower() for t in data.get("tags", [])]
            if tag_filter not in tags:
                continue
        safe = _safe_dict(data)
        safe["_id"] = slug_clean
        results.append(safe)

    return jsonify({"secrets": results, "total": len(results)}), 200

@other_secrets_bp.route("/<slug>", methods=["GET"])
@require_auth("secrets:read")
def get_other_secret(slug: str):
    """Get a specific other credential. Pass ?reveal=true to show passwords."""
    reveal = request.args.get("reveal", "false").lower() == "true"
    
    if reveal:
        api_key = g.get("current_api_key")
        if api_key and not api_key.has_scope("secrets:write"):
            return jsonify({"error": "secrets:write scope required to reveal credentials"}), 403

    base_path = _get_user_vault_path()
    data = VaultClient.kv_read(f"{base_path}/{slug}")
    if data is None:
        return jsonify({"error": "Secret not found"}), 404

    AuditLog.log(
        action="other_secret.read",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="other_secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"reveal": reveal},
    )

    result = data if reveal else _safe_dict(data)
    result["_id"] = slug
    
    # Compute live TOTP code if secret exists and is revealed
    if reveal and result.get("totp_secret"):
        import pyotp
        secret_val = result["totp_secret"]
        if "-" in secret_val:
            base_path_totp = "totp/" + base_path.split("/")[-1]
            totp_data = VaultClient.kv_read(f"{base_path_totp}/{secret_val}")
            if totp_data and totp_data.get("secret_key"):
                secret_val = totp_data["secret_key"]
        
        if secret_val:
            try:
                result["current_totp"] = pyotp.TOTP(secret_val).now()
            except Exception:
                result["current_totp"] = "Error"

    return jsonify(result), 200

@other_secrets_bp.route("", methods=["POST"])
@require_auth("secrets:write")
@limiter.limit("50 per hour")
def create_other_secret():
    """Create a new other credential."""
    data = request.get_json(silent=True) or {}

    if not data.get("name"):
        return jsonify({"error": "Missing required field: name"}), 400

    base_path = _get_user_vault_path()
    slug = _slugify(data["name"])
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if existing:
        return jsonify({"error": f"Secret '{slug}' already exists. Use PUT to update."}), 409

    now = datetime.now(timezone.utc).isoformat()
    totp_secret_raw = data.get("totp_secret", "")
    totp_secret = totp_secret_raw if "-" in totp_secret_raw else totp_secret_raw.replace(" ", "").upper()

    secret_data = {
        "name": data["name"],
        "type": data.get("type", "other"),
        "target_url": data.get("target_url", ""),
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "totp_secret": totp_secret,
        "description": data.get("description", ""),
        "folder": data.get("folder", ""),
        "tags": data.get("tags", []),
        "created_by": g.current_user.username if g.current_user else "api_key",
        "created_at": now,
        "updated_at": now,
    }

    VaultClient.kv_write(f"{base_path}/{slug}", secret_data)

    AuditLog.log(
        action="other_secret.created",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="other_secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"type": data.get("type")}
    )

    return jsonify({"message": "Secret created", "_id": slug}), 201

@other_secrets_bp.route("/<slug>", methods=["PUT"])
@require_auth("secrets:write")
def update_other_secret(slug: str):
    """Update an existing other credential."""
    data = request.get_json(silent=True) or {}
    base_path = _get_user_vault_path()
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if not existing:
        return jsonify({"error": "Secret not found"}), 404

    updated = {**existing, **data}
    if "totp_secret" in data:
        t_sec = data["totp_secret"]
        updated["totp_secret"] = t_sec if "-" in t_sec else t_sec.replace(" ", "").upper()
        
    updated["updated_at"] = datetime.now(timezone.utc).isoformat()

    VaultClient.kv_update(f"{base_path}/{slug}", updated)

    AuditLog.log(
        action="other_secret.updated",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="other_secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"fields_updated": list(data.keys())},
    )

    return jsonify({"message": "Secret updated", "_id": slug}), 200

@other_secrets_bp.route("/<slug>", methods=["DELETE"])
@require_auth("secrets:delete")
def delete_other_secret(slug: str):
    """Delete an other credential."""
    base_path = _get_user_vault_path()
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if not existing:
        return jsonify({"error": "Secret not found"}), 404

    ok = VaultClient.kv_delete(f"{base_path}/{slug}")
    if not ok:
        return jsonify({"error": "Failed to delete secret from Vault"}), 500

    AuditLog.log(
        action="other_secret.deleted",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="other_secret",
        resource_id=slug,
        ip_address=_ip(),
    )

    return jsonify({"message": f"Secret '{slug}' permanently deleted"}), 200
