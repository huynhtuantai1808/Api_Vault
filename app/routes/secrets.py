"""
app/routes/secrets.py - Server credential CRUD stored in HashiCorp Vault KV v2.

Secret structure stored in Vault at: secret/servers/<slug>
{
  "host": "192.168.1.1",
  "port": 22,
  "username": "root",
  "auth_type": "password" | "ssh_key" | "token",
  "password": "...",         # if auth_type == password
  "ssh_private_key": "...",  # if auth_type == ssh_key
  "token": "...",            # if auth_type == token
  "description": "...",
  "tags": ["prod", "db"],
  "created_by": "admin",
  "created_at": "...",
  "updated_at": "..."
}
"""
import re
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from app.extensions import limiter
from app.utils.vault_client import VaultClient
from app.models.audit_log import AuditLog
from app.middleware.auth_guard import require_auth

secrets_bp = Blueprint("secrets", __name__, url_prefix="/api/v1/secrets")

def _get_user_vault_path():
    if g.get("current_user"):
        return f"servers/{g.current_user.username}"
    elif g.get("current_api_key"):
        from app.models.user import User
        user = User.query.get(g.current_api_key.user_id)
        if user:
            return f"servers/{user.username}"
    return "servers/unknown"


def _ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


def _slugify(name: str) -> str:
    """Convert name to safe vault path slug."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", name.strip().lower())


def _safe_dict(data: dict, hide_fields=("password", "ssh_private_key", "token", "totp_secret")) -> dict:
    """Return dict with sensitive fields masked."""
    return {
        k: ("***HIDDEN***" if k in hide_fields and v else v)
        for k, v in data.items()
    }


@secrets_bp.route("", methods=["GET"])
@require_auth("secrets:read")
def list_secrets():
    """
    List all stored server credentials (sensitive fields masked).
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: tag
        in: query
        type: string
        required: false
        description: Filter by tag
    responses:
      200:
        description: List of server credentials
    """
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


@secrets_bp.route("/export", methods=["GET"])
@require_auth("secrets:read")
def export_secrets():
    """
    Export all server credentials.
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
    parameters:
      - name: reveal
        in: query
        type: boolean
        description: Set to true to export raw passwords/keys (requires write scope)
    """
    reveal = request.args.get("reveal", "false").lower() == "true"
    if reveal:
        api_key = g.get("current_api_key")
        if api_key and not api_key.has_scope("secrets:write"):
            return jsonify({"error": "secrets:write scope required to reveal credentials"}), 403

    base_path = _get_user_vault_path()
    slugs = VaultClient.kv_list(path=base_path + "/")
    results = []

    for slug in slugs:
        slug_clean = slug.rstrip("/")
        data = VaultClient.kv_read(f"{base_path}/{slug_clean}")
        if data is None:
            continue
            
        result = data if reveal else _safe_dict(data)
        result["_slug"] = slug_clean
        results.append(result)

    AuditLog.log(
        action="secret.export",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id="*",
        ip_address=_ip(),
        details={"reveal": reveal, "count": len(results)},
    )
    
    filename = f"api_vault_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return jsonify(results), 200, {
        "Content-Disposition": f"attachment; filename={filename}"
    }


@secrets_bp.route("/import", methods=["POST"])
@require_auth("secrets:write")
def import_secrets():
    """
    Import server credentials from a JSON file.
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
    """
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON array of secrets"}), 400

    base_path = _get_user_vault_path()
    now = datetime.now(timezone.utc).isoformat()
    imported = 0
    errors = []

    for item in data:
        slug = item.get("_slug")
        if not slug and "name" in item:
            slug = _slugify(item["name"])
            
        if not slug:
            errors.append({"item": item.get("name", "Unknown"), "error": "Missing name or slug"})
            continue
            
        item.pop("_id", None)
        item.pop("_slug", None)
        
        if "created_at" not in item:
            item["created_at"] = now
        item["updated_at"] = now
        
        if "created_by" not in item:
            item["created_by"] = g.current_user.username if g.current_user else "api_key"

        try:
            VaultClient.kv_write(f"{base_path}/{slug}", item)
            imported += 1
        except Exception as e:
            errors.append({"slug": slug, "error": str(e)})

    AuditLog.log(
        action="secret.import_json",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id="*",
        ip_address=_ip(),
        details={"imported": imported, "errors": len(errors)},
    )

    return jsonify({
        "message": "Import finished",
        "imported": imported,
        "errors": errors
    }), 200


@secrets_bp.route("/<slug>", methods=["GET"])
@require_auth("secrets:read")
def get_secret(slug: str):
    """
    Retrieve a server credential by slug (sensitive fields masked by default).
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: slug
        in: path
        type: string
        required: true
      - name: reveal
        in: query
        type: boolean
        required: false
        description: Set to true to reveal sensitive fields (requires secrets:write scope)
    responses:
      200:
        description: Server credential
      404:
        description: Not found
    """
    reveal = request.args.get("reveal", "false").lower() == "true"
    if reveal:
        # Must also have write scope to reveal secrets
        api_key = g.get("current_api_key")
        if api_key and not api_key.has_scope("secrets:write"):
            return jsonify({"error": "secrets:write scope required to reveal credentials"}), 403

    base_path = _get_user_vault_path()
    data = VaultClient.kv_read(f"{base_path}/{slug}")
    if data is None:
        return jsonify({"error": "Secret not found"}), 404

    AuditLog.log(
        action="secret.read",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"reveal": reveal},
    )

    result = data if reveal else _safe_dict(data)
    result["_id"] = slug
    
    # Compute live TOTP code if secret exists and is revealed
    if reveal and result.get("totp_secret"):
        import pyotp
        try:
            result["totp_code"] = pyotp.TOTP(result["totp_secret"]).now()
        except Exception:
            result["totp_code"] = "INVALID_SECRET"
            
    return jsonify(result), 200


@secrets_bp.route("", methods=["POST"])
@require_auth("secrets:write")
@limiter.limit("50 per hour")
def create_secret():
    """
    Create a new server credential entry.
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name, host, username, auth_type]
          properties:
            name:
              type: string
              example: "prod-web-01"
            host:
              type: string
              example: "192.168.1.10"
            port:
              type: integer
              example: 22
            username:
              type: string
              example: "root"
            auth_type:
              type: string
              enum: [password, ssh_key, token]
            password:
              type: string
            ssh_private_key:
              type: string
            token:
              type: string
            description:
              type: string
            tags:
              type: array
              items:
                type: string
    responses:
      201:
        description: Secret created
    """
    data = request.get_json(silent=True) or {}

    required_fields = ["name", "host", "username", "auth_type"]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    auth_type = data["auth_type"]
    if auth_type not in ("password", "ssh_key", "token"):
        return jsonify({"error": "auth_type must be: password, ssh_key, or token"}), 400

    base_path = _get_user_vault_path()
    slug = _slugify(data["name"])
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if existing:
        return jsonify({"error": f"Secret '{slug}' already exists. Use PUT to update."}), 409

    now = datetime.now(timezone.utc).isoformat()
    secret_data = {
        "name": data["name"],
        "host": data["host"],
        "port": int(data.get("port", 22)),
        "username": data["username"],
        "auth_type": auth_type,
        "password": data.get("password", ""),
        "ssh_private_key": data.get("ssh_private_key", ""),
        "token": data.get("token", ""),
        "totp_secret": data.get("totp_secret", "").replace(" ", "").upper(),
        "description": data.get("description", ""),
        "tags": data.get("tags", []),
        "created_by": g.current_user.username if g.current_user else "api_key",
        "created_at": now,
        "updated_at": now,
    }

    VaultClient.kv_write(f"{base_path}/{slug}", secret_data)

    AuditLog.log(
        action="secret.created",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"host": data["host"], "username": data["username"]},
    )

    return jsonify({"message": "Secret created", "_id": slug, "host": data["host"]}), 201


@secrets_bp.route("/<slug>", methods=["PUT"])
@require_auth("secrets:write")
def update_secret(slug: str):
    """
    Update an existing server credential.
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: slug
        in: path
        type: string
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
    responses:
      200:
        description: Secret updated
    """
    data = request.get_json(silent=True) or {}
    base_path = _get_user_vault_path()
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if not existing:
        return jsonify({"error": "Secret not found"}), 404

    # Merge update (preserve fields not in request)
    updated = {**existing, **data}
    if "totp_secret" in data:
        updated["totp_secret"] = data["totp_secret"].replace(" ", "").upper()
        
    updated["updated_at"] = datetime.now(timezone.utc).isoformat()

    VaultClient.kv_update(f"{base_path}/{slug}", updated)

    AuditLog.log(
        action="secret.updated",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id=slug,
        ip_address=_ip(),
        details={"fields_updated": list(data.keys())},
    )

    return jsonify({"message": "Secret updated", "_id": slug}), 200


@secrets_bp.route("/<slug>", methods=["DELETE"])
@require_auth("secrets:delete")
def delete_secret(slug: str):
    """
    Permanently delete a server credential and all its Vault versions.
    ---
    tags:
      - Secrets
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: slug
        in: path
        type: string
        required: true
    responses:
      200:
        description: Secret deleted
    """
    base_path = _get_user_vault_path()
    existing = VaultClient.kv_read(f"{base_path}/{slug}")
    if not existing:
        return jsonify({"error": "Secret not found"}), 404

    ok = VaultClient.kv_delete(f"{base_path}/{slug}")
    if not ok:
        return jsonify({"error": "Failed to delete secret from Vault"}), 500

    AuditLog.log(
        action="secret.deleted",
        user_id=g.current_user.id if g.current_user else None,
        api_key_id=g.current_api_key.id if g.current_api_key else None,
        resource_type="secret",
        resource_id=slug,
        ip_address=_ip(),
    )

    return jsonify({"message": f"Secret '{slug}' permanently deleted"}), 200
