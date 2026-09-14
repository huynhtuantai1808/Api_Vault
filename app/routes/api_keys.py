"""
app/routes/api_keys.py - CRUD and management for API keys.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from app.extensions import db, limiter
from app.models.api_key import ApiKey, SCOPES
from app.models.audit_log import AuditLog
from app.middleware.auth_guard import require_auth, require_admin

api_keys_bp = Blueprint("api_keys", __name__, url_prefix="/api/v1/keys")


def _ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


@api_keys_bp.route("/scopes", methods=["GET"])
def list_scopes():
    """
    List all available API key permission scopes.
    ---
    tags:
      - API Keys
    responses:
      200:
        description: Available scopes and descriptions
    """
    return jsonify({"scopes": SCOPES}), 200


@api_keys_bp.route("", methods=["GET"])
@require_auth()
def list_keys():
    """
    List all API keys for the current user (admins see all).
    ---
    tags:
      - API Keys
    security:
      - Bearer: []
      - ApiKey: []
    responses:
      200:
        description: List of API keys
    """
    user = g.current_user
    if user.is_admin:
        keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    else:
        keys = ApiKey.query.filter_by(user_id=user.id).order_by(ApiKey.created_at.desc()).all()

    return jsonify({"keys": [k.to_dict() for k in keys], "total": len(keys)}), 200


@api_keys_bp.route("", methods=["POST"])
@require_auth()
@limiter.limit("20 per hour")
def create_key():
    """
    Generate a new API key.
    ---
    tags:
      - API Keys
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name, scopes]
          properties:
            name:
              type: string
              example: "ci-pipeline-key"
            scopes:
              type: array
              items:
                type: string
              example: ["secrets:read", "ssh:sign"]
            expires_at:
              type: string
              format: date-time
              example: "2025-12-31T23:59:59"
    responses:
      201:
        description: API key created (raw key shown once)
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    scopes = data.get("scopes", [])
    expires_at_str = data.get("expires_at")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not scopes or not isinstance(scopes, list):
        return jsonify({"error": "scopes must be a non-empty list"}), 400

    # Validate scopes
    invalid = [s for s in scopes if s not in SCOPES]
    if invalid:
        return jsonify({"error": f"Invalid scopes: {invalid}", "valid_scopes": list(SCOPES.keys())}), 400

    # Non-admins cannot use keys:manage scope
    if "keys:manage" in scopes and not g.current_user.is_admin:
        return jsonify({"error": "Only admins can grant keys:manage scope"}), 403

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except ValueError:
            return jsonify({"error": "Invalid expires_at format. Use ISO 8601."}), 400

    key_obj, raw_key = ApiKey.create(
        user_id=g.current_user.id,
        name=name,
        scopes=scopes,
        expires_at=expires_at,
    )
    db.session.add(key_obj)
    db.session.commit()

    AuditLog.log(
        action="api_key.created",
        user_id=g.current_user.id,
        api_key_id=key_obj.id,
        resource_type="api_key",
        resource_id=key_obj.id,
        ip_address=_ip(),
        details={"name": name, "scopes": scopes},
    )

    result = key_obj.to_dict()
    result["raw_key"] = raw_key  # Shown ONCE
    result["warning"] = "Store this key securely — it will not be shown again."
    return jsonify(result), 201


@api_keys_bp.route("/<int:key_id>", methods=["GET"])
@require_auth()
def get_key(key_id: int):
    """
    Get details of a specific API key.
    ---
    tags:
      - API Keys
    security:
      - Bearer: []
    parameters:
      - name: key_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: API key details
    """
    user = g.current_user
    key_obj = ApiKey.query.get_or_404(key_id)
    if not user.is_admin and key_obj.user_id != user.id:
        return jsonify({"error": "Not found"}), 404

    return jsonify(key_obj.to_dict()), 200


@api_keys_bp.route("/<int:key_id>", methods=["DELETE"])
@require_auth()
def revoke_key(key_id: int):
    """
    Revoke (deactivate) an API key.
    ---
    tags:
      - API Keys
    security:
      - Bearer: []
    parameters:
      - name: key_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: API key revoked
    """
    user = g.current_user
    key_obj = ApiKey.query.get_or_404(key_id)
    if not user.is_admin and key_obj.user_id != user.id:
        return jsonify({"error": "Not found"}), 404

    key_obj.is_active = False
    db.session.commit()

    AuditLog.log(
        action="api_key.revoked",
        user_id=user.id,
        api_key_id=key_obj.id,
        resource_type="api_key",
        resource_id=key_id,
        ip_address=_ip(),
        details={"name": key_obj.name},
    )
    return jsonify({"message": f"API key '{key_obj.name}' revoked successfully"}), 200


@api_keys_bp.route("/<int:key_id>/rotate", methods=["POST"])
@require_auth()
def rotate_key(key_id: int):
    """
    Rotate (regenerate) an API key — revokes old, returns new raw key.
    ---
    tags:
      - API Keys
    security:
      - Bearer: []
    parameters:
      - name: key_id
        in: path
        type: integer
        required: true
    responses:
      201:
        description: New rotated key (shown once)
    """
    user = g.current_user
    old_key = ApiKey.query.get_or_404(key_id)
    if not user.is_admin and old_key.user_id != user.id:
        return jsonify({"error": "Not found"}), 404

    # Revoke old
    old_key.is_active = False

    # Create new with same settings
    new_key_obj, raw_key = ApiKey.create(
        user_id=old_key.user_id,
        name=old_key.name + " (rotated)",
        scopes=old_key.scopes.split(","),
        expires_at=old_key.expires_at,
    )
    db.session.add(new_key_obj)
    db.session.commit()

    AuditLog.log(
        action="api_key.rotated",
        user_id=user.id,
        api_key_id=new_key_obj.id,
        ip_address=_ip(),
        details={"old_key_id": key_id, "new_key_id": new_key_obj.id},
    )

    result = new_key_obj.to_dict()
    result["raw_key"] = raw_key
    result["warning"] = "Store this key securely — it will not be shown again."
    return jsonify(result), 201
