"""
app/middleware/auth_guard.py - Authentication middleware supporting both JWT and API Key.
"""
import hashlib
from functools import wraps
from flask import request, jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.api_key import ApiKey
from app.models.user import User
from app.models.audit_log import AuditLog


def _get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


def _get_user_agent():
    return request.headers.get("User-Agent", "")[:256]


def require_auth(*required_scopes):
    """
    Decorator that accepts either:
      - Bearer JWT token (Authorization: Bearer <jwt>)
      - API Key       (X-API-Key: vk_...)

    Optionally enforces scope checks when required_scopes are provided.
    Sets g.current_user and g.current_api_key on success.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # --- Try API Key first ---
            api_key_raw = request.headers.get("X-API-Key")
            if api_key_raw:
                key_hash = hashlib.sha256(api_key_raw.encode()).hexdigest()
                key_obj = ApiKey.query.filter_by(key_hash=key_hash).first()

                if not key_obj or not key_obj.is_valid():
                    AuditLog.log(
                        action="auth.api_key.invalid",
                        status="failure",
                        ip_address=_get_client_ip(),
                        user_agent=_get_user_agent(),
                        details={"reason": "Invalid or expired API key"},
                    )
                    return jsonify({"error": "Invalid or expired API key"}), 401

                # Scope check
                for scope in required_scopes:
                    if not key_obj.has_scope(scope):
                        AuditLog.log(
                            action="auth.api_key.forbidden",
                            user_id=key_obj.user_id,
                            api_key_id=key_obj.id,
                            status="failure",
                            ip_address=_get_client_ip(),
                            details={"missing_scope": scope},
                        )
                        return jsonify({"error": f"Missing required scope: {scope}"}), 403

                key_obj.record_usage()
                user = User.query.get(key_obj.user_id)
                g.current_user = user
                g.current_api_key = key_obj
                return fn(*args, **kwargs)

            # --- Fall back to JWT ---
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                if not user or not user.is_active:
                    return jsonify({"error": "User not found or inactive"}), 401
                g.current_user = user
                g.current_api_key = None
                return fn(*args, **kwargs)
            except Exception as e:
                from flask import current_app
                current_app.logger.error(f"JWT verification failed: {e}")
                return jsonify({"error": "Authentication required"}), 401

        return wrapper
    return decorator


def require_admin(fn):
    """Decorator requiring admin role (JWT only or API key with keys:manage scope)."""
    @wraps(fn)
    @require_auth()
    def wrapper(*args, **kwargs):
        user = g.get("current_user")
        if not user or not user.is_admin:
            return jsonify({"error": "Admin privilege required"}), 403
        return fn(*args, **kwargs)
    return wrapper
