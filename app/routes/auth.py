"""
app/routes/auth.py - Authentication endpoints: login, refresh, logout, me.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from app.extensions import db, limiter
from app.models.user import User
from app.models.audit_log import AuditLog
from app.middleware.auth_guard import require_auth

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

# Track revoked JTIs (in-memory; replace with Redis in production)
_revoked_tokens: set[str] = set()


def _ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """
    Login with username and password.
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [username, password]
          properties:
            username:
              type: string
              example: admin
            password:
              type: string
              example: Admin@123456
    responses:
      200:
        description: JWT access and refresh tokens
      401:
        description: Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = User.query.filter_by(username=username, is_active=True).first()
    if not user or not user.check_password(password):
        AuditLog.log(
            action="auth.login.failed",
            status="failure",
            ip_address=_ip(),
            details={"username": username},
        )
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    user.update_last_login()

    AuditLog.log(
        action="auth.login.success",
        user_id=user.id,
        ip_address=_ip(),
        details={"username": username},
    )

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token using refresh token.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: New access token
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({"error": "User not found"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token, "token_type": "Bearer"}), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Revoke current access token.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Logged out
    """
    jti = get_jwt()["jti"]
    _revoked_tokens.add(jti)
    user_id = get_jwt_identity()
    AuditLog.log(action="auth.logout", user_id=user_id, ip_address=_ip())
    return jsonify({"message": "Successfully logged out"}), 200


@auth_bp.route("/me", methods=["GET"])
@require_auth()
def me():
    """
    Get current authenticated user info.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
      - ApiKey: []
    responses:
      200:
        description: Current user profile
    """
    return jsonify({"user": g.current_user.to_dict()}), 200


@auth_bp.route("/change-password", methods=["POST"])
@require_auth()
def change_password():
    """
    Change password for current user.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [old_password, new_password]
          properties:
            old_password:
              type: string
            new_password:
              type: string
    responses:
      200:
        description: Password changed
    """
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")

    if not old_pw or not new_pw:
        return jsonify({"error": "old_password and new_password required"}), 400

    user = g.current_user
    if not user.check_password(old_pw):
        return jsonify({"error": "Current password is incorrect"}), 401

    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    user.set_password(new_pw)
    db.session.commit()

    AuditLog.log(action="auth.password_changed", user_id=user.id, ip_address=_ip())
    return jsonify({"message": "Password changed successfully"}), 200
