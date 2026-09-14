"""
app/routes/admin.py - Admin-only endpoints: user management, audit logs, system health.
"""
from flask import Blueprint, request, jsonify, g
from app.extensions import db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.middleware.auth_guard import require_admin, require_auth
from app.utils.vault_client import VaultClient

admin_bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin")


# ================================================================== USERS

@admin_bp.route("/users", methods=["GET"])
@require_admin
def list_users():
    """
    List all users.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: List of users
    """
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users], "total": len(users)}), 200


@admin_bp.route("/users", methods=["POST"])
@require_admin
def create_user():
    """
    Create a new user.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
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
            password:
              type: string
            email:
              type: string
            is_admin:
              type: boolean
    responses:
      201:
        description: User created
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email")
    is_admin = data.get("is_admin", False)

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": f"Username '{username}' already exists"}), 409

    user = User(username=username, email=email, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    AuditLog.log(
        action="admin.user_created",
        user_id=g.current_user.id,
        details={"new_username": username, "is_admin": is_admin},
    )
    return jsonify({"message": "User created", "user": user.to_dict()}), 201


@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@require_admin
def update_user(user_id: int):
    """
    Update user details or status.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            is_active:
              type: boolean
            is_admin:
              type: boolean
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: User updated
    """
    user = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if "is_active" in data:
        user.is_active = bool(data["is_active"])
    if "is_admin" in data:
        user.is_admin = bool(data["is_admin"])
    if "email" in data:
        user.email = data["email"]
    if "password" in data and data["password"]:
        if len(data["password"]) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        user.set_password(data["password"])

    db.session.commit()
    AuditLog.log(
        action="admin.user_updated",
        user_id=g.current_user.id,
        details={"target_user_id": user_id, "fields": list(data.keys())},
    )
    return jsonify({"message": "User updated", "user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_admin
def delete_user(user_id: int):
    """
    Delete a user and all their API keys.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: User deleted
    """
    user = User.query.get_or_404(user_id)
    if user.id == g.current_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    username = user.username
    db.session.delete(user)
    db.session.commit()

    AuditLog.log(
        action="admin.user_deleted",
        user_id=g.current_user.id,
        details={"deleted_username": username},
    )
    return jsonify({"message": f"User '{username}' deleted"}), 200


# ================================================================== AUDIT LOGS

@admin_bp.route("/audit-logs", methods=["GET"])
@require_auth("audit:read")
def list_audit_logs():
    """
    Retrieve audit logs with filtering and pagination.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 50
      - name: action
        in: query
        type: string
      - name: user_id
        in: query
        type: integer
      - name: status
        in: query
        type: string
        enum: [success, failure]
    responses:
      200:
        description: Paginated audit logs
    """
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    action_filter = request.args.get("action")
    user_id_filter = request.args.get("user_id")
    status_filter = request.args.get("status")

    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
    if user_id_filter:
        query = query.filter(AuditLog.user_id == int(user_id_filter))
    if status_filter:
        query = query.filter(AuditLog.status == status_filter)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "logs": [log.to_dict() for log in paginated.items],
        "total": paginated.total,
        "page": page,
        "per_page": per_page,
        "pages": paginated.pages,
    }), 200


# ================================================================== HEALTH

@admin_bp.route("/health", methods=["GET"])
def health_check():
    """
    System health check: app, database, and Vault connectivity.
    ---
    tags:
      - Admin
    responses:
      200:
        description: System health status
    """
    db_ok = True
    db_error = None
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception as e:
        db_ok = False
        db_error = str(e)

    vault_status = VaultClient.health()

    status = "healthy" if db_ok and vault_status.get("connected") else "degraded"

    return jsonify({
        "status": status,
        "database": {"ok": db_ok, "error": db_error},
        "vault": vault_status,
        "version": "1.0.0",
    }), 200 if status == "healthy" else 503


# ================================================================== STATS

@admin_bp.route("/stats", methods=["GET"])
@require_admin
def system_stats():
    """
    Get system-wide statistics.
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: System statistics
    """
    from app.utils.vault_client import VaultClient
    secret_count = len(VaultClient.kv_list("servers/"))
    return jsonify({
        "users": {
            "total": User.query.count(),
            "active": User.query.filter_by(is_active=True).count(),
            "admins": User.query.filter_by(is_admin=True).count(),
        },
        "api_keys": {
            "total": ApiKey.query.count(),
            "active": ApiKey.query.filter_by(is_active=True).count(),
        },
        "secrets": {
            "total": secret_count,
        },
        "audit_logs": {
            "total": AuditLog.query.count(),
            "failures_today": AuditLog.query.filter(
                AuditLog.status == "failure",
            ).count(),
        },
    }), 200
