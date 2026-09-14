"""
app/__init__.py - Flask application factory.
"""
from flask import Flask, jsonify, send_from_directory
from flasgger import Swagger
from app.config import get_config
from app.extensions import db, migrate, jwt, limiter, cors


SWAGGER_TEMPLATE = {
    "swagger": "2.0",
    "info": {
        "title": "API Vault",
        "description": (
            "🔐 **API Vault** - Secure credential management system.\n\n"
            "## Authentication\n"
            "Use **Bearer JWT token** or **X-API-Key header**.\n\n"
            "1. POST `/api/v1/auth/login` to get JWT tokens\n"
            "2. Or POST `/api/v1/keys` to generate an API key\n"
            "3. Then set `Authorization: Bearer <token>` or `X-API-Key: vk_...`"
        ),
        "version": "1.0.0",
        "contact": {"name": "API Vault", "email": "admin@example.com"},
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Bearer token. Format: **Bearer &lt;token&gt;**",
        },
        "ApiKey": {
            "type": "apiKey",
            "name": "X-API-Key",
            "in": "header",
            "description": "API key starting with **vk_**",
        },
    },
    "tags": [
        {"name": "Authentication", "description": "Login, logout, token management"},
        {"name": "API Keys", "description": "Generate and manage API keys with scopes"},
        {"name": "Secrets", "description": "Store and retrieve server credentials via Vault KV"},
        {"name": "SSH Certificates", "description": "Sign SSH keys via Vault SSH CA"},
        {"name": "Import", "description": "Import credentials from KeePass .kdbx files"},
        {"name": "Admin", "description": "User management, audit logs, health"},
    ],
}

SWAGGER_CONFIG = {
    "headers": [],
    "specs": [{"endpoint": "apispec", "route": "/apispec.json"}],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs",
}


def create_app(config=None):
    app = Flask(__name__, static_folder="../static", static_url_path="/static")

    # Load config
    cfg = config or get_config()
    app.config.from_object(cfg)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    # Swagger docs
    Swagger(app, template=SWAGGER_TEMPLATE, config=SWAGGER_CONFIG)

    # Register blueprints
    from app.routes import auth_bp, api_keys_bp, secrets_bp, ssh_bp, admin_bp, import_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_keys_bp)
    app.register_blueprint(secrets_bp)
    app.register_blueprint(ssh_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(import_bp)

    # Serve Web Dashboard
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_dashboard(path):
        import os
        static_dir = os.path.join(app.root_path, "..", "static")
        if path and os.path.exists(os.path.join(static_dir, path)):
            return send_from_directory(static_dir, path)
        return send_from_directory(static_dir, "index.html")

    # Global error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error"}), 500

    # Seed admin user on first run
    with app.app_context():
        _seed_admin(app)

    return app


def _seed_admin(app):
    """Create default admin user if no users exist. Silently skips if tables aren't created yet."""
    from app.models.user import User
    from sqlalchemy import inspect
    try:
        # Check if the users table actually exists before querying
        inspector = inspect(db.engine)
        if "users" not in inspector.get_table_names():
            return  # Tables not created yet — migrations haven't run
        if User.query.count() == 0:
            admin = User(
                username=app.config["ADMIN_USERNAME"],
                is_admin=True,
                is_active=True,
            )
            admin.set_password(app.config["ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()
            app.logger.info(
                f"✅ Admin user '{app.config['ADMIN_USERNAME']}' created."
            )
    except Exception:
        pass  # Silently skip — tables may not exist yet
