"""
app/routes/__init__.py
"""
from .auth import auth_bp
from .api_keys import api_keys_bp
from .secrets import secrets_bp
from .ssh import ssh_bp
from .admin import admin_bp

__all__ = ["auth_bp", "api_keys_bp", "secrets_bp", "ssh_bp", "admin_bp"]
