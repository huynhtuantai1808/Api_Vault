"""
app/config.py - Application configuration loaded from environment variables.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    DEBUG = False
    TESTING = False

    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://vault_user:vault_pass@localhost:5432/api_vault"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    from sqlalchemy.pool import NullPool
    SQLALCHEMY_ENGINE_OPTIONS = {
        "poolclass": NullPool,
    }

    # JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 604800))
    )
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    # HashiCorp Vault
    VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")
    VAULT_SSH_ROLE = os.getenv("VAULT_SSH_ROLE", "my-role")
    VAULT_KV_MOUNT = os.getenv("VAULT_KV_MOUNT", "secret")
    VAULT_SSH_MOUNT = os.getenv("VAULT_SSH_MOUNT", "ssh")

    # Admin seed
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123456")

    # Rate limiting
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per minute")
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "memory://")

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # File storage for SSH keys
    SSH_DOWNLOAD_DIR = os.getenv("SSH_DOWNLOAD_DIR", "/tmp/vault_keys")

    # Guacamole Daemon (guacd) for RDP
    GUACD_HOST = os.getenv("GUACD_HOST", "guacd")
    GUACD_PORT = int(os.getenv("GUACD_PORT", 4822))

    # Performance Monitoring & Telegram Alerts
    TELEGRAM_ALERT_BOT_TOKEN = os.getenv("TELEGRAM_ALERT_BOT_TOKEN", "")
    TELEGRAM_ALERT_CHAT_ID = os.getenv("TELEGRAM_ALERT_CHAT_ID", "")
    ALERT_SCAN_INTERVAL = int(os.getenv("ALERT_SCAN_INTERVAL", 180))
    ALERT_CPU_THRESHOLD = float(os.getenv("ALERT_CPU_THRESHOLD", 95.0))
    ALERT_RAM_MIN_FREE_GB = float(os.getenv("ALERT_RAM_MIN_FREE_GB", 1.0))
    ALERT_DISK_MIN_FREE_GB = float(os.getenv("ALERT_DISK_MIN_FREE_GB", 2.0))
    ALERT_ONLY_LINUX = os.getenv("ALERT_ONLY_LINUX", "true").lower() in ("true", "1", "yes")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    env = os.getenv("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
