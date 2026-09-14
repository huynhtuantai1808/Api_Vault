"""
app/models/api_key.py - API Key model with scopes, expiry, and usage tracking.
"""
import secrets
import hashlib
from datetime import datetime, timezone
from app.extensions import db


# Available permission scopes
SCOPES = {
    "secrets:read":   "Read stored server credentials",
    "secrets:write":  "Create/update server credentials",
    "secrets:delete": "Delete server credentials",
    "ssh:sign":       "Sign SSH public keys via Vault CA",
    "keys:manage":    "Manage API keys (admin only)",
    "audit:read":     "Read audit logs",
}


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    key_prefix = db.Column(db.String(12), nullable=False)          # "vk_" + 8 chars visible
    key_hash = db.Column(db.String(64), nullable=False, unique=True)  # SHA-256 of full key
    scopes = db.Column(db.Text, default="secrets:read")             # comma-separated
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)              # None = no expiry
    last_used_at = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, default=0)

    # Relationships
    user = db.relationship("User", back_populates="api_keys")

    @staticmethod
    def generate_key() -> str:
        """Generate a new raw API key (shown once)."""
        random_part = secrets.token_urlsafe(32)
        return f"vk_{random_part}"

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """SHA-256 hash of the raw key for storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @classmethod
    def create(cls, user_id: int, name: str, scopes: list[str], expires_at=None):
        """Generate a new API key, return (model_instance, raw_key)."""
        raw_key = cls.generate_key()
        key_hash = cls.hash_key(raw_key)
        key_prefix = raw_key[:11]  # "vk_" + 8 chars

        instance = cls(
            user_id=user_id,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            scopes=",".join(scopes),
            expires_at=expires_at,
        )
        return instance, raw_key

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes.split(",")

    def is_valid(self) -> bool:
        if not self.is_active:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def record_usage(self):
        self.last_used_at = datetime.now(timezone.utc)
        self.usage_count += 1
        db.session.commit()

    def to_dict(self, show_prefix_only=True):
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix + "...",
            "scopes": self.scopes.split(","),
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "usage_count": self.usage_count,
            "user_id": self.user_id,
        }

    def __repr__(self):
        return f"<ApiKey {self.key_prefix}... ({self.name})>"
