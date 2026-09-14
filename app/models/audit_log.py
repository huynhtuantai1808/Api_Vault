"""
app/models/audit_log.py - Immutable audit trail for all sensitive operations.
"""
from datetime import datetime, timezone
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    resource_type = db.Column(db.String(64), nullable=True)   # "secret", "ssh_key", "api_key"
    resource_id = db.Column(db.String(256), nullable=True)    # vault path or key ID
    status = db.Column(db.String(16), default="success")      # success | failure
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    details = db.Column(db.Text, nullable=True)               # JSON string with extra info
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    user = db.relationship("User", back_populates="audit_logs")

    @classmethod
    def log(cls, action: str, user_id=None, api_key_id=None,
            resource_type=None, resource_id=None, status="success",
            ip_address=None, user_agent=None, details=None):
        """Create and persist an audit log entry."""
        import json
        entry = cls(
            user_id=user_id,
            api_key_id=api_key_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            status=status,
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps(details) if isinstance(details, dict) else details,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def to_dict(self):
        import json
        details_parsed = None
        if self.details:
            try:
                details_parsed = json.loads(self.details)
            except Exception:
                details_parsed = self.details

        return {
            "id": self.id,
            "user_id": self.user_id,
            "api_key_id": self.api_key_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "status": self.status,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "details": details_parsed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<AuditLog [{self.action}] by user={self.user_id} at {self.created_at}>"
