"""
app/utils/vault_client.py - HashiCorp Vault client wrapper with KV v2 and SSH secrets engine.
"""
import hvac
from flask import current_app
import logging

logger = logging.getLogger(__name__)


class VaultClient:
    """Singleton-like wrapper around hvac.Client."""

    _client: hvac.Client | None = None

    @classmethod
    def get_client(cls) -> hvac.Client:
        if cls._client is None or not cls._client.is_authenticated():
            cls._client = hvac.Client(
                url=current_app.config["VAULT_ADDR"],
                token=current_app.config["VAULT_TOKEN"],
            )
        return cls._client

    # ------------------------------------------------------------------ KV v2

    @classmethod
    def kv_write(cls, path: str, data: dict, mount: str = None) -> dict:
        """Write a secret to KV v2."""
        client = cls.get_client()
        mount = mount or current_app.config["VAULT_KV_MOUNT"]
        return client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=data,
            mount_point=mount,
        )

    @classmethod
    def kv_read(cls, path: str, mount: str = None) -> dict | None:
        """Read a secret from KV v2. Returns data dict or None if not found."""
        client = cls.get_client()
        mount = mount or current_app.config["VAULT_KV_MOUNT"]
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
                raise_on_deleted_version=True,
            )
            return response["data"]["data"]
        except hvac.exceptions.InvalidPath:
            return None
        except Exception as e:
            logger.error(f"Vault KV read error at '{path}': {e}")
            raise

    @classmethod
    def kv_delete(cls, path: str, mount: str = None) -> bool:
        """Permanently delete all versions of a secret."""
        client = cls.get_client()
        mount = mount or current_app.config["VAULT_KV_MOUNT"]
        try:
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=mount,
            )
            return True
        except Exception as e:
            logger.error(f"Vault KV delete error at '{path}': {e}")
            return False

    @classmethod
    def kv_list(cls, path: str = "servers/", mount: str = None) -> list[str]:
        """List keys under a path in KV v2."""
        client = cls.get_client()
        mount = mount or current_app.config["VAULT_KV_MOUNT"]
        try:
            response = client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=mount,
            )
            return response["data"].get("keys", [])
        except hvac.exceptions.InvalidPath:
            return []
        except Exception as e:
            logger.error(f"Vault KV list error at '{path}': {e}")
            return []

    @classmethod
    def kv_update(cls, path: str, data: dict, mount: str = None) -> dict:
        """Alias for kv_write (KV v2 always creates new version)."""
        return cls.kv_write(path, data, mount)

    # ------------------------------------------------------------------ SSH CA

    @classmethod
    def ssh_sign(cls, public_key: str, valid_principals: str, ttl: str = "30m") -> str:
        """Sign a public SSH key using Vault SSH secrets engine."""
        client = cls.get_client()
        role = current_app.config["VAULT_SSH_ROLE"]
        mount = current_app.config["VAULT_SSH_MOUNT"]

        response = client.write(
            f"{mount}/sign/{role}",
            public_key=public_key,
            valid_principals=valid_principals,
            ttl=ttl,
        )
        return response["data"]["signed_key"]

    # ------------------------------------------------------------------ Health

    @classmethod
    def health(cls) -> dict:
        """Check Vault connectivity and auth status."""
        try:
            client = cls.get_client()
            status = client.sys.read_health_status(method="GET")
            return {
                "connected": True,
                "initialized": status.get("initialized", False),
                "sealed": status.get("sealed", True),
                "authenticated": client.is_authenticated(),
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}
