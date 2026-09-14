"""
app/routes/ssh.py - SSH certificate signing via HashiCorp Vault SSH secrets engine.
Enhanced version of the original vault_ssh_api.py with auth, audit logging, and cleanup.
"""
import os
import uuid
import subprocess
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, send_file, make_response, current_app, g
from app.middleware.auth_guard import require_auth
from app.models.audit_log import AuditLog
from app.utils.vault_client import VaultClient
from app.extensions import limiter

ssh_bp = Blueprint("ssh", __name__, url_prefix="/api/v1/ssh")


def _ip():
    xff = request.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else request.remote_addr


def _get_download_dir() -> str:
    d = current_app.config.get("SSH_DOWNLOAD_DIR", "/tmp/vault_keys")
    os.makedirs(d, exist_ok=True)
    return d


@ssh_bp.route("/sign", methods=["POST"])
@require_auth("ssh:sign")
@limiter.limit("30 per hour")
def sign_ssh_key():
    """
    Generate a new SSH key pair, sign the public key via Vault CA, and return download links.
    ---
    tags:
      - SSH Certificates
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [server, user]
          properties:
            server:
              type: string
              example: "192.168.1.10"
            user:
              type: string
              example: "root"
            ttl:
              type: string
              example: "30m"
              description: Key validity (e.g. 30m, 1h, 4h)
    responses:
      200:
        description: SSH key signed, download links returned
      500:
        description: Vault or keygen error
    """
    data = request.get_json(silent=True) or {}
    server = data.get("server", "").strip()
    user = data.get("user", "").strip()
    ttl = data.get("ttl", "30m").strip()

    if not server or not user:
        return jsonify({"error": "server and user are required"}), 400

    download_dir = _get_download_dir()
    unique_id = str(uuid.uuid4())[:8]
    private_key_path = os.path.join(download_dir, f"{unique_id}_id_rsa")
    public_key_path = private_key_path + ".pub"
    signed_key_path = os.path.join(download_dir, f"{unique_id}_id_rsa-cert.pub")
    tar_path = os.path.join(download_dir, f"{unique_id}_keys.tar.gz")

    try:
        # Generate SSH key pair
        subprocess.run([
            "ssh-keygen", "-q", "-t", "rsa", "-b", "4096",
            "-N", "", "-f", private_key_path
        ], check=True)

        # Read public key
        with open(public_key_path, "r") as f:
            public_key_data = f.read().strip()

        # Sign via Vault
        signed_key = VaultClient.ssh_sign(
            public_key=public_key_data,
            valid_principals=user,
            ttl=ttl,
        )

        # Write signed cert
        with open(signed_key_path, "w") as f:
            f.write(signed_key)

        # Package into tarball
        subprocess.run([
            "tar", "-czf", tar_path, "-C", download_dir,
            os.path.basename(private_key_path),
            os.path.basename(public_key_path),
            os.path.basename(signed_key_path),
        ], check=True)

        base_url = request.host_url.rstrip("/")
        ssh_command = (
            f"ssh -i {os.path.basename(private_key_path)} "
            f"-o CertificateFile={os.path.basename(signed_key_path)} "
            f"{user}@{server}"
        )

        AuditLog.log(
            action="ssh.key_signed",
            user_id=g.current_user.id if g.current_user else None,
            api_key_id=g.current_api_key.id if g.current_api_key else None,
            resource_type="ssh_key",
            resource_id=unique_id,
            ip_address=_ip(),
            details={"server": server, "user": user, "ttl": ttl},
        )

        return jsonify({
            "message": "SSH key pair generated and signed successfully",
            "server": server,
            "user": user,
            "ttl": ttl,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "ssh_command": ssh_command,
            "download_links": {
                "private_key": f"{base_url}/api/v1/ssh/download/{os.path.basename(private_key_path)}",
                "public_key": f"{base_url}/api/v1/ssh/download/{os.path.basename(public_key_path)}",
                "signed_cert": f"{base_url}/api/v1/ssh/download/{os.path.basename(signed_key_path)}",
                "bundle": f"{base_url}/api/v1/ssh/download/{os.path.basename(tar_path)}",
            },
        }), 200

    except subprocess.CalledProcessError as e:
        AuditLog.log(
            action="ssh.key_sign_failed",
            user_id=g.current_user.id if g.current_user else None,
            status="failure",
            ip_address=_ip(),
            details={"error": str(e)},
        )
        return jsonify({"error": "SSH key generation or packaging failed", "details": str(e)}), 500
    except Exception as e:
        AuditLog.log(
            action="ssh.key_sign_failed",
            user_id=g.current_user.id if g.current_user else None,
            status="failure",
            ip_address=_ip(),
            details={"error": str(e)},
        )
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@ssh_bp.route("/sign-existing", methods=["POST"])
@require_auth("ssh:sign")
@limiter.limit("30 per hour")
def sign_existing_key():
    """
    Sign an existing public key (provided by caller) via Vault CA.
    ---
    tags:
      - SSH Certificates
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [public_key, server, user]
          properties:
            public_key:
              type: string
              description: SSH public key content (ssh-rsa AAAA...)
            server:
              type: string
            user:
              type: string
            ttl:
              type: string
              example: "1h"
    responses:
      200:
        description: Signed certificate
    """
    data = request.get_json(silent=True) or {}
    public_key = data.get("public_key", "").strip()
    server = data.get("server", "").strip()
    user = data.get("user", "").strip()
    ttl = data.get("ttl", "1h").strip()

    if not all([public_key, server, user]):
        return jsonify({"error": "public_key, server, and user are required"}), 400

    try:
        signed_key = VaultClient.ssh_sign(
            public_key=public_key,
            valid_principals=user,
            ttl=ttl,
        )

        AuditLog.log(
            action="ssh.existing_key_signed",
            user_id=g.current_user.id if g.current_user else None,
            api_key_id=g.current_api_key.id if g.current_api_key else None,
            resource_type="ssh_key",
            ip_address=_ip(),
            details={"server": server, "user": user, "ttl": ttl},
        )

        return jsonify({
            "message": "Public key signed successfully",
            "server": server,
            "user": user,
            "ttl": ttl,
            "signed_cert": signed_key,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ssh_bp.route("/download/<filename>", methods=["GET"])
@require_auth("ssh:sign")
def download_key(filename: str):
    """
    Download a generated SSH key file.
    ---
    tags:
      - SSH Certificates
    security:
      - Bearer: []
      - ApiKey: []
    parameters:
      - name: filename
        in: path
        type: string
        required: true
    responses:
      200:
        description: File download
      404:
        description: File not found
    """
    # Security: prevent path traversal
    if ".." in filename or "/" in filename:
        return jsonify({"error": "Invalid filename"}), 400

    download_dir = _get_download_dir()
    file_path = os.path.join(download_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found or expired"}), 404

    response = make_response(send_file(file_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response
