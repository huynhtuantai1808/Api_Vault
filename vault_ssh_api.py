from flask import Flask, request, jsonify, send_file, make_response
from flasgger import Swagger
import subprocess
import tempfile
import os
import hvac
import uuid
import shutil

app = Flask(__name__)
swagger = Swagger(app)

# === Config Vault ===
VAULT_ADDR = ""
VAULT_TOKEN = ""
VAULT_SSH_ROLE = ""

client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

DOWNLOAD_DIR = "/tmp/vault_keys"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


@app.route('/sign', methods=['GET'])
def sign_ssh_key():
    """
    Generate, sign SSH key pair using Vault SSH CA, and auto-download
    ---
    parameters:
      - name: server
        in: query
        type: string
        required: true
        description: Target SSH server IP or hostname
      - name: user
        in: query
        type: string
        required: true
        description: SSH username
      - name: ttl
        in: query
        type: string
        required: false
        default: "30m"
        description: Validity period for signed key (e.g. 30m, 1h)
    responses:
      200:
        description: Signed SSH key and download links
    """
    server = request.args.get("server")
    user = request.args.get("user")
    ttl = request.args.get("ttl", "30m")

    if not server or not user:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        # === Unique key filenames ===
        unique_id = str(uuid.uuid4())[:8]
        private_key_path = os.path.join(DOWNLOAD_DIR, f"{unique_id}_id_rsa")
        public_key_path = private_key_path + ".pub"

        # === Cleanup old file ===
        for f in [private_key_path, public_key_path]:
            if os.path.exists(f):
                os.remove(f)

        # === Generate SSH key pair ===
        subprocess.run([
            "ssh-keygen", "-q", "-t", "rsa", "-b", "4096",
            "-N", "", "-f", private_key_path
        ], check=True)

        # === Read public key ===
        with open(public_key_path, "r") as f:
            public_key_data = f.read().strip()

        # === Sign key using Vault ===
        sign_response = client.write(
            f"ssh/sign/{VAULT_SSH_ROLE}",
            public_key=public_key_data,
            valid_principals=user,
            ttl=ttl
        )

        signed_key = sign_response["data"]["signed_key"]

        signed_key_path = os.path.join(DOWNLOAD_DIR, f"{unique_id}_id_rsa-signed.pub")
        with open(signed_key_path, "w") as f:
            f.write(signed_key)

        # === Prepare SSH command ===
        ssh_command = f"ssh -i {os.path.basename(private_key_path)} -o CertificateFile={os.path.basename(signed_key_path)} {user}@{server}"

        # === Auto-download both files ===
        # Combine both key files into a tarball for one-click download
        tar_path = os.path.join(DOWNLOAD_DIR, f"{unique_id}_keys.tar.gz")
        subprocess.run(["tar", "-czf", tar_path, "-C", DOWNLOAD_DIR,
                        os.path.basename(private_key_path),
                        os.path.basename(signed_key_path)], check=True)

        base_url = request.host_url.rstrip('/')

        return jsonify({
            "message": "SSH key pair generated and signed successfully",
            "server": server,
            "user": user,
            "ttl": ttl,
            "ssh_command": ssh_command,
            "download_links": {
                "private_key": f"{base_url}/download/{os.path.basename(private_key_path)}",
                "signed_key": f"{base_url}/download/{os.path.basename(signed_key_path)}",
                "bundle": f"{base_url}/download/{os.path.basename(tar_path)}"
            }
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "SSH key generation or packaging failed", "details": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@app.route("/download/<filename>", methods=["GET"])
def download_key(filename):
    """
    Download generated/signed SSH key or bundle
    ---
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: Filename to download
    responses:
      200:
        description: File content
    """
    file_path = os.path.join(DOWNLOAD_DIR, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    response = make_response(send_file(file_path, as_attachment=True))
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5055)
