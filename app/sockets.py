"""
app/sockets.py - Web SSH Terminal logic
"""
import io
import os
import time
import paramiko
from flask import request
from flask_socketio import emit
from flask_jwt_extended import decode_token
from app.extensions import socketio
from app.utils.vault_client import VaultClient
from flask import current_app

# Store SSH channels mapping request.sid to paramiko channels
active_channels = {}
active_ssh_clients = {}
active_sftp_clients = {}
active_sftp_ssh = {}
session_info = {}
active_guac_clients = {}

def proxy_guac_output(sid, guac_client):
    """Background task to read from guacd and send to WebSocket."""
    import re
    buf = b""
    try:
        while True:
            chunk = guac_client.read(4096)
            if not chunk:
                break
            # Debug: log if it contains sync
            if b"sync," in chunk:
                print(f"[GUACD OUTPUT]: Found sync in chunk of size {len(chunk)}")
            socketio.emit("guac_instruction", chunk, to=sid)
            socketio.sleep(0)  # yield to other greenlets
    except Exception as e:
        print(f"Guacamole read error: {e}")
    finally:
        socketio.emit("guac_state", 5, to=sid)  # CLOSED
        cleanup_session(sid)


def proxy_ssh_output(sid, chan):
    """Background task to read from SSH channel and send to WebSocket."""
    try:
        while not chan.exit_status_ready():
            if chan.recv_ready():
                data = chan.recv(4096)
                if data:
                    socketio.emit("terminal_output", data.decode("utf-8", "replace"), to=sid)
            else:
                socketio.sleep(0.01)
                
        # Send remaining data before exit
        if chan.recv_ready():
            data = chan.recv(4096)
            if data:
                socketio.emit("terminal_output", data.decode("utf-8", "replace"), to=sid)
        socketio.emit("terminal_output", "\r\n\r\n[SSH Connection Closed by Server]\r\n", to=sid)
    except Exception as e:
        socketio.emit("terminal_output", f"\r\n\r\n[Error reading SSH stream: {str(e)}]\r\n", to=sid)
    finally:
        cleanup_session(sid)


def _connect_ssh_client(owner, slug, app, secret=None):
    """Create and connect a Paramiko SSHClient with TOTP 2FA fallback."""
    with app.app_context():
        if secret is None:
            secret = VaultClient.kv_read(f"servers/{owner}/{slug}")
        if not secret:
            raise ValueError(f"Secret not found for '{slug}'")

        host = secret.get("host")
        port = int(secret.get("port", 22))
        username = secret.get("username")
        auth_type = secret.get("auth_type", "password")

        if not host or not username:
            raise ValueError("Invalid secret: missing host or username")

        # Parse command-style username if imported as SSH command (e.g. ssh -p 4422 user@host)
        if username.startswith("ssh "):
            parts = username.split()
            if "-p" in parts:
                p_idx = parts.index("-p")
                if p_idx + 1 < len(parts):
                    try:
                        port = int(parts[p_idx + 1])
                    except Exception:
                        pass
            for part in parts:
                if "@" in part and not part.startswith("-"):
                    u_p, h_p = part.split("@", 1)
                    username = u_p
                    host = h_p
                    break

        class TOTPSSHClient(paramiko.SSHClient):
            def _auth(self, username, password, pkey, *args, **kwargs):
                saved_exception = None
                try:
                    if pkey is not None:
                        self._transport.auth_publickey(username, pkey)
                        return
                    if password is not None:
                        try:
                            self._transport.auth_password(username, password)
                            return
                        except paramiko.AuthenticationException as e:
                            saved_exception = e
                            def handler(title, instructions, prompt_list):
                                answers = []
                                with app.app_context():
                                    for pr, show_input in prompt_list:
                                        pr_lower = pr.lower()
                                        if 'password' in pr_lower:
                                            answers.append(password)
                                        elif any(k in pr_lower for k in ['verification', 'code', 'otp', 'token']):
                                            totp_sec = secret.get("totp_secret")
                                            if totp_sec:
                                                if "-" in totp_sec:
                                                    totp_data = VaultClient.kv_read(f"totp/{owner}/{totp_sec}")
                                                    if totp_data and totp_data.get("secret_key"):
                                                        totp_sec = totp_data["secret_key"]
                                                import pyotp
                                                answers.append(pyotp.TOTP(totp_sec).now())
                                            else:
                                                answers.append("")
                                        else:
                                            answers.append(password)
                                return answers
                            self._transport.auth_interactive(username, handler)
                            return
                except paramiko.AuthenticationException as e:
                    saved_exception = e
                
                if saved_exception is not None:
                    raise saved_exception
                raise paramiko.AuthenticationException("No authentication methods succeeded")

        ssh = TOTPSSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # ── Đọc SSH Config (~/.ssh/config) để hỗ trợ server cũ ──
        # Apply per-host settings: KexAlgorithms, HostKeyAlgorithms, MACs, User
        ssh_cfg_path = os.path.expanduser("~/.ssh/config")
        connect_kwargs = dict(
            hostname=host,
            port=port,
            username=username,
            timeout=12,
            allow_agent=False,
            look_for_keys=False,
        )
        extra_kw = {}
        if os.path.isfile(ssh_cfg_path):
            try:
                cfg = paramiko.SSHConfig()
                with open(ssh_cfg_path) as f:
                    cfg.parse(f)
                hconf = cfg.lookup(host)

                # Merge per-host disabled_algorithms (enable legacy by NOT disabling them)
                kex_extra = []
                key_extra = []
                mac_extra = []
                if "kexalgorithms" in hconf:
                    for algo in hconf["kexalgorithms"].split(","):
                        a = algo.strip().lstrip("+")
                        if a and a not in paramiko.Transport._preferred_kex:
                            kex_extra.append(a)
                if "hostkeyalgorithms" in hconf:
                    for algo in hconf["hostkeyalgorithms"].split(","):
                        a = algo.strip().lstrip("+")
                        if a and a not in paramiko.Transport._preferred_keys:
                            key_extra.append(a)
                if "macs" in hconf:
                    for algo in hconf["macs"].split(","):
                        a = algo.strip().lstrip("+")
                        if a and a not in paramiko.Transport._preferred_mac:
                            mac_extra.append(a)

                if kex_extra or key_extra or mac_extra:
                    extra_kw["disabled_algorithms"] = {
                        # NOTE: paramiko's disabled_algorithms REMOVES from negotiation.
                        # To ADD legacy, we must patch _preferred_* on the Transport AFTER connect.
                        # We'll use the 'passphrase' workaround: inject via connect 'transport_factory'.
                        # Simpler: pre-patch globals before connect.
                    }
                    # Patch paramiko globals to accept legacy algorithms temporarily
                    if kex_extra:
                        paramiko.Transport._preferred_kex = (
                            list(kex_extra) + list(paramiko.Transport._preferred_kex)
                        )
                    if key_extra:
                        paramiko.Transport._preferred_keys = (
                            list(key_extra) + list(paramiko.Transport._preferred_keys)
                        )
                    if mac_extra:
                        paramiko.Transport._preferred_mac = (
                            list(mac_extra) + list(paramiko.Transport._preferred_mac)
                        )
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"SSH config parse error: {e}")

        if auth_type == "ssh_key":
            priv_key = secret.get("ssh_private_key")
            if not priv_key:
                raise ValueError("Missing SSH private key")
            key_file = io.StringIO(priv_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except Exception:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except Exception:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(**connect_kwargs, pkey=pkey)
        else:
            password = secret.get("password")
            ssh.connect(**connect_kwargs, password=password)

        return ssh


def init_sftp_session(sid, owner, slug, app):
    """
    Background task to initialize SFTP client for the given session.
    First tries to open SFTP directly on the primary SSH connection (for direct servers).
    If multiplexing fails (e.g. PAM/proxy closes second channel), establishes a dedicated
    SSH connection specifically for SFTP.
    """
    try:
        with app.app_context():
            # 1. Try multiplexing on the primary SSH connection (direct OpenSSH)
            primary_ssh = active_ssh_clients.get(sid)
            if primary_ssh and primary_ssh.get_transport() and primary_ssh.get_transport().is_active():
                try:
                    sftp = primary_ssh.open_sftp()
                    active_sftp_clients[sid] = sftp
                    socketio.emit("sftp_ready", {"status": "ready"}, to=sid)
                    return sftp
                except Exception:
                    pass

            # 2. Establish dedicated SSH connection for SFTP (PAM / proxy / jump hosts)
            if sid not in session_info:
                return None
            sftp_ssh = _connect_ssh_client(owner, slug, app)
            active_sftp_ssh[sid] = sftp_ssh
            sftp = sftp_ssh.open_sftp()
            active_sftp_clients[sid] = sftp
            socketio.emit("sftp_ready", {"status": "ready"}, to=sid)
            return sftp
    except Exception as e:
        socketio.emit("sftp_error", f"SFTP init failed: {str(e)}", to=sid)
        return None


def get_sftp(sid):
    """
    Retrieve active SFTP client for sid. If not yet initialized or reconnecting,
    waits up to 10 seconds for the background initialization to complete.
    """
    sftp = active_sftp_clients.get(sid)
    if sftp:
        try:
            chan = sftp.get_channel()
            if chan and not chan.closed:
                return sftp
        except Exception:
            pass

    info = session_info.get(sid)
    if not info:
        return None

    app = current_app._get_current_object()
    for _ in range(20):  # 20 * 0.5s = 10s wait
        if sid not in session_info:
            return None
        sftp = active_sftp_clients.get(sid)
        if sftp:
            try:
                chan = sftp.get_channel()
                if chan and not chan.closed:
                    return sftp
            except Exception:
                pass
        socketio.sleep(0.5)

    # Last resort fallback: run init synchronously
    return init_sftp_session(sid, info["owner"], info["slug"], app)


@socketio.on("connect")
def on_connect():
    pass # Wait for start_terminal event to auth


@socketio.on("start_terminal")
def on_start_terminal(data):
    sid = request.sid
    token = data.get("token")
    slug = data.get("slug")
    cols = data.get("cols", 80)
    rows = data.get("rows", 24)
    
    # 1. Verify token manually
    try:
        decoded = decode_token(token)
        user_id = decoded.get("sub")
        from app.models.user import User
        user = User.query.get(user_id)
        if not user:
            emit("terminal_output", "Authentication failed: User not found\r\n")
            return
        owner = user.username
    except Exception as e:
        emit("terminal_output", f"Authentication failed: {str(e)}\r\n")
        return

    # Record session early so SFTP knows which server this session is for
    session_info[sid] = {"owner": owner, "slug": slug}
        
    emit("terminal_output", f"Authenticating and fetching secret '{slug}'...\r\n")
    
    app = current_app._get_current_object()
    
    try:
        ssh = _connect_ssh_client(owner, slug, app)
        chan = ssh.invoke_shell(term="xterm-256color", width=cols, height=rows)
        chan.setblocking(0)
        
        # Save session
        active_ssh_clients[sid] = ssh
        active_channels[sid] = chan
        
        # Start background reader for shell output
        socketio.start_background_task(proxy_ssh_output, sid, chan)

        # Notify frontend that terminal is ready
        emit("terminal_ready", {"slug": slug})

        # Start background task to initialize SFTP client (works for both direct and proxy)
        socketio.start_background_task(init_sftp_session, sid, owner, slug, app)
        
    except paramiko.AuthenticationException:
        emit("terminal_output", "SSH Authentication Failed.\r\n")
        cleanup_session(sid)
    except Exception as e:
        emit("terminal_output", f"SSH Error: {str(e)}\r\n")
        cleanup_session(sid)

@socketio.on("terminal_input")
def on_terminal_input(data):
    sid = request.sid
    chan = active_channels.get(sid)
    if chan and not chan.exit_status_ready():
        try:
            chan.send(data)
        except:
            pass

@socketio.on("terminal_resize")
def on_terminal_resize(data):
    sid = request.sid
    chan = active_channels.get(sid)
    if chan and not chan.exit_status_ready():
        try:
            cols = data.get("cols", 80)
            rows = data.get("rows", 24)
            chan.resize_pty(width=cols, height=rows)
        except:
            pass

@socketio.on("start_rdp")
def on_start_rdp(data):
    sid = request.sid
    token = data.get("token")
    slug = data.get("slug")
    width = data.get("width", 1024)
    height = data.get("height", 768)
    
    try:
        decoded = decode_token(token)
        user_id = decoded.get("sub")
        from app.models.user import User
        user = User.query.get(user_id)
        if not user:
            emit("guac_state", 4) # ERROR
            return
        owner = user.username
        
        secret = VaultClient.kv_read(f"servers/{owner}/{slug}")
        if not secret:
            emit("guac_state", 4)
            return
            
        host = secret.get("host")
        port = int(secret.get("port", 3389))
        username = secret.get("username", "")
        domain = ""
        if "\\" in username:
            domain, username = username.split("\\", 1)
            
        password = secret.get("password", "")
        
        from app.utils.guac_client import GuacamoleClient
        import os
        guacd_host = current_app.config.get("GUACD_HOST", os.getenv("GUACD_HOST", "guacd"))
        guacd_port = int(current_app.config.get("GUACD_PORT", os.getenv("GUACD_PORT", 4822)))
        guac = GuacamoleClient(host=guacd_host, port=guacd_port)
        guac.connect()
        kwargs = {
            'hostname': host,
            'port': port,
            'username': username,
            'domain': domain,
            'password': password,
            'ignore-cert': 'true',
            'security': secret.get('security', 'any'),
            'width': width,
            'height': height,
            'color-depth': '32'
        }
        conn_id = guac.handshake("rdp", **kwargs)
        
        # Send synthesized ready instruction to JS client
        ready_inst = f"5.ready,{len(conn_id)}.{conn_id};"
        emit("guac_instruction", ready_inst.encode('utf-8'))
        
        emit("guac_state", 1) # Guacamole.Tunnel.State.OPEN
        active_guac_clients[sid] = guac
        socketio.start_background_task(proxy_guac_output, sid, guac)
        
    except Exception as e:
        import traceback
        current_app.logger.error(f"RDP Start Error: {e}\n{traceback.format_exc()}")
        print(f"RDP Start Error: {e}")
        emit("guac_state", 4)

@socketio.on("guac_input")
def on_guac_input(data):
    sid = request.sid
    print(f"[GUAC INPUT from {sid}]: {data}")
    guac = active_guac_clients.get(sid)
    if guac:
        try:
            guac.write(data)
        except Exception as e:
            print(f"[GUAC INPUT ERROR]: {e}")

@socketio.on("stop_rdp")
def on_stop_rdp():
    cleanup_session(request.sid)

@socketio.on("disconnect")
def on_disconnect():
    cleanup_session(request.sid)

def cleanup_session(sid):
    session_info.pop(sid, None)
    chan = active_channels.pop(sid, None)
    if chan:
        try:
            chan.close()
        except Exception:
            pass
    ssh = active_ssh_clients.pop(sid, None)
    if ssh:
        try:
            ssh.close()
        except Exception:
            pass
    sftp = active_sftp_clients.pop(sid, None)
    if sftp:
        try:
            sftp.close()
        except Exception:
            pass
    sftp_ssh = active_sftp_ssh.pop(sid, None)
    if sftp_ssh:
        try:
            sftp_ssh.close()
        except Exception:
            pass
    guac = active_guac_clients.pop(sid, None)
    if guac:
        try:
            guac.close()
        except Exception:
            pass

@socketio.on("client_log")
def on_client_log(msg):
    from flask import current_app
    current_app.logger.error(f"[CLIENT LOG from {request.sid}]: {msg}")
    print(f"[CLIENT LOG from {request.sid}]: {msg}")


# ─── SFTP File Browser ──────────────────────────────────────────────────────

def _sftp_rmtree(sftp, remote_path):
    """Recursively remove a directory on remote SFTP server."""
    import stat
    for item in sftp.listdir_attr(remote_path):
        item_path = remote_path.rstrip("/") + "/" + item.filename
        if stat.S_ISDIR(item.st_mode):
            _sftp_rmtree(sftp, item_path)
        else:
            sftp.remove(item_path)
    sftp.rmdir(remote_path)


@socketio.on("sftp_ls")
def on_sftp_ls(data):
    """List directory contents via SFTP."""
    sid = request.sid
    sftp = get_sftp(sid)
    if not sftp:
        emit("sftp_error", "No active SSH session or SFTP not available")
        return
    path = data.get("path", ".")
    try:
        # Normalize relative path (e.g. '.' -> '/home/user')
        try:
            resolved = sftp.normalize(path)
        except Exception:
            resolved = path

        entries = []
        for attr in sftp.listdir_attr(resolved):
            import stat
            is_dir = stat.S_ISDIR(attr.st_mode)
            entries.append({
                "name": attr.filename,
                "is_dir": is_dir,
                "size": attr.st_size,
                "mtime": attr.st_mtime,
            })
        # Sort: dirs first, then files, both alphabetically
        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        emit("sftp_ls_result", {"path": resolved, "entries": entries})
    except Exception as e:
        emit("sftp_error", f"ls failed: {str(e)}")


@socketio.on("sftp_download")
def on_sftp_download(data):
    """Download a file from the remote server via SFTP."""
    import base64
    sid = request.sid
    sftp = get_sftp(sid)
    if not sftp:
        emit("sftp_error", "No active SSH session")
        return
    remote_path = data.get("path", "")
    try:
        buf = io.BytesIO()
        sftp.getfo(remote_path, buf)
        content_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        filename = remote_path.split("/")[-1]
        emit("sftp_download_result", {
            "filename": filename,
            "content_b64": content_b64,
            "mime": "application/octet-stream"
        })
    except Exception as e:
        emit("sftp_error", f"download failed: {str(e)}")


@socketio.on("sftp_upload")
def on_sftp_upload(data):
    """Upload a file to the remote server via SFTP."""
    import base64
    sid = request.sid
    sftp = get_sftp(sid)
    if not sftp:
        emit("sftp_error", "No active SSH session")
        return
    remote_dir = data.get("path", "/tmp")
    filename = data.get("filename", "upload")
    content_b64 = data.get("content_b64", "")
    try:
        content = base64.b64decode(content_b64)
        remote_path = remote_dir.rstrip("/") + "/" + filename
        with sftp.open(remote_path, "wb") as f:
            f.write(content)
        emit("sftp_upload_result", {"path": remote_path, "success": True})
    except Exception as e:
        emit("sftp_error", f"upload failed: {str(e)}")


@socketio.on("sftp_mkdir")
def on_sftp_mkdir(data):
    """Create a directory via SFTP."""
    sid = request.sid
    sftp = get_sftp(sid)
    if not sftp:
        emit("sftp_error", "No active SSH session")
        return
    path = data.get("path", "")
    try:
        sftp.mkdir(path)
        emit("sftp_mkdir_result", {"path": path, "success": True})
    except Exception as e:
        emit("sftp_error", f"mkdir failed: {str(e)}")


@socketio.on("sftp_rm")
def on_sftp_rm(data):
    """Remove a file or directory via SFTP."""
    sid = request.sid
    sftp = get_sftp(sid)
    if not sftp:
        emit("sftp_error", "No active SSH session")
        return
    path = data.get("path", "")
    is_dir = data.get("is_dir", False)
    try:
        if is_dir:
            _sftp_rmtree(sftp, path)
        else:
            sftp.remove(path)
        emit("sftp_rm_result", {"path": path, "success": True})
    except Exception as e:
        emit("sftp_error", f"rm failed: {str(e)}")


# ─── Terminal Remote Monitoring ─────────────────────────────────────────────

@socketio.on("terminal_metrics")
def on_terminal_metrics(data=None):
    """Fetch live system metrics (CPU, RAM, DISK, Network, Uptime) for terminal session."""
    sid = request.sid
    info = session_info.get(sid)
    if not info:
        emit("terminal_metrics_error", "No active terminal session")
        return
    owner = info.get("owner")
    slug = info.get("slug")
    from app.utils.monitoring import collect_server_metrics
    try:
        metrics = collect_server_metrics(owner, slug)
        emit("terminal_metrics_result", metrics)
    except Exception as e:
        emit("terminal_metrics_error", str(e))

