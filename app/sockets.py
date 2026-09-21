"""
app/sockets.py - Web SSH Terminal logic
"""
import io
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

@socketio.on("connect")
def on_connect():
    pass # Wait for start_terminal event to auth

@socketio.on("start_terminal")
def on_start_terminal(data):
    sid = request.sid
    token = data.get("token")
    slug = data.get("slug")
    
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
        
    emit("terminal_output", f"Authenticating and fetching secret '{slug}'...\r\n")
    
    # 2. Fetch secret from Vault
    try:
        secret = VaultClient.kv_read(f"servers/{owner}/{slug}")
        if not secret:
            emit("terminal_output", "Secret not found.\r\n")
            return
    except Exception as e:
        emit("terminal_output", f"Vault error: {str(e)}\r\n")
        return
        
    host = secret.get("host")
    port = int(secret.get("port", 22))
    username = secret.get("username")
    auth_type = secret.get("auth_type", "password")
    
    if not host or not username:
        emit("terminal_output", "Invalid secret: missing host or username.\r\n")
        return
        
    emit("terminal_output", f"Connecting to {username}@{host}:{port}...\r\n")
    
    app = current_app._get_current_object()
    
    # 3. Establish SSH Connection
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
                        # Fallback to interactive
                        def handler(title, instructions, prompt_list):
                            answers = []
                            with app.app_context():
                                for pr, show_input in prompt_list:
                                    pr_lower = pr.lower()
                                    if 'password' in pr_lower:
                                        answers.append(password)
                                    elif 'verification' in pr_lower or 'code' in pr_lower or 'otp' in pr_lower or 'token' in pr_lower:
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
    
    try:
        if auth_type == "ssh_key":
            priv_key = secret.get("ssh_private_key")
            if not priv_key:
                emit("terminal_output", "Missing SSH private key.\r\n")
                return
            key_file = io.StringIO(priv_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(hostname=host, port=port, username=username, pkey=pkey, timeout=10, allow_agent=False, look_for_keys=False)
        else:
            password = secret.get("password")
            ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, allow_agent=False, look_for_keys=False)
            
        chan = ssh.invoke_shell(term="xterm-256color")
        chan.setblocking(0)
        
        # Save session
        active_ssh_clients[sid] = ssh
        active_channels[sid] = chan
        
        # Start background reader
        socketio.start_background_task(proxy_ssh_output, sid, chan)
        
    except paramiko.AuthenticationException:
        emit("terminal_output", "SSH Authentication Failed.\r\n")
    except Exception as e:
        emit("terminal_output", f"SSH Error: {str(e)}\r\n")

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
        guac = GuacamoleClient(host='127.0.0.1', port=4822)
        guac.connect()
        kwargs = {
            'hostname': host,
            'port': port,
            'username': username,
            'domain': domain,
            'password': password,
            'ignore-cert': 'true',
            'security': 'nla',
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
    chan = active_channels.pop(sid, None)
    if chan:
        try:
            chan.close()
        except:
            pass
    ssh = active_ssh_clients.pop(sid, None)
    if ssh:
        try:
            ssh.close()
        except:
            pass
    guac = active_guac_clients.pop(sid, None)
    if guac:
        try:
            guac.close()
        except:
            pass

@socketio.on("client_log")
def on_client_log(msg):
    from flask import current_app
    current_app.logger.error(f"[CLIENT LOG from {request.sid}]: {msg}")
    print(f"[CLIENT LOG from {request.sid}]: {msg}")
