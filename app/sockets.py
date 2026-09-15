"""
app/sockets.py - Web SSH Terminal logic
"""
import io
import time
import gevent
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

def get_vault_client():
    vault_addr = current_app.config.get("VAULT_ADDR")
    vault_token = current_app.config.get("VAULT_TOKEN")
    return VaultClient(vault_addr, vault_token)

def proxy_ssh_output(sid, chan):
    """Background task to read from SSH channel and send to WebSocket."""
    try:
        while not chan.exit_status_ready():
            if chan.recv_ready():
                data = chan.recv(4096)
                if data:
                    socketio.emit("terminal_output", data.decode("utf-8", "replace"), to=sid)
            else:
                gevent.sleep(0.01)
                
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
    except Exception as e:
        emit("terminal_output", f"Authentication failed: {str(e)}\r\n")
        return
        
    emit("terminal_output", f"Authenticating and fetching secret '{slug}'...\r\n")
    
    # 2. Fetch secret from Vault
    try:
        vault = get_vault_client()
        raw_secret = vault.get_secret("servers", slug)
        if not raw_secret:
            emit("terminal_output", "Secret not found.\r\n")
            return
            
        secret = raw_secret.get("data", {})
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
    
    # 3. Establish SSH Connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if auth_type == "ssh_key":
            priv_key = secret.get("ssh_private_key")
            if not priv_key:
                emit("terminal_output", "Missing SSH private key.\r\n")
                return
            key_file = io.StringIO(priv_key)
            # Try RSA first, fallback to Ed25519/ECDSA could be added if needed
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(hostname=host, port=port, username=username, pkey=pkey, timeout=10)
        else:
            password = secret.get("password")
            ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10)
            
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
