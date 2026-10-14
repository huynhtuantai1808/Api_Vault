"""
app/utils/monitoring.py - Remote server metrics collection via SSH.
Gathers CPU, RAM, DISK, Network, Uptime, and Host/OS info with zero remote dependencies.
Supports both Linux (via /proc filesystem & POSIX tools) and Windows (via PowerShell / OpenSSH).
Gracefully detects Windows RDP-only servers and provides actionable OpenSSH activation guidance.
"""
import io
import time
import socket
import logging
from flask import current_app

logger = logging.getLogger(__name__)

# Linux metrics command: 100% POSIX + /proc filesystem (no Python / third-party tools needed)
METRICS_COMMAND = '''sh -c "
echo '<<<UPTIME>>>'
cat /proc/uptime 2>/dev/null || uptime
echo '<<<UNAME>>>'
uname -s -r -m
echo '<<<HOSTNAME>>>'
hostname 2>/dev/null || cat /proc/sys/kernel/hostname
echo '<<<LOAD>>>'
cat /proc/loadavg 2>/dev/null
echo '<<<CPU_CORES>>>'
grep -c ^processor /proc/cpuinfo 2>/dev/null || nproc 2>/dev/null || echo 1
echo '<<<CPU_STAT1>>>'
grep '^cpu ' /proc/stat 2>/dev/null
sleep 0.3
echo '<<<CPU_STAT2>>>'
grep '^cpu ' /proc/stat 2>/dev/null
echo '<<<MEM>>>'
cat /proc/meminfo 2>/dev/null
echo '<<<DISK>>>'
df -kP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -kP
echo '<<<NET>>>'
cat /proc/net/dev 2>/dev/null
"'''

# Windows metrics command: executed via OpenSSH on Windows using PowerShell CIM instances
WINDOWS_METRICS_COMMAND = '''powershell -NoProfile -NonInteractive -Command "
Write-Output '<<<UPTIME>>>'
try { [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds) } catch { 0 }
Write-Output '<<<HOSTNAME>>>'
hostname
Write-Output '<<<OS>>>'
try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Windows' }
Write-Output '<<<CPU>>>'
try { [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1) } catch { 0 }
Write-Output '<<<CPU_CORES>>>'
try { (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors } catch { 1 }
Write-Output '<<<MEM>>>'
try {
  $os = Get-CimInstance Win32_OperatingSystem
  $tot = [math]::Round($os.TotalVisibleMemorySize / 1024, 1)
  $fre = [math]::Round($os.FreePhysicalMemory / 1024, 1)
  Write-Output \"$tot $fre\"
} catch {}
Write-Output '<<<DISK>>>'
try {
  Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $sz = [math]::Round($_.Size / 1GB, 1)
    $fr = [math]::Round($_.FreeSpace / 1GB, 1)
    Write-Output \"$($_.DeviceID) $sz $fr\"
  }
} catch {}
Write-Output '<<<NET>>>'
try {
  Get-NetAdapterStatistics | ForEach-Object {
    Write-Output \"$($_.Name): $($_.ReceivedBytes) $($_.SentBytes)\"
  }
} catch {}
"'''


def _human_bytes(b: int) -> str:
    """Format bytes to human readable string (B, KB, MB, GB, TB)."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024**3:
        return f"{b / (1024**2):.1f} MB"
    elif b < 1024**4:
        return f"{b / (1024**3):.2f} GB"
    return f"{b / (1024**4):.2f} TB"


def parse_metrics_output(raw: str) -> dict:
    """Parse output of METRICS_COMMAND into structured JSON for Linux."""
    sections = {}
    current_key = None
    for line in raw.splitlines():
        line_s = line.strip()
        if line_s.startswith("<<<") and line_s.endswith(">>>"):
            current_key = line_s.strip("<> \r")
            sections[current_key] = []
        elif current_key is not None:
            sections[current_key].append(line)

    # 1. Uptime
    uptime_sec = 0
    uptime_str = "—"
    up_lines = sections.get("UPTIME", [])
    if up_lines:
        try:
            uptime_sec = int(float(up_lines[0].split()[0]))
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            mins = (uptime_sec % 3600) // 60
            parts = []
            if days > 0:
                parts.append(f"{days}d")
            if hours > 0 or days > 0:
                parts.append(f"{hours}h")
            parts.append(f"{mins}m")
            uptime_str = " ".join(parts)
        except Exception:
            pass

    # 2. Hostname & OS
    os_info = "Linux"
    uname_lines = sections.get("UNAME", [])
    if uname_lines:
        os_info = uname_lines[0].strip()

    hostname = "unknown"
    h_lines = sections.get("HOSTNAME", [])
    if h_lines:
        hostname = h_lines[0].strip()

    # 3. CPU (instantaneous calculation from 0.3s sample)
    cpu_percent = 0.0
    s1_lines = sections.get("CPU_STAT1", [])
    s2_lines = sections.get("CPU_STAT2", [])
    if s1_lines and s2_lines:
        try:
            p1 = [int(x) for x in s1_lines[0].split()[1:]]
            p2 = [int(x) for x in s2_lines[0].split()[1:]]
            idle1 = p1[3] + (p1[4] if len(p1) > 4 else 0)
            idle2 = p2[3] + (p2[4] if len(p2) > 4 else 0)
            total1 = sum(p1)
            total2 = sum(p2)
            d_total = total2 - total1
            d_idle = idle2 - idle1
            if d_total > 0:
                cpu_percent = round((1.0 - (d_idle / d_total)) * 100.0, 1)
                cpu_percent = max(0.0, min(100.0, cpu_percent))
        except Exception:
            pass

    cores = 1
    c_lines = sections.get("CPU_CORES", [])
    if c_lines:
        try:
            cores = int(c_lines[0].strip())
        except Exception:
            pass

    load = [0.0, 0.0, 0.0]
    l_lines = sections.get("LOAD", [])
    if l_lines:
        try:
            parts = l_lines[0].split()
            load = [float(parts[0]), float(parts[1]), float(parts[2])]
        except Exception:
            pass

    # 4. Memory
    mem_total_kb = 0
    mem_avail_kb = 0
    mem_free_kb = 0
    swap_total_kb = 0
    swap_free_kb = 0
    for line in sections.get("MEM", []):
        flds = line.split(":")
        if len(flds) == 2:
            k = flds[0].strip()
            v_val = flds[1].strip().split()[0]
            try:
                v = int(v_val)
                if k == "MemTotal":
                    mem_total_kb = v
                elif k == "MemAvailable":
                    mem_avail_kb = v
                elif k == "MemFree":
                    mem_free_kb = v
                elif k == "SwapTotal":
                    swap_total_kb = v
                elif k == "SwapFree":
                    swap_free_kb = v
            except Exception:
                pass

    if mem_avail_kb == 0:
        mem_avail_kb = mem_free_kb
    mem_used_kb = max(0, mem_total_kb - mem_avail_kb)
    mem_pct = round((mem_used_kb / mem_total_kb) * 100.0, 1) if mem_total_kb > 0 else 0.0

    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_pct = round((swap_used_kb / swap_total_kb) * 100.0, 1) if swap_total_kb > 0 else 0.0

    # 5. Disk Partitions
    disks = []
    disk_lines = sections.get("DISK", [])
    if disk_lines:
        for line in disk_lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                try:
                    size_kb = int(parts[1])
                    used_kb = int(parts[2])
                    avail_kb = int(parts[3])
                    pct = int(parts[4].replace("%", ""))
                    disks.append({
                        "filesystem": parts[0],
                        "mount": parts[5],
                        "size_gb": round(size_kb / (1024 * 1024), 1),
                        "used_gb": round(used_kb / (1024 * 1024), 1),
                        "avail_gb": round(avail_kb / (1024 * 1024), 1),
                        "percent": pct
                    })
                except Exception:
                    pass

    # 6. Network
    net_interfaces = []
    net_lines = sections.get("NET", [])
    if len(net_lines) > 2:
        for line in net_lines[2:]:
            if ":" in line:
                iface, stats = line.split(":", 1)
                iface = iface.strip()
                if iface != "lo":
                    flds = stats.split()
                    if len(flds) >= 9:
                        try:
                            rx = int(flds[0])
                            tx = int(flds[8])
                            net_interfaces.append({
                                "interface": iface,
                                "rx_bytes": rx,
                                "tx_bytes": tx,
                                "rx_human": _human_bytes(rx),
                                "tx_human": _human_bytes(tx)
                            })
                        except Exception:
                            pass

    return {
        "status": "online",
        "hostname": hostname,
        "os": os_info,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "cpu": {
            "percent": cpu_percent,
            "cores": cores,
            "load": load
        },
        "memory": {
            "total_gb": round(mem_total_kb / (1024 * 1024), 2),
            "used_gb": round(mem_used_kb / (1024 * 1024), 2),
            "free_gb": round(mem_avail_kb / (1024 * 1024), 2),
            "percent": mem_pct,
            "swap_total_gb": round(swap_total_kb / (1024 * 1024), 2),
            "swap_used_gb": round(swap_used_kb / (1024 * 1024), 2),
            "swap_percent": swap_pct
        },
        "disk": disks,
        "network": net_interfaces,
        "collected_at": int(time.time())
    }


def parse_windows_metrics(raw: str) -> dict:
    """Parse output of WINDOWS_METRICS_COMMAND into structured JSON."""
    sections = {}
    current_key = None
    for line in raw.splitlines():
        line_s = line.strip()
        if line_s.startswith("<<<") and line_s.endswith(">>>"):
            current_key = line_s.strip("<> \r")
            sections[current_key] = []
        elif current_key is not None and line_s:
            sections[current_key].append(line_s)

    # 1. Uptime
    uptime_sec = 0
    uptime_str = "—"
    up_lines = sections.get("UPTIME", [])
    if up_lines:
        try:
            uptime_sec = int(float(up_lines[0].split()[0]))
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            mins = (uptime_sec % 3600) // 60
            parts = []
            if days > 0:
                parts.append(f"{days}d")
            if hours > 0 or days > 0:
                parts.append(f"{hours}h")
            parts.append(f"{mins}m")
            uptime_str = " ".join(parts)
        except Exception:
            pass

    # 2. Hostname & OS
    hostname = sections.get("HOSTNAME", ["Windows Server"])[0] if sections.get("HOSTNAME") else "Windows Server"
    os_info = sections.get("OS", ["Windows Server"])[0] if sections.get("OS") else "Windows Server"

    # 3. CPU
    cpu_percent = 0.0
    cpu_lines = sections.get("CPU", [])
    if cpu_lines:
        try:
            cpu_percent = round(float(cpu_lines[0]), 1)
        except Exception:
            pass

    cores = 1
    cores_lines = sections.get("CPU_CORES", [])
    if cores_lines:
        try:
            cores = int(cores_lines[0])
        except Exception:
            pass

    # 4. Memory
    mem_total_gb = 0.0
    mem_used_gb = 0.0
    mem_pct = 0.0
    mem_lines = sections.get("MEM", [])
    if mem_lines:
        try:
            flds = mem_lines[0].split()
            if len(flds) >= 2:
                tot_mb = float(flds[0])
                fre_mb = float(flds[1])
                used_mb = max(0.0, tot_mb - fre_mb)
                mem_total_gb = round(tot_mb / 1024, 2)
                mem_used_gb = round(used_mb / 1024, 2)
                if tot_mb > 0:
                    mem_pct = round((used_mb / tot_mb) * 100, 1)
        except Exception:
            pass

    # 5. Disks
    disks = []
    disk_lines = sections.get("DISK", [])
    for d_line in disk_lines:
        parts = d_line.split()
        if len(parts) >= 3:
            try:
                mount = parts[0]
                sz_gb = float(parts[1])
                fr_gb = float(parts[2])
                used_gb = round(max(0.0, sz_gb - fr_gb), 1)
                pct = round((used_gb / sz_gb) * 100) if sz_gb > 0 else 0
                disks.append({
                    "mount": mount,
                    "filesystem": "NTFS",
                    "size_gb": sz_gb,
                    "used_gb": used_gb,
                    "avail_gb": fr_gb,
                    "percent": pct
                })
            except Exception:
                pass

    # 6. Network
    net_interfaces = []
    net_lines = sections.get("NET", [])
    for n_line in net_lines:
        if ":" in n_line:
            iface, stats = n_line.split(":", 1)
            parts = stats.split()
            if len(parts) >= 2:
                try:
                    rx = int(parts[0])
                    tx = int(parts[1])
                    net_interfaces.append({
                        "interface": iface.strip(),
                        "rx_bytes": rx,
                        "tx_bytes": tx,
                        "rx_human": _human_bytes(rx),
                        "tx_human": _human_bytes(tx)
                    })
                except Exception:
                    pass

    return {
        "status": "online",
        "os_type": "windows",
        "hostname": hostname,
        "os": os_info,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "cpu": {
            "percent": cpu_percent,
            "cores": cores,
            "load": [round(cpu_percent / 100.0, 2), 0.0, 0.0]
        },
        "memory": {
            "total_gb": mem_total_gb,
            "used_gb": mem_used_gb,
            "free_gb": round(max(0.0, mem_total_gb - mem_used_gb), 2),
            "percent": mem_pct,
            "swap_total_gb": 0,
            "swap_used_gb": 0,
            "swap_percent": 0
        },
        "disk": disks,
        "network": net_interfaces,
        "collected_at": int(time.time())
    }


def collect_server_metrics(owner: str, slug: str, app_obj=None) -> dict:
    """Connect to the server via SSH and execute the metrics command (Linux or Windows)."""
    from app.sockets import _connect_ssh_client
    from app.utils.vault_client import VaultClient
    app = app_obj or current_app._get_current_object()

    with app.app_context():
        secret = VaultClient.kv_read(f"servers/{owner}/{slug}")
        if not secret:
            raise ValueError(f"Secret not found for '{slug}'")

    os_type = (secret.get("os_type") or "linux").lower()
    host = secret.get("host")
    port = int(secret.get("port") or (3389 if os_type == "windows" else 22))

    # ──────── WINDOWS SERVERS HANDLING ────────
    if os_type == "windows":
        target_ssh_port = None

        # Check if custom port is an active SSH port (non-3389)
        if port != 3389:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                s.connect((host, port))
                target_ssh_port = port
            except Exception:
                pass
            finally:
                s.close()

        # If port is 3389 or custom port wasn't reachable, check standard SSH port 22
        if not target_ssh_port:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(1.5)
            try:
                s2.connect((host, 22))
                target_ssh_port = 22
            except Exception:
                pass
            finally:
                s2.close()

        # If OpenSSH is not running on the Windows server:
        if not target_ssh_port:
            return {
                "status": "unsupported",
                "os_type": "windows",
                "hostname": secret.get("name") or slug,
                "host": host,
                "port": port,
                "protocol": "RDP (Cổng 3389)",
                "uptime": "N/A (RDP)",
                "os": "Windows Server",
                "message": f"Máy chủ Windows ({host}) hiện đang kết nối qua cổng RDP {port}. Giao thức RDP chỉ hỗ trợ giao diện đồ họa (Remote Desktop), không mở giao diện thu thập chỉ số phần cứng từ xa.",
                "guide": (
                    "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n"
                    "Start-Service sshd\n"
                    "Set-Service -Name sshd -StartupType 'Automatic'\n"
                    "New-NetFirewallRule -Name 'OpenSSH-Server' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
                ),
                "collected_at": int(time.time())
            }

        # If SSH is open on Windows (e.g. port 22), connect and run PowerShell commands
        secret_ssh = dict(secret)
        secret_ssh["port"] = target_ssh_port
        try:
            ssh = _connect_ssh_client(owner, slug, app, secret=secret_ssh)
            try:
                stdin, stdout, stderr = ssh.exec_command(WINDOWS_METRICS_COMMAND, timeout=12)
                raw = stdout.read().decode("utf-8", "replace")
                err = stderr.read().decode("utf-8", "replace")
                if not raw and err:
                    raise RuntimeError(f"Command error: {err}")
                return parse_windows_metrics(raw)
            finally:
                try:
                    ssh.close()
                except Exception:
                    pass
        except Exception as e:
            return {
                "status": "unsupported",
                "os_type": "windows",
                "hostname": secret.get("name") or slug,
                "host": host,
                "port": port,
                "protocol": "RDP",
                "uptime": "N/A (RDP)",
                "os": "Windows Server",
                "message": f"Không thể lấy chỉ số từ máy chủ Windows qua SSH: {str(e)}",
                "guide": (
                    "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n"
                    "Start-Service sshd\n"
                    "Set-Service -Name sshd -StartupType 'Automatic'"
                ),
                "collected_at": int(time.time())
            }

    # ──────── LINUX SERVERS HANDLING ────────
    ssh = _connect_ssh_client(owner, slug, app)
    try:
        stdin, stdout, stderr = ssh.exec_command(METRICS_COMMAND, timeout=12)
        raw = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        if not raw and err:
            raise RuntimeError(f"Command error: {err}")
        return parse_metrics_output(raw)
    finally:
        try:
            ssh.close()
        except Exception:
            pass
