"""
app/utils/monitoring.py - Remote server metrics collection via SSH.
Gathers CPU, RAM, DISK, Network, Uptime, and Host/OS info with zero remote dependencies.
"""
import io
import time
import logging
from flask import current_app

logger = logging.getLogger(__name__)

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
    """Parse output of METRICS_COMMAND into structured JSON."""
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
            if days > 0:
                uptime_str = f"{days}d {hours}h {mins}m"
            else:
                uptime_str = f"{hours}h {mins}m"
        except Exception:
            uptime_str = up_lines[0].strip()

    # 2. Hostname & OS
    hostname = sections.get("HOSTNAME", ["unknown"])[0].strip() if sections.get("HOSTNAME") else "unknown"
    os_info = sections.get("UNAME", ["Linux"])[0].strip() if sections.get("UNAME") else "Linux"

    # 3. CPU Cores & Load
    cores = 1
    try:
        cores = int(sections.get("CPU_CORES", ["1"])[0].strip())
    except Exception:
        pass

    load = [0.0, 0.0, 0.0]
    load_lines = sections.get("LOAD", [])
    if load_lines:
        parts = load_lines[0].split()
        if len(parts) >= 3:
            try:
                load = [float(parts[0]), float(parts[1]), float(parts[2])]
            except Exception:
                pass

    # CPU Percentage from STAT1 and STAT2
    cpu_percent = 0.0
    stat1 = sections.get("CPU_STAT1", [])
    stat2 = sections.get("CPU_STAT2", [])
    if stat1 and stat2:
        try:
            f1 = [float(x) for x in stat1[0].split()[1:]]
            f2 = [float(x) for x in stat2[0].split()[1:]]
            delta_total = sum(f2) - sum(f1)
            delta_idle = f2[3] - f1[3]
            if delta_total > 0:
                cpu_percent = round((1.0 - (delta_idle / delta_total)) * 100.0, 1)
                cpu_percent = max(0.0, min(100.0, cpu_percent))
        except Exception:
            pass

    # 4. Memory
    mem_vals = {}
    for line in sections.get("MEM", []):
        if ":" in line:
            k, v = line.split(":", 1)
            try:
                mem_vals[k.strip()] = int(v.strip().split()[0])
            except Exception:
                pass

    mem_total_kb = mem_vals.get("MemTotal", 1)
    mem_free_kb = mem_vals.get("MemFree", 0)
    mem_avail_kb = mem_vals.get("MemAvailable", mem_free_kb)
    mem_used_kb = max(0, mem_total_kb - mem_avail_kb)
    mem_pct = round((mem_used_kb / max(1, mem_total_kb)) * 100.0, 1)

    swap_total_kb = mem_vals.get("SwapTotal", 0)
    swap_free_kb = mem_vals.get("SwapFree", 0)
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_pct = round((swap_used_kb / max(1, swap_total_kb)) * 100.0, 1) if swap_total_kb > 0 else 0.0

    # 5. Disk
    disks = []
    disk_lines = sections.get("DISK", [])
    if len(disk_lines) > 1:
        for line in disk_lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                try:
                    pct = int(parts[4].replace("%", ""))
                    size_kb = int(parts[1])
                    used_kb = int(parts[2])
                    avail_kb = int(parts[3])
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


def collect_server_metrics(owner: str, slug: str, app_obj=None) -> dict:
    """Connect to the server via SSH and execute the metrics command."""
    from app.sockets import _connect_ssh_client
    app = app_obj or current_app._get_current_object()

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
