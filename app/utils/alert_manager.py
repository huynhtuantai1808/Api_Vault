"""
app/utils/alert_manager.py - Centralized agentless performance alert manager.
Periodically scans Linux servers from Vault credentials, evaluates thresholds:
- CPU >= 95%
- RAM Free < 1 GB
- Disk Free < 2 GB
Supports individual and master On/Off toggles for:
- Tất cả (Master All)
- CPU Alert
- RAM Alert
- Disk Alert
Sends real-time Telegram alerts with anti-spam cooldown and auto-recovery notifications.
"""
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from flask import current_app
import requests

logger = logging.getLogger(__name__)

# State tracking for Cooldown, Enable/Disable, and Auto-Recovery:
# { slug: { "alerting": bool, "last_sent": float, "issues": list, "hostname": str } }
_server_alert_states = {}
_scheduler_started = False
_last_scan_time = None
_last_scan_summary = {}

# Granular Alert Controls: All (Master), CPU, RAM, Disk
_alert_config = {
    "enabled": True,        # Tất cả (Master On/Off)
    "cpu_enabled": True,    # CPU Alert On/Off
    "ram_enabled": True,    # RAM Alert On/Off
    "disk_enabled": True,   # Disk Alert On/Off
}


def get_alert_config() -> dict:
    """Get current alert configuration."""
    return dict(_alert_config)


def update_alert_config(updates: dict) -> dict:
    """Update alert configuration for all or individual metrics."""
    global _alert_config
    if "all" in updates:
        val = bool(updates["all"])
        _alert_config["enabled"] = val
        _alert_config["cpu_enabled"] = val
        _alert_config["ram_enabled"] = val
        _alert_config["disk_enabled"] = val
    if "enabled" in updates:
        _alert_config["enabled"] = bool(updates["enabled"])
    if "cpu_enabled" in updates:
        _alert_config["cpu_enabled"] = bool(updates["cpu_enabled"])
    if "ram_enabled" in updates:
        _alert_config["ram_enabled"] = bool(updates["ram_enabled"])
    if "disk_enabled" in updates:
        _alert_config["disk_enabled"] = bool(updates["disk_enabled"])

    logger.info(f"Updated alert configuration: {_alert_config}")
    return dict(_alert_config)


def is_alerts_enabled() -> bool:
    """Check if master alerts are currently enabled."""
    return _alert_config["enabled"]


def set_alerts_enabled(enabled: bool) -> bool:
    """Set master alert enabled state."""
    _alert_config["enabled"] = bool(enabled)
    logger.info(f"Performance master alerts toggled: {'ENABLED' if _alert_config['enabled'] else 'DISABLED'}")
    return _alert_config["enabled"]


def send_telegram_alert(bot_token: str, chat_id: str, message: str, force: bool = False) -> bool:
    """Send formatted alert message to Telegram chat/group."""
    if not _alert_config["enabled"] and not force:
        logger.debug("Telegram alert skipped: alerts are toggled OFF.")
        return False

    if not bot_token or not chat_id:
        logger.debug("Telegram alert skipped: bot_token or chat_id not set.")
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }
    try:
        res = requests.post(url, json=payload, timeout=8)
        if res.status_code == 200:
            return True
        else:
            logger.error(f"Telegram API error {res.status_code}: {res.text}")
            return False
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")
        return False


def evaluate_server_metrics(metrics: dict, config: dict) -> list:
    """
    Evaluate server metrics against configured thresholds and metric toggle switches.
    Returns a list of human-readable issue descriptions.
    """
    issues = []
    if not metrics or metrics.get("status") != "online":
        return issues

    # If master switch is OFF, generate no issues
    if not _alert_config.get("enabled", True):
        return []

    cpu_threshold = config.get("ALERT_CPU_THRESHOLD", 95.0)
    ram_min_free_gb = config.get("ALERT_RAM_MIN_FREE_GB", 1.0)
    disk_min_free_gb = config.get("ALERT_DISK_MIN_FREE_GB", 2.0)

    # 1. CPU Threshold (only if cpu_enabled is True)
    if _alert_config.get("cpu_enabled", True):
        cpu_pct = metrics.get("cpu", {}).get("percent", 0.0)
        if cpu_pct >= cpu_threshold:
            load_avg = metrics.get("cpu", {}).get("load", [])
            load_str = ", ".join(f"{x:.2f}" for x in load_avg) if load_avg else "N/A"
            issues.append(f"🔥 *CPU quá tải*: `{cpu_pct}%` (Ngưỡng: >= {cpu_threshold}%, Load: `{load_str}`)")

    # 2. RAM Free Threshold (only if ram_enabled is True)
    if _alert_config.get("ram_enabled", True):
        mem = metrics.get("memory", {})
        mem_free_gb = mem.get("free_gb", 999.0)
        mem_total_gb = mem.get("total_gb", 0.0)
        mem_used_gb = mem.get("used_gb", 0.0)
        mem_pct = mem.get("percent", 0.0)
        if mem_free_gb < ram_min_free_gb:
            issues.append(f"🧠 *RAM cạn kiệt*: Chỉ còn `{mem_free_gb} GB` khả dụng / `{mem_total_gb} GB` (Đã dùng: `{mem_used_gb} GB` - `{mem_pct}%`, Ngưỡng: < {ram_min_free_gb} GB)")

    # 3. Disk Free Threshold (only if disk_enabled is True)
    if _alert_config.get("disk_enabled", True):
        for d in metrics.get("disk", []):
            avail_gb = d.get("avail_gb", 999.0)
            size_gb = d.get("size_gb", 0.0)
            mount = d.get("mount", "/")
            used_gb = d.get("used_gb", 0.0)
            pct = d.get("percent", 0)

            # For small partitions (like /boot <= 2GB), only alert if usage is critical (>= 85%)
            # For standard partitions (> 2GB), alert if free space < disk_min_free_gb or pct >= 90%
            is_disk_critical = False
            if size_gb <= disk_min_free_gb:
                if pct >= 85:
                    is_disk_critical = True
            else:
                if avail_gb < disk_min_free_gb or pct >= 90:
                    is_disk_critical = True

            if is_disk_critical:
                issues.append(f"💾 *Ổ đĩa `{mount}` sắp đầy*: Còn trống `{avail_gb} GB` / `{size_gb} GB` (Đã dùng: `{used_gb} GB` - `{pct}%`, Ngưỡng: < {disk_min_free_gb} GB)")

    return issues


def scan_single_server(owner: str, slug: str, app_obj, config: dict, dry_run=False) -> dict:
    """Scan a single server, evaluate thresholds, and send alerts if needed."""
    from app.utils.monitoring import collect_server_metrics
    from app.utils.vault_client import VaultClient
    now = time.time()
    bot_token = config.get("TELEGRAM_ALERT_BOT_TOKEN", "")
    chat_id = config.get("TELEGRAM_ALERT_CHAT_ID", "")
    cooldown = 900  # 15 minutes anti-spam

    with app_obj.app_context():
        secret = VaultClient.kv_read(f"servers/{owner}/{slug}")
        if not secret:
            return {"slug": slug, "status": "skipped", "reason": "not_found"}

    os_type = (secret.get("os_type") or "linux").lower()
    port = int(secret.get("port") or (3389 if os_type == "windows" else 22))

    # In current phase, only test/scan Linux servers
    if config.get("ALERT_ONLY_LINUX", True):
        if os_type == "windows" or port == 3389:
            return {"slug": slug, "status": "skipped", "reason": "windows_rdp", "hostname": secret.get("name") or slug}

    try:
        metrics = collect_server_metrics(owner, slug, app_obj)
        if not metrics or metrics.get("status") != "online":
            return {"slug": slug, "status": "offline", "metrics": metrics, "hostname": secret.get("name") or slug}

        hostname = metrics.get("hostname", secret.get("name") or slug)
        issues = evaluate_server_metrics(metrics, config)

        state = _server_alert_states.setdefault(slug, {
            "alerting": False,
            "last_sent": 0,
            "issues": [],
            "hostname": hostname
        })

        if issues:
            # Threshold violated!
            last_sent = state.get("last_sent", 0)
            is_new = not state.get("alerting", False)
            should_send = is_new or (now - last_sent > cooldown)

            if should_send and not dry_run and _alert_config.get("enabled", True):
                msg = (
                    f"🚨 *[CẢNH BÁO HIỆU NĂNG MÁY CHỦ]* 🚨\n\n"
                    f"🖥 *Máy chủ*: `{hostname}` (`{slug}`)\n"
                    f"🌐 *Host*: `{secret.get('host')}:{port}`\n"
                    f"⏰ *Thời gian*: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n\n"
                    f"*Chi tiết cảnh báo:*\n"
                )
                for issue in issues:
                    msg += f"• {issue}\n"

                msg += f"\n📊 *Uptime*: `{metrics.get('uptime', '—')}`\n"
                msg += f"👉 Kiểm tra chi tiết tại [API Vault](http://localhost:5055)"

                logger.warning(f"Sending Telegram alert for {slug}: {issues}")
                send_telegram_alert(bot_token, chat_id, msg)
                state["last_sent"] = now

            state["alerting"] = True
            state["issues"] = issues
            state["hostname"] = hostname

            return {
                "slug": slug,
                "hostname": hostname,
                "status": "alert",
                "issues": issues,
                "metrics": {
                    "cpu_pct": metrics.get("cpu", {}).get("percent"),
                    "ram_free_gb": metrics.get("memory", {}).get("free_gb"),
                    "ram_total_gb": metrics.get("memory", {}).get("total_gb"),
                    "uptime": metrics.get("uptime")
                }
            }

        else:
            # Metrics are normal. Check if it just recovered from an alert:
            if state.get("alerting", False) and not dry_run and _alert_config.get("enabled", True):
                state["alerting"] = False
                state["issues"] = []
                rec_msg = (
                    f"✅ *[ĐÃ PHỤC HỒI HIỆU NĂNG]*\n\n"
                    f"🖥 *Máy chủ*: `{hostname}` (`{slug}`)\n"
                    f"⏰ *Thời gian*: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n\n"
                    f"Tất cả chỉ số (CPU: `{metrics.get('cpu', {}).get('percent')}%`, "
                    f"RAM Free: `{metrics.get('memory', {}).get('free_gb')} GB`) "
                    f"đã trở lại trạng thái an toàn."
                )
                logger.info(f"Sending recovery alert for {slug}")
                send_telegram_alert(bot_token, chat_id, rec_msg)

            return {
                "slug": slug,
                "hostname": hostname,
                "status": "healthy",
                "metrics": {
                    "cpu_pct": metrics.get("cpu", {}).get("percent"),
                    "ram_free_gb": metrics.get("memory", {}).get("free_gb"),
                    "ram_total_gb": metrics.get("memory", {}).get("total_gb"),
                    "uptime": metrics.get("uptime")
                }
            }

    except Exception as e:
        logger.debug(f"Failed to scan metrics for {slug}: {e}")
        return {"slug": slug, "status": "error", "error": str(e), "hostname": secret.get("name") or slug}


def scan_all_servers(app_obj=None, dry_run=False) -> dict:
    """
    Perform a concurrent scan across all eligible Linux servers from Vault.
    Uses ThreadPoolExecutor(max_workers=5) for safe, lightweight execution.
    """
    global _last_scan_time, _last_scan_summary
    from app.utils.vault_client import VaultClient
    app = app_obj or current_app._get_current_object()

    config = {
        "TELEGRAM_ALERT_BOT_TOKEN": app.config.get("TELEGRAM_ALERT_BOT_TOKEN", ""),
        "TELEGRAM_ALERT_CHAT_ID": app.config.get("TELEGRAM_ALERT_CHAT_ID", ""),
        "ALERT_CPU_THRESHOLD": app.config.get("ALERT_CPU_THRESHOLD", 95.0),
        "ALERT_RAM_MIN_FREE_GB": app.config.get("ALERT_RAM_MIN_FREE_GB", 1.0),
        "ALERT_DISK_MIN_FREE_GB": app.config.get("ALERT_DISK_MIN_FREE_GB", 2.0),
        "ALERT_ONLY_LINUX": app.config.get("ALERT_ONLY_LINUX", True),
    }

    with app.app_context():
        try:
            keys = VaultClient.kv_list("servers/admin") or []
        except Exception as e:
            logger.error(f"Cannot list servers from Vault: {e}")
            return {"error": str(e)}

    slugs = [k for k in keys if k and not k.startswith(".")]

    if not _alert_config.get("enabled", True):
        logger.info("Alert scan paused: master alerts are toggled OFF.")
        return {
            "status": "disabled",
            "enabled": False,
            "config": dict(_alert_config),
            "message": "Cảnh báo đang tạm tắt.",
            "timestamp": int(time.time()),
            "total_targets": len(slugs),
            "scanned_count": 0,
            "healthy_count": 0,
            "alert_count": 0,
            "active_alerts": []
        }

    logger.info(f"Running performance scan across {len(slugs)} servers (dry_run={dry_run})...")

    results = []
    # Maximum 5 concurrent connections to prevent host resource exhaustion
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(scan_single_server, "admin", slug, app, config, dry_run)
            for slug in slugs
        ]
        for f in futures:
            try:
                res = f.result(timeout=20)
                results.append(res)
            except Exception as e:
                results.append({"status": "timeout_or_error", "error": str(e)})

    alerts = [r for r in results if r.get("status") == "alert"]
    healthy = [r for r in results if r.get("status") == "healthy"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    errors = [r for r in results if r.get("status") in ("error", "offline", "timeout_or_error")]

    _last_scan_time = time.time()
    _last_scan_summary = {
        "timestamp": int(_last_scan_time),
        "config": dict(_alert_config),
        "enabled": _alert_config.get("enabled", True),
        "total_targets": len(slugs),
        "scanned_count": len(healthy) + len(alerts),
        "healthy_count": len(healthy),
        "alert_count": len(alerts),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "active_alerts": alerts,
        "all_results": results
    }

    logger.info(
        f"Performance scan completed: {len(healthy)} healthy, {len(alerts)} alerts, "
        f"{len(skipped)} skipped, {len(errors)} errors."
    )
    return _last_scan_summary


def start_alert_scheduler(app_obj):
    """Start background scheduler loop if not already running."""
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        logger.info("Starting Background Alert Monitoring Scheduler...")
        # Initial delay of 15 seconds after app startup
        time.sleep(15)
        while True:
            try:
                if _alert_config.get("enabled", True):
                    scan_interval = app_obj.config.get("ALERT_SCAN_INTERVAL", 180)
                    scan_all_servers(app_obj)
            except Exception as e:
                logger.error(f"Error in alert scheduler loop: {e}")
            time.sleep(max(30, app_obj.config.get("ALERT_SCAN_INTERVAL", 180)))

    # Use gevent / socketio background task or threading
    try:
        from app.extensions import socketio
        socketio.start_background_task(_loop)
        logger.info("Alert scheduler registered via socketio background task.")
    except Exception:
        import threading
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        logger.info("Alert scheduler registered via daemon thread.")


def get_alert_status() -> dict:
    """Return status of alert scheduler, enabled state for all/cpu/ram/disk, last scan summary, and currently alerting servers."""
    return {
        "config": dict(_alert_config),
        "enabled": _alert_config.get("enabled", True),
        "cpu_enabled": _alert_config.get("cpu_enabled", True),
        "ram_enabled": _alert_config.get("ram_enabled", True),
        "disk_enabled": _alert_config.get("disk_enabled", True),
        "scheduler_running": _scheduler_started,
        "last_scan": _last_scan_summary,
        "active_alerts": [
            {"slug": k, "hostname": v.get("hostname"), "issues": v.get("issues"), "last_sent": v.get("last_sent")}
            for k, v in _server_alert_states.items() if v.get("alerting")
        ]
    }
