"""
PCGuard macOS Agent
Supports: macOS 12+ (Monterey and later)

Config file : ~/Library/Application Support/PCGuard/config.json
Log file    : ~/Library/Logs/PCGuard/agent.log
"""

import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

import psutil
import requests
import schedule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def _read_version() -> str:
    try:
        _dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(_dir, "VERSION")) as _f:
            return _f.read().strip()
    except Exception:
        return "1.0.0"

AGENT_VERSION = _read_version()
DEVICE_NAME   = socket.gethostname()

FUNCTIONS_BASE     = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL      = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL    = f"{FUNCTIONS_BASE}/submitScan"
REALTIME_URL       = f"{FUNCTIONS_BASE}/realtimeHeartbeat"

CONFIG_PATH = os.path.expanduser("~/Library/Application Support/PCGuard/config.json")
LOG_PATH    = os.path.expanduser("~/Library/Logs/PCGuard/agent.log")

DANGEROUS_PORTS = {23, 4444, 1337, 5900, 31337}

SUSPICIOUS_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan",
    "hydra", "john", "hashcat", "msfconsole",
}

# ---------------------------------------------------------------------------
# Global runtime state (populated in main())
# ---------------------------------------------------------------------------

AGENT_TOKEN:    str = ""
DEVICE_ID:      str = ""
SCAN_INTERVAL:  int = 300
HEARTBEAT_SECS: int = 60

logger = logging.getLogger("mac_agent")

# Network info cache — avoid hammering the network every 10 s
_net_cache:     dict  = {}
_net_last_time: list  = [0.0]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = RotatingFileHandler(LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    logger.setLevel(logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(sh)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Failed to read config: %s", exc)
    return {}


def save_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Device ID  — IOPlatformUUID (permanent, hardware-bound)
# ---------------------------------------------------------------------------

def resolve_device_id(cfg: dict) -> str:
    # 1. ioreg IOPlatformUUID — survives reinstalls, unique per Mac
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', line)
                if m:
                    return m.group(1)
    except Exception as exc:
        logger.debug("ioreg device-id error: %s", exc)

    # 2. Saved UUID in config
    if "device_id" in cfg:
        return cfg["device_id"]

    import uuid
    new_id = str(uuid.uuid4())
    cfg["device_id"] = new_id
    try:
        save_config(cfg)
    except Exception:
        pass
    return new_id


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _post(url: str, payload: dict, timeout: int = 30):
    """POST JSON, return (status_code, body_dict)."""
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        try:
            body = resp.json()
        except Exception:
            body = {}
        return resp.status_code, body
    except requests.RequestException as exc:
        logger.debug("POST %s failed: %s", url, exc)
        return 0, {}


# ---------------------------------------------------------------------------
# Safe wrapper
# ---------------------------------------------------------------------------

def _safe(name: str, fn, default=None):
    if default is None:
        default = []
    try:
        return fn()
    except Exception as exc:
        logger.error("Error in %s: %s", name, exc)
        return default


def _run(cmd: list, timeout: int = 10) -> str:
    """Run a command, return stdout stripped, or '' on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# MacScanner
# ---------------------------------------------------------------------------

class MacScanner:

    # -- Storage ----------------------------------------------------------

    def scan_storage(self) -> list:
        results = []
        try:
            usage = psutil.disk_usage("/")
            results.append({
                "mount":       "/",
                "totalGB":     round(usage.total / 1e9, 2),
                "usedGB":      round(usage.used  / 1e9, 2),
                "freeGB":      round(usage.free  / 1e9, 2),
                "usedPercent": usage.percent,
            })
        except Exception as exc:
            logger.error("scan_storage: %s", exc)
        return results

    # -- Processes --------------------------------------------------------

    def scan_processes(self) -> list:
        procs = []
        try:
            for p in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_info", "status", "username"]
            ):
                try:
                    info = p.info
                    name = (info.get("name") or "").lower()
                    cpu  = info.get("cpu_percent") or 0.0
                    mem  = info.get("memory_info")
                    mem_mb = round(mem.rss / 1e6, 1) if mem else 0.0
                    suspicious = name in SUSPICIOUS_NAMES
                    procs.append({
                        "pid":         info.get("pid"),
                        "name":        info.get("name"),
                        "cpu_percent": cpu,
                        "memory_mb":   mem_mb,
                        "status":      info.get("status"),
                        "username":    info.get("username"),
                        "suspicious":  suspicious,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            logger.error("scan_processes: %s", exc)
        procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
        return procs[:20]

    # -- CPU temperature --------------------------------------------------

    def scan_temperatures(self) -> list:
        """Try powermetrics for SMC sensor data (requires sudo — usually N/A)."""
        try:
            r = subprocess.run(
                ["sudo", "-n", "powermetrics", "--samplers", "smc", "-i1", "-n1"],
                capture_output=True, text=True, timeout=5
            )
            temps = []
            for line in r.stdout.splitlines():
                m = re.match(r"^(.+):\s+([\d.]+)\s+C$", line.strip())
                if m:
                    temps.append({"label": m.group(1).strip(), "current": float(m.group(2))})
                    if len(temps) >= 5:
                        break
            if temps:
                return temps
        except Exception:
            pass
        return []  # Not available without sudo

    # -- Mac model & chip -------------------------------------------------

    def get_mac_model(self) -> str:
        out = _run(["system_profiler", "SPHardwareDataType"])
        for line in out.splitlines():
            if "Model Name" in line:
                return line.split(":", 1)[-1].strip()
        return platform.machine()

    def get_chip(self) -> str:
        proc = platform.processor()
        if proc:
            return proc
        # Apple Silicon shows up differently
        out = _run(["uname", "-m"])
        if out == "arm64":
            return "Apple Silicon"
        return "Intel"

    def get_chip_type(self) -> str:
        """Returns 'Apple Silicon' or 'Intel'."""
        out = _run(["uname", "-m"])
        return "Apple Silicon" if out == "arm64" else "Intel"

    # -- OS info ----------------------------------------------------------

    def get_os_info(self) -> dict:
        mac_ver, _, machine = platform.mac_ver()
        return {
            "version": mac_ver or "Unknown",
            "machine": machine or platform.machine(),
        }

    # -- Uptime -----------------------------------------------------------

    def get_uptime_seconds(self) -> int:
        try:
            return int(time.time() - psutil.boot_time())
        except Exception:
            return 0

    # -- Internet / IP ----------------------------------------------------

    def get_internet_status(self):
        try:
            start = time.time()
            sock  = socket.create_connection(("8.8.8.8", 53), timeout=2)
            latency_ms = int((time.time() - start) * 1000)
            sock.close()
            return True, latency_ms
        except OSError:
            return False, None

    def get_local_ip(self) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except Exception:
            return "unknown"

    def get_public_ip(self):
        try:
            return requests.get("https://api.ipify.org", timeout=5).text.strip()
        except Exception:
            return None

    # -- Open ports -------------------------------------------------------

    def scan_open_ports(self) -> list:
        ports = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN:
                    continue
                laddr = conn.laddr
                if not laddr:
                    continue
                ip = laddr.ip
                if ip.startswith("127.") or ip == "::1":
                    continue
                port = laddr.port
                process_name = ""
                try:
                    if conn.pid:
                        process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                ports.append({
                    "port":      port,
                    "protocol":  "TCP",
                    "pid":       conn.pid,
                    "process":   process_name,
                    "dangerous": port in DANGEROUS_PORTS,
                })
        except Exception as exc:
            logger.error("scan_open_ports: %s", exc)
        ports.sort(key=lambda p: p["port"])
        return ports

    # -- SSH status (launchd) --------------------------------------------

    def check_ssh_enabled(self) -> bool:
        out = _run(["launchctl", "list"])
        return "com.openssh" in out.lower()

    # -- Remote Management (VNC/Screen Sharing) --------------------------

    def check_remote_management(self) -> bool:
        out = _run(["launchctl", "list"])
        return "com.apple.screensharing" in out.lower()

    # -- Current logged-in users -----------------------------------------

    def get_current_users(self) -> list:
        sessions = []
        try:
            for u in psutil.users():
                sessions.append({
                    "username": u.name,
                    "terminal": u.terminal or "",
                    "host":     u.host or "",
                    "started":  u.started,
                    "is_ssh":   bool(u.host and u.host not in ("", "localhost", "::1")),
                })
        except Exception as exc:
            logger.debug("get_current_users: %s", exc)
        return sessions

    # ── macOS Security checks ──────────────────────────────────────────

    def scan_filevault(self) -> dict:
        """Check FileVault disk encryption status."""
        out = _run(["fdesetup", "status"])
        enabled = "fileVault is On" in out or "FileVault is On" in out
        return {"enabled": enabled, "raw": out[:200]}

    def scan_gatekeeper(self) -> dict:
        """Check Gatekeeper (app notarisation enforcement) status."""
        out = _run(["spctl", "--status"])
        enabled = "assessments enabled" in out.lower()
        return {"enabled": enabled, "raw": out[:200]}

    def scan_sip(self) -> dict:
        """Check System Integrity Protection status."""
        out = _run(["csrutil", "status"])
        enabled = "enabled" in out.lower() and "disabled" not in out.lower()
        return {"enabled": enabled, "raw": out[:200]}

    def scan_firewall(self) -> dict:
        """Check macOS Application Firewall status."""
        out = _run([
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ])
        enabled = "enabled" in out.lower() or "(State = 1)" in out
        return {"enabled": enabled, "raw": out[:200]}

    def scan_admin_users(self) -> list:
        """List members of the local admin group."""
        out = _run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        users = []
        for line in out.splitlines():
            if "GroupMembership:" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    users = [u.strip() for u in parts[1].split() if u.strip()]
        return users

    def scan_recent_installs(self, days: int = 7) -> list:
        """Return apps installed in the last `days` days via system_profiler."""
        out = _run(["system_profiler", "SPInstallHistoryDataType"], timeout=30)
        cutoff = datetime.now() - timedelta(days=days)
        results = []
        current_name = None
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Install History"):
                # Name lines have no leading whitespace key: value pattern
                if not line.startswith("Install Date:") and not line.startswith("Package"):
                    current_name = line.rstrip(":")
                elif line.startswith("Install Date:") and current_name:
                    date_str = line.replace("Install Date:", "").strip()
                    try:
                        # Format: "2024-03-01 12:00:00 +0000"
                        dt = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S")
                        if dt >= cutoff:
                            results.append({"name": current_name, "date": date_str[:10]})
                    except ValueError:
                        pass
        return results[:20]

    def scan_ssh_failed_logins(self) -> dict:
        """Count failed SSH logins in the last 24 h via unified log."""
        try:
            result = subprocess.run(
                [
                    "log", "show",
                    "--last", "24h",
                    "--predicate", 'process == "sshd"',
                    "--style", "compact",
                ],
                capture_output=True, text=True, timeout=20
            )
            lines = result.stdout.splitlines()
            ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
            ip_counter: Counter = Counter()
            for line in lines:
                if "Failed" in line or "Invalid" in line:
                    m = ip_re.search(line)
                    if m:
                        ip_counter[m.group(1)] += 1
            total   = sum(ip_counter.values())
            top_ips = [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(10)]
            return {"total": total, "unique_ips": len(ip_counter), "top_ips": top_ips}
        except Exception as exc:
            logger.debug("scan_ssh_failed_logins: %s", exc)
            return {"total": 0, "unique_ips": 0, "top_ips": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# Health score
# ---------------------------------------------------------------------------

def health_score(scan: dict) -> int:
    score = 100

    # Storage
    for drive in scan.get("storage", []):
        pct = drive.get("usedPercent", 0)
        if pct >= 90:
            score -= 20
        elif pct >= 80:
            score -= 10

    # macOS security features
    if not scan.get("filevault", {}).get("enabled", True):
        score -= 20
    if not scan.get("gatekeeper", {}).get("enabled", True):
        score -= 15
    if not scan.get("sip", {}).get("enabled", True):
        score -= 15
    if not scan.get("macFirewall", {}).get("enabled", True):
        score -= 10

    # SSH enabled
    if scan.get("sshEnabled"):
        score -= 5

    # Remote management (VNC)
    if scan.get("remoteManagement"):
        score -= 10

    # Dangerous open ports
    dangerous_count = sum(1 for p in scan.get("openPorts", []) if p.get("dangerous"))
    score -= min(dangerous_count * 15, 30)

    # SSH brute-force
    ssh = scan.get("sshFailedLogins", {})
    total_fails = ssh.get("total", 0)
    if total_fails >= 100:
        score -= 20
    elif total_fails >= 20:
        score -= 10
    elif total_fails >= 5:
        score -= 5

    # Suspicious processes
    sus_count = sum(1 for p in scan.get("processes", []) if p.get("suspicious"))
    if sus_count >= 3:
        score -= 15
    elif sus_count >= 1:
        score -= 8

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Agent actions
# ---------------------------------------------------------------------------

def send_heartbeat() -> dict:
    """Send liveness ping. Returns response body (may contain heartbeat_paused)."""
    status, body = _post(HEARTBEAT_URL, {
        "token":        AGENT_TOKEN,
        "deviceId":     DEVICE_ID,
        "deviceName":   DEVICE_NAME,
        "hostname":     DEVICE_NAME,
        "agentVersion": AGENT_VERSION,
        "readOnlyMode": True,
        "os":           "macOS",
    })
    if status == 200:
        logger.info("Heartbeat OK")
    else:
        logger.warning("Heartbeat failed (status=%s body=%s)", status, body)
    return body if isinstance(body, dict) else {}


def _handle_heartbeat_paused() -> None:
    logger.warning("Heartbeats paused by server. Retrying every 5 min …")
    schedule.clear()

    _POLL_INTERVAL = 300   # 5 minutes
    _MAX_POLLS     = 12    # 1 hour total

    for _ in range(_MAX_POLLS):
        time.sleep(_POLL_INTERVAL)
        status, body = _post(HEARTBEAT_URL, {
            "token":        AGENT_TOKEN,
            "deviceId":     DEVICE_ID,
            "deviceName":   DEVICE_NAME,
            "hostname":     DEVICE_NAME,
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": True,
            "os":           "macOS",
        })
        paused = isinstance(body, dict) and body.get("heartbeat_paused", True)
        if status == 200 and not paused:
            logger.info("Pause lifted. Resuming normal operation.")
            schedule.every(HEARTBEAT_SECS).seconds.do(_scheduled_heartbeat)
            schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
            schedule.every(10).seconds.do(send_realtime_heartbeat)
            return

    logger.warning("Still paused after 1 hour. Re-scheduling heartbeat only.")
    schedule.every(HEARTBEAT_SECS).seconds.do(_scheduled_heartbeat)


def send_realtime_heartbeat() -> None:
    global _net_cache, _net_last_time

    scanner = MacScanner()

    cpu         = psutil.cpu_percent(interval=0.1)
    vm          = psutil.virtual_memory()
    ram_percent = vm.percent
    ram_used_gb = round(vm.used  / 1e9, 2)
    ram_total_gb= round(vm.total / 1e9, 2)

    top_procs = []
    try:
        raw = list(psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]))
        raw.sort(key=lambda p: p.info.get("cpu_percent") or 0, reverse=True)
        for p in raw[:5]:
            top_procs.append({
                "name":   p.info["name"] or "",
                "cpu":    round(p.info.get("cpu_percent") or 0.0, 1),
                "ram_mb": round((p.info["memory_info"].rss
                                 if p.info.get("memory_info") else 0) / 1e6, 1),
            })
    except Exception:
        pass

    temps = _safe("temperatures_realtime", scanner.scan_temperatures)

    now = time.time()
    if now - _net_last_time[0] >= 30:
        connected, latency_ms = scanner.get_internet_status()
        local_ip              = scanner.get_local_ip()
        _net_cache = {
            "connected":  connected,
            "latency_ms": latency_ms,
            "local_ip":   local_ip,
        }
        _net_last_time[0] = now

    uptime_seconds = scanner.get_uptime_seconds()
    current_users  = _safe("current_users_realtime", scanner.get_current_users)

    # Current user session
    current_username = ""
    current_user_is_admin = False
    try:
        import getpass
        current_username = getpass.getuser()
        admin_users = scanner.scan_admin_users()
        current_user_is_admin = current_username in admin_users
    except Exception:
        pass

    payload = {
        "token":                 AGENT_TOKEN,
        "deviceId":              DEVICE_ID,
        "deviceName":            DEVICE_NAME,
        "agentVersion":          AGENT_VERSION,
        "os":                    "macOS",
        "cpu_percent":           round(cpu, 1),
        "ram_percent":           ram_percent,
        "ram_used_gb":           ram_used_gb,
        "ram_total_gb":          ram_total_gb,
        "top_processes":         top_procs,
        "temperatures":          temps,
        "network":               _net_cache,
        "uptime_seconds":        uptime_seconds,
        "current_users":         current_users,
        "current_username":      current_username,
        "current_user_is_admin": current_user_is_admin,
    }

    status, body = _post(REALTIME_URL, payload)
    if status not in (200, 204):
        logger.debug("Realtime heartbeat status=%s", status)


def run_scan() -> None:
    logger.info("Starting full scan …")
    scanner = MacScanner()

    storage          = _safe("scan_storage",          scanner.scan_storage,          [])
    processes        = _safe("scan_processes",         scanner.scan_processes,        [])
    temperatures     = _safe("scan_temperatures",      scanner.scan_temperatures,     [])
    filevault        = _safe("scan_filevault",          scanner.scan_filevault,        {})
    gatekeeper       = _safe("scan_gatekeeper",        scanner.scan_gatekeeper,       {})
    sip              = _safe("scan_sip",               scanner.scan_sip,              {})
    mac_firewall     = _safe("scan_firewall",           scanner.scan_firewall,         {})
    admin_users      = _safe("scan_admin_users",       scanner.scan_admin_users,      [])
    recent_installs  = _safe("scan_recent_installs",   scanner.scan_recent_installs,  [])
    ssh_failed       = _safe("scan_ssh_failed_logins", scanner.scan_ssh_failed_logins, {})
    open_ports       = _safe("scan_open_ports",        scanner.scan_open_ports,       [])
    os_info          = _safe("get_os_info",            scanner.get_os_info,           {})
    uptime_seconds   = _safe("get_uptime_seconds",     scanner.get_uptime_seconds,    0)
    current_users    = _safe("get_current_users",      scanner.get_current_users,     [])
    mac_model        = _safe("get_mac_model",          scanner.get_mac_model,         "")
    chip_type        = _safe("get_chip_type",          scanner.get_chip_type,         "")
    ssh_enabled      = _safe("check_ssh_enabled",      scanner.check_ssh_enabled,     False)
    remote_mgmt      = _safe("check_remote_management",scanner.check_remote_management, False)

    connected, latency_ms = scanner.get_internet_status()
    local_ip              = scanner.get_local_ip()
    public_ip             = _safe("get_public_ip",     scanner.get_public_ip,         None)

    # Firewall grade — based on macOS firewall + SIP + Gatekeeper
    security_count = sum([
        mac_firewall.get("enabled", False),
        sip.get("enabled", False),
        gatekeeper.get("enabled", False),
    ])
    firewall_grade = "A" if security_count == 3 else ("B" if security_count == 2 else "F")

    network_info = {
        "connected":  connected,
        "latency_ms": latency_ms,
        "local_ip":   local_ip,
        "public_ip":  public_ip,
        "rdp_enabled":  False,
        "ssh_enabled":  ssh_enabled,
        "open_ports":   open_ports,
    }

    scan = {
        "token":             AGENT_TOKEN,
        "deviceId":          DEVICE_ID,
        "deviceName":        DEVICE_NAME,
        "agentVersion":      AGENT_VERSION,
        "hostname":          DEVICE_NAME,
        "os":                "macOS",
        "osInfo":            os_info,
        "macModel":          mac_model,
        "chipType":          chip_type,
        "uptime":            uptime_seconds,
        "storage":           storage,
        "processes":         processes,
        "temperatures":      temperatures,
        "filevault":         filevault,
        "gatekeeper":        gatekeeper,
        "sip":               sip,
        "macFirewall":       mac_firewall,
        "firewallGrade":     firewall_grade,
        "adminUsers":        admin_users,
        "recentInstalls":    recent_installs,
        "sshEnabled":        ssh_enabled,
        "remoteManagement":  remote_mgmt,
        "sshFailedLogins":   ssh_failed,
        "openPorts":         open_ports,
        "networkInfo":       network_info,
        "currentUsers":      current_users,
        "healthScore":       0,  # computed below
    }

    scan["healthScore"] = health_score(scan)

    status, body = _post(SUBMIT_SCAN_URL, scan)
    if status == 200:
        logger.info("Scan submitted OK (healthScore=%s)", scan["healthScore"])
    else:
        logger.warning("Scan submit failed (status=%s)", status)


# ---------------------------------------------------------------------------
# Scheduled heartbeat wrapper
# ---------------------------------------------------------------------------

def _scheduled_heartbeat():
    body = send_heartbeat()
    if body.get("heartbeat_paused"):
        _handle_heartbeat_paused()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global AGENT_TOKEN, DEVICE_ID, SCAN_INTERVAL, HEARTBEAT_SECS

    setup_logging()
    logger.info("PCGuard macOS Agent v%s starting …", AGENT_VERSION)
    logger.info("Hostname: %s", DEVICE_NAME)

    cfg = load_config()

    AGENT_TOKEN = cfg.get("agent_token", "")
    if not AGENT_TOKEN:
        logger.warning(
            "No agent_token in %s — agent will run but may be rejected by server.",
            CONFIG_PATH,
        )

    SCAN_INTERVAL  = int(cfg.get("scan_interval", 300))
    HEARTBEAT_SECS = int(cfg.get("heartbeat_interval", 60))

    DEVICE_ID = resolve_device_id(cfg)
    logger.info("Device ID: %s", DEVICE_ID)

    # Startup: check server status before first scan
    startup_body = send_heartbeat()
    if startup_body.get("heartbeat_paused"):
        _handle_heartbeat_paused()
    else:
        run_scan()

    schedule.every(HEARTBEAT_SECS).seconds.do(_scheduled_heartbeat)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    schedule.every(10).seconds.do(send_realtime_heartbeat)

    logger.info(
        "Scheduler started — heartbeat every %ss, scan every %ss, realtime every 10s",
        HEARTBEAT_SECS, SCAN_INTERVAL,
    )

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
