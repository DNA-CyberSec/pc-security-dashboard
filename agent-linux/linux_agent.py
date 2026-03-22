"""
PC Health & Security Dashboard — Linux Agent
Version: 0.1.0
Supports: Ubuntu / Debian (and compatible) servers

Config file : /opt/pcguard/config.json
Log file    : /opt/pcguard/agent.log
"""

import glob
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from collections import Counter
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
DEVICE_NAME = socket.gethostname()

FUNCTIONS_BASE = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL = f"{FUNCTIONS_BASE}/submitScan"
REALTIME_URL = f"{FUNCTIONS_BASE}/realtimeHeartbeat"
COMMAND_RESULT_URL = f"{FUNCTIONS_BASE}/reportCommandResult"

CONFIG_PATH = "/opt/pcguard/config.json"
LOG_PATH = "/opt/pcguard/agent.log"

DANGEROUS_PORTS = {23, 3389, 5900, 4444, 1337, 4899, 6667, 31337}

SUSPICIOUS_NAMES = {
    "nc", "ncat", "netcat", "nmap", "masscan", "sqlmap",
    "hydra", "john", "hashcat", "msfconsole", "msfvenom",
    "python -c", "perl -e", "ruby -e", "bash -i", "sh -i",
}

SKIP_FSTYPES = {
    "", "squashfs", "tmpfs", "devtmpfs", "proc", "sysfs",
    "devpts", "cgroup", "cgroup2", "pstore", "hugetlbfs",
    "mqueue", "debugfs", "tracefs", "securityfs", "configfs",
    "fusectl", "efivarfs",
}

# ---------------------------------------------------------------------------
# Global runtime state (populated in main())
# ---------------------------------------------------------------------------

AGENT_TOKEN: str = ""
DEVICE_ID: str = ""
SCAN_INTERVAL: int = 300
HEARTBEAT_SECS: int = 60

logger = logging.getLogger("linux_agent")

# Network info cache to avoid hammering the network every 10 s
_net_cache: dict = {}
_net_last_time: list = [0.0]


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(fmt)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)

    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Failed to read config: %s", exc)
    return {}


def save_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)
    # Restrict permissions so only root can read the token
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Device ID resolution
# ---------------------------------------------------------------------------

def resolve_device_id(cfg: dict) -> str:
    # 1. /etc/machine-id
    try:
        with open("/etc/machine-id") as fh:
            mid = fh.read().strip()
            if mid:
                return mid
    except OSError:
        pass

    # 2. MAC address of first non-loopback NIC
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            if iface == "lo":
                continue
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address.replace(":", "").replace("-", "")
                    if mac and mac != "000000000000":
                        return f"mac-{mac}"
    except Exception:
        pass

    # 3. Saved random UUID in config
    if "device_id" in cfg:
        return cfg["device_id"]

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
    """POST JSON payload, return (status_code, body_dict)."""
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
# Scanner
# ---------------------------------------------------------------------------

class LinuxScanner:

    # -- Storage -------------------------------------------------------------

    def scan_storage(self) -> list:
        results = []
        try:
            for part in psutil.disk_partitions(all=True):
                if part.fstype in SKIP_FSTYPES:
                    continue
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                except (PermissionError, OSError):
                    continue
                results.append({
                    "mount": part.mountpoint,
                    "totalGB": round(usage.total / 1e9, 2),
                    "usedGB": round(usage.used / 1e9, 2),
                    "freeGB": round(usage.free / 1e9, 2),
                    "usedPercent": usage.percent,
                })
        except Exception as exc:
            logger.error("scan_storage error: %s", exc)
        return results

    # -- Processes -----------------------------------------------------------

    def scan_processes(self) -> list:
        procs = []
        try:
            for p in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_info", "status", "username"]
            ):
                try:
                    info = p.info
                    name = (info.get("name") or "").lower()
                    cpu = info.get("cpu_percent") or 0.0
                    username = (info.get("username") or "").lower()
                    mem_info = info.get("memory_info")
                    mem_mb = round(mem_info.rss / 1e6, 1) if mem_info else 0.0

                    suspicious = (
                        name in SUSPICIOUS_NAMES
                        or (cpu > 80 and username in ("nobody", "daemon", "www-data"))
                    )

                    procs.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "cpu_percent": cpu,
                        "memory_mb": mem_mb,
                        "status": info.get("status"),
                        "username": info.get("username"),
                        "suspicious": suspicious,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            logger.error("scan_processes error: %s", exc)

        procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
        return procs[:20]

    # -- Temperatures --------------------------------------------------------

    def scan_temperatures(self) -> list:
        entries = []

        # psutil sensors
        try:
            sensors = psutil.sensors_temperatures()
            if sensors:
                for _key, readings in sensors.items():
                    for r in readings:
                        entries.append({
                            "label": r.label or _key,
                            "current": r.current,
                        })
                        if len(entries) >= 8:
                            return entries
        except AttributeError:
            pass
        except Exception as exc:
            logger.debug("sensors_temperatures error: %s", exc)

        # Fallback: /sys/class/thermal
        if not entries:
            try:
                for zone in sorted(
                    glob.glob("/sys/class/thermal/thermal_zone*/temp")
                ):
                    try:
                        with open(zone) as fh:
                            raw = int(fh.read().strip())
                        label = os.path.basename(os.path.dirname(zone))
                        entries.append({
                            "label": label,
                            "current": raw / 1000.0,
                        })
                        if len(entries) >= 8:
                            break
                    except Exception:
                        continue
            except Exception as exc:
                logger.debug("thermal_zone fallback error: %s", exc)

        return entries

    # -- SSH failed logins ---------------------------------------------------

    def scan_ssh_failed_logins(self) -> dict:
        log_candidates = ["/var/log/auth.log", "/var/log/secure"]
        log_file = None
        for candidate in log_candidates:
            if os.path.exists(candidate):
                log_file = candidate
                break

        if log_file is None:
            return {"total": 0, "unique_ips": 0, "top_ips": [], "error": "log file not found"}

        try:
            with open(log_file, "r", errors="replace") as fh:
                lines = fh.readlines()
        except PermissionError:
            return {"total": 0, "unique_ips": 0, "top_ips": [], "error": "permission denied"}
        except Exception as exc:
            return {"total": 0, "unique_ips": 0, "top_ips": [], "error": str(exc)}

        tail = lines[-2000:]
        ip_counter: Counter = Counter()
        ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

        for line in tail:
            if "Failed password" in line or "Invalid user" in line:
                match = ip_re.search(line)
                if match:
                    ip_counter[match.group(1)] += 1

        total = sum(ip_counter.values())
        top_ips = [
            {"ip": ip, "count": cnt}
            for ip, cnt in ip_counter.most_common(10)
        ]

        return {
            "total": total,
            "unique_ips": len(ip_counter),
            "top_ips": top_ips,
        }

    # -- Recent logins -------------------------------------------------------

    def scan_recent_logins(self) -> list:
        try:
            result = subprocess.run(
                ["last", "-n", "10", "-F"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()
        except Exception as exc:
            logger.debug("scan_recent_logins error: %s", exc)
            return []

        logins = []
        for line in lines:
            if not line.strip():
                continue
            if "wtmp begins" in line or "btmp begins" in line:
                continue
            parts = line.split()
            if not parts:
                continue
            user = parts[0]
            if user in ("reboot", "shutdown"):
                continue
            ip_or_tty = parts[1] if len(parts) > 1 else ""
            time_str = " ".join(parts[2:7]) if len(parts) > 6 else ""
            logins.append({"user": user, "ip_or_tty": ip_or_tty, "time_str": time_str})
            if len(logins) >= 5:
                break

        return logins

    # -- Sudo users ----------------------------------------------------------

    def scan_sudo_users(self) -> list:
        users: set = set()

        for group in ("sudo", "wheel"):
            try:
                result = subprocess.run(
                    ["getent", "group", group],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Format: groupname:x:gid:user1,user2,...
                    parts = result.stdout.strip().split(":")
                    if len(parts) >= 4 and parts[3]:
                        for u in parts[3].split(","):
                            u = u.strip()
                            if u:
                                users.add(u)
            except Exception as exc:
                logger.debug("getent group %s error: %s", group, exc)

        # Also try /etc/sudoers
        try:
            with open("/etc/sudoers", "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    # Simple heuristic: lines like "username ALL=(ALL..."
                    m = re.match(r"^([A-Za-z0-9_.-]+)\s+ALL", line)
                    if m:
                        users.add(m.group(1))
        except PermissionError:
            pass
        except Exception as exc:
            logger.debug("sudoers read error: %s", exc)

        return sorted(users)

    # -- SUID suspects -------------------------------------------------------

    def scan_suid_suspects(self) -> list:
        try:
            result = subprocess.run(
                ["find", "/tmp", "/dev/shm", "/var/tmp", "/run/shm",
                 "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=10
            )
            paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
            return paths
        except Exception as exc:
            logger.debug("scan_suid_suspects error: %s", exc)
            return []

    # -- World-writable /etc -------------------------------------------------

    def scan_world_writable_etc(self) -> list:
        try:
            result = subprocess.run(
                ["find", "/etc", "-maxdepth", "2", "-type", "f", "-writable"],
                capture_output=True, text=True, timeout=10
            )
            paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
            return paths
        except Exception as exc:
            logger.debug("scan_world_writable_etc error: %s", exc)
            return []

    # -- Firewall status -----------------------------------------------------

    def scan_firewall_status(self) -> dict:
        active = False
        rules_count = 0
        ufw_available = False

        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True, text=True, timeout=10
            )
            ufw_available = True
            output = result.stdout

            if "Status: active" in output:
                active = True

            # Count rule lines after the "---" separator
            past_separator = False
            for line in output.splitlines():
                if "---" in line:
                    past_separator = True
                    continue
                if past_separator and line.strip():
                    rules_count += 1

        except FileNotFoundError:
            ufw_available = False
        except Exception as exc:
            logger.debug("ufw status error: %s", exc)

        # Fallback: count iptables ACCEPT rules (count in Python, no shell pipe needed)
        if not active:
            try:
                result = subprocess.run(
                    ["iptables", "-n", "-L", "--line-numbers"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    iptables_count = result.stdout.count("ACCEPT")
                    if iptables_count > 0 and rules_count == 0:
                        rules_count = iptables_count
            except Exception as exc:
                logger.debug("iptables count error: %s", exc)

        return {
            "active": active,
            "rules_count": rules_count,
            "ufw_available": ufw_available,
        }

    # -- Open ports ----------------------------------------------------------

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
                # Skip loopback
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
                    "port": port,
                    "protocol": "TCP",
                    "pid": conn.pid,
                    "process": process_name,
                    "dangerous": port in DANGEROUS_PORTS,
                })
        except Exception as exc:
            logger.error("scan_open_ports error: %s", exc)

        ports.sort(key=lambda p: p["port"])
        return ports

    # -- Network helpers -----------------------------------------------------

    def get_internet_status(self):
        """Return (connected: bool, latency_ms: int|None)."""
        try:
            start = time.time()
            sock = socket.create_connection(("8.8.8.8", 53), timeout=2)
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

    # -- Current active sessions ---------------------------------------------

    def get_current_users(self) -> list:
        """Returns currently logged-in users via psutil."""
        sessions = []
        try:
            for u in psutil.users():
                sessions.append({
                    "username": u.name,
                    "terminal": u.terminal or "",
                    "host":     u.host or "",
                    "started":  u.started,
                    "is_ssh":   bool(u.host and u.host not in ("", "localhost", "::1", "0.0.0.0")),
                })
        except Exception as exc:
            logger.debug("get_current_users error: %s", exc)
        return sessions

    # -- All local user accounts --------------------------------------------

    def get_all_users(self) -> list:
        """Returns all local user accounts (uid >= 1000 plus root) from /etc/passwd."""
        sudo_set = set(self.scan_sudo_users())
        users = []
        try:
            with open("/etc/passwd", "r") as fh:
                for line in fh:
                    parts = line.strip().split(":")
                    if len(parts) < 4:
                        continue
                    uname = parts[0]
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    if uid < 1000 and uname != "root":
                        continue
                    last_login = None
                    try:
                        r = subprocess.run(
                            ["lastlog", "-u", uname],
                            capture_output=True, text=True, timeout=5
                        )
                        lines = r.stdout.strip().splitlines()
                        if len(lines) >= 2:
                            last_line = lines[-1]
                            if "Never logged in" in last_line:
                                last_login = "Never"
                            else:
                                ll_parts = last_line.split()
                                if len(ll_parts) >= 5:
                                    last_login = " ".join(ll_parts[-5:])
                    except Exception:
                        pass
                    users.append({
                        "username":   uname,
                        "is_admin":   uname in sudo_set,
                        "last_login": last_login,
                    })
        except Exception as exc:
            logger.debug("get_all_users error: %s", exc)
        return users

    # -- OS info -------------------------------------------------------------

    def scan_os_info(self) -> dict:
        distro = "Unknown"
        kernel = "Unknown"

        try:
            os_release = {}
            with open("/etc/os-release") as fh:
                for line in fh:
                    line = line.strip()
                    if "=" in line:
                        k, _, v = line.partition("=")
                        os_release[k] = v.strip('"')
            distro = os_release.get("PRETTY_NAME") or os_release.get("ID", "Unknown")
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["uname", "-r"],
                capture_output=True, text=True, timeout=5
            )
            kernel = result.stdout.strip()
        except Exception:
            pass

        return {"distro": distro, "kernel": kernel}

    # -- Uptime --------------------------------------------------------------

    def get_uptime_seconds(self) -> int:
        try:
            with open("/proc/uptime") as fh:
                return int(float(fh.read().split()[0]))
        except Exception:
            return 0


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

    # SSH failed logins
    ssh = scan.get("sshFailedLogins", {})
    total_fails = ssh.get("total", 0)
    if total_fails >= 100:
        score -= 20
    elif total_fails >= 20:
        score -= 10
    elif total_fails >= 5:
        score -= 5

    # Firewall
    fw = scan.get("firewallStatus", {})
    if not fw.get("active", False):
        score -= 15

    # Dangerous open ports
    dangerous_count = sum(
        1 for p in scan.get("openPorts", []) if p.get("dangerous")
    )
    score -= min(dangerous_count * 15, 30)

    # SUID suspect files
    suid_count = len(scan.get("suidSuspect", []))
    score -= min(suid_count * 5, 15)

    # Suspicious processes
    sus_count = sum(
        1 for p in scan.get("processes", []) if p.get("suspicious")
    )
    if sus_count >= 3:
        score -= 15
    elif sus_count >= 1:
        score -= 8

    # Too many admin accounts
    admin_count = sum(1 for u in scan.get("localUsers", []) if u.get("is_admin"))
    if admin_count > 2:
        score -= 5

    return max(0, min(100, score))


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


# ---------------------------------------------------------------------------
# Agent actions
# ---------------------------------------------------------------------------

def send_heartbeat() -> dict:
    """Send liveness ping. Returns the response body (may contain heartbeat_paused)."""
    status, body = _post(HEARTBEAT_URL, {
        "token": AGENT_TOKEN,
        "deviceId": DEVICE_ID,
        "deviceName": DEVICE_NAME,
        "hostname": DEVICE_NAME,
        "agentVersion": AGENT_VERSION,
        "readOnlyMode": False,
        "os": "Linux",
    })
    if status == 200:
        logger.info("Heartbeat OK")
    else:
        logger.warning("Heartbeat failed (status=%s body=%s)", status, body)
    return body if isinstance(body, dict) else {}


def _handle_heartbeat_paused() -> None:
    """
    Server has paused heartbeats (e.g. daily Firestore write limit exceeded).
    Clear all scheduled tasks, then poll every 5 minutes for up to 1 hour.
    Once the server lifts the pause, restore the normal schedule.
    """
    logger.warning(
        "Heartbeats paused by server. Clearing schedule and retrying every 5 min …"
    )
    schedule.clear()

    _POLL_INTERVAL = 300   # 5 minutes
    _MAX_POLLS     = 12    # 12 × 5 min = 1 hour

    for _ in range(_MAX_POLLS):
        time.sleep(_POLL_INTERVAL)
        status, body = _post(HEARTBEAT_URL, {
            "token":        AGENT_TOKEN,
            "deviceId":     DEVICE_ID,
            "deviceName":   DEVICE_NAME,
            "hostname":     DEVICE_NAME,
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": False,
            "os":           "Linux",
        })
        paused = isinstance(body, dict) and body.get("heartbeat_paused", True)
        if status == 200 and not paused:
            logger.info("Pause lifted. Resuming normal operation.")
            schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)
            schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
            schedule.every(10).seconds.do(send_realtime_heartbeat)
            return

    # Still paused after 1 hour — restore only the heartbeat so we keep checking
    logger.warning("Still paused after 1 hour. Re-scheduling heartbeat only.")
    schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)


def send_realtime_heartbeat() -> None:
    global _net_cache, _net_last_time

    scanner = LinuxScanner()

    cpu = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    ram_percent = vm.percent
    ram_used_gb = round(vm.used / 1e9, 2)
    ram_total_gb = round(vm.total / 1e9, 2)

    top_procs = []
    try:
        raw = list(psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]))
        raw.sort(key=lambda p: p.info.get("cpu_percent") or 0, reverse=True)
        for p in raw[:5]:
            top_procs.append({
                "name":   p.info["name"] or "",
                "cpu":    round(p.info.get("cpu_percent") or 0.0, 1),
                "ram_mb": round((p.info["memory_info"].rss if p.info.get("memory_info") else 0) / 1e6, 1),
            })
    except Exception:
        pass

    temps = _safe("temperatures_realtime", scanner.scan_temperatures)

    now = time.time()
    if now - _net_last_time[0] >= 30:
        connected, latency_ms = scanner.get_internet_status()
        local_ip = scanner.get_local_ip()
        _net_cache = {
            "connected": connected,
            "latency_ms": latency_ms,
            "local_ip": local_ip,
        }
        _net_last_time[0] = now

    uptime_seconds = scanner.get_uptime_seconds()
    current_users  = _safe("current_users_realtime", scanner.get_current_users)

    payload = {
        "token": AGENT_TOKEN,
        "deviceId": DEVICE_ID,
        "deviceName": DEVICE_NAME,
        "agentVersion": AGENT_VERSION,
        "os": "Linux",
        "cpu_percent": round(cpu, 1),
        "ram_percent": ram_percent,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "top_processes": top_procs,
        "temperatures": temps,
        "network": _net_cache,
        "uptime_seconds": uptime_seconds,
        "current_users": current_users,
    }

    status, body = _post(REALTIME_URL, payload)
    if status not in (200, 204):
        logger.debug("Realtime heartbeat status=%s", status)

    # Handle pending commands
    pending = body.get("pendingCommands")
    if pending:
        execute_commands(pending)


def _is_valid_ipv4(ip: str) -> bool:
    """Validate each octet is a decimal integer 0–255 (defense in depth)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# Maximum bytes kept from command output stored in Firestore
_CMD_OUTPUT_LIMIT = 2000


def execute_commands(commands: list) -> None:
    scanner = LinuxScanner()
    for cmd in commands:
        cmd_type = cmd.get("type", "")
        cmd_id = cmd.get("id", "")
        success = False
        output = ""

        try:
            if cmd_type == "block_ip":
                ip = cmd.get("ip", "").strip()
                if ip and _is_valid_ipv4(ip):
                    result = subprocess.run(
                        ["ufw", "deny", "from", ip],
                        capture_output=True, text=True, timeout=10
                    )
                    output = (result.stdout + result.stderr)[:_CMD_OUTPUT_LIMIT]
                    success = result.returncode == 0
                elif ip:
                    output = "Invalid IP address rejected"
                else:
                    output = "No IP provided"

            elif cmd_type == "enable_ufw":
                result = subprocess.run(
                    ["ufw", "--force", "enable"],
                    capture_output=True, text=True, timeout=10
                )
                output = (result.stdout + result.stderr)[:_CMD_OUTPUT_LIMIT]
                success = result.returncode == 0

            else:
                output = f"Unknown command type: {cmd_type}"

        except FileNotFoundError as exc:
            output = f"Command not found: {exc}"
            success = False
        except subprocess.TimeoutExpired:
            output = "Command timed out"
            success = False
        except Exception as exc:
            output = str(exc)
            success = False

        logger.info(
            "Command %s type=%s success=%s output=%s",
            cmd_id, cmd_type, success, output[:200]
        )

        if cmd_id:
            _post(COMMAND_RESULT_URL, {
                "token": AGENT_TOKEN,
                "commandId": cmd_id,
                "deviceId": DEVICE_ID,
                "success": success,
                "output": output,
            })


def run_scan() -> None:
    logger.info("Starting full scan …")
    scanner = LinuxScanner()

    storage = _safe("scan_storage", scanner.scan_storage, [])
    processes = _safe("scan_processes", scanner.scan_processes, [])
    temperatures = _safe("scan_temperatures", scanner.scan_temperatures, [])
    ssh_failed = _safe("scan_ssh_failed_logins", scanner.scan_ssh_failed_logins, {})
    recent_logins = _safe("scan_recent_logins", scanner.scan_recent_logins, [])
    sudo_users = _safe("scan_sudo_users", scanner.scan_sudo_users, [])
    suid_suspect = _safe("scan_suid_suspects", scanner.scan_suid_suspects, [])
    world_writable = _safe("scan_world_writable_etc", scanner.scan_world_writable_etc, [])
    fw_status_raw = _safe("scan_firewall_status", scanner.scan_firewall_status, {})
    open_ports = _safe("scan_open_ports", scanner.scan_open_ports, [])
    os_info = _safe("scan_os_info", scanner.scan_os_info, {})
    uptime_seconds = _safe("get_uptime_seconds", scanner.get_uptime_seconds, 0)
    local_users = _safe("get_all_users", scanner.get_all_users, [])
    current_users = _safe("get_current_users", scanner.get_current_users, [])

    connected, latency_ms = scanner.get_internet_status()
    local_ip = scanner.get_local_ip()
    public_ip = _safe("get_public_ip", scanner.get_public_ip, None)

    # Firewall with grade
    fw_active = fw_status_raw.get("active", False)
    firewall_status = dict(fw_status_raw)
    firewall_status["grade"] = "A" if fw_active else "F"

    # Check if SSH is listening
    ssh_enabled = any(p["port"] == 22 for p in open_ports)

    network_info = {
        "connected": connected,
        "latency_ms": latency_ms,
        "local_ip": local_ip,
        "public_ip": public_ip,
        "rdp_enabled": False,
        "ssh_enabled": ssh_enabled,
        "open_ports": open_ports,
    }

    scan = {
        "token": AGENT_TOKEN,
        "deviceId": DEVICE_ID,
        "deviceName": DEVICE_NAME,
        "agentVersion": AGENT_VERSION,
        "hostname": DEVICE_NAME,
        "os": "Linux",
        "osInfo": os_info,
        "uptime": uptime_seconds,
        "storage": storage,
        "processes": processes,
        "temperatures": temperatures,
        "sshFailedLogins": ssh_failed,
        "recentLogins": recent_logins,
        "sudoUsers": sudo_users,
        "suidSuspect": suid_suspect,
        "worldWritableEtc": world_writable,
        "firewallStatus": firewall_status,
        "openPorts": open_ports,
        "networkInfo": network_info,
        "localUsers": local_users,
        "currentUsers": current_users,
        "healthScore": 0,  # placeholder, computed below
    }

    scan["healthScore"] = health_score(scan)

    status, body = _post(SUBMIT_SCAN_URL, scan)
    if status == 200:
        logger.info("Scan submitted OK (healthScore=%s)", scan["healthScore"])
    else:
        logger.warning("Scan submit failed (status=%s)", status)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global AGENT_TOKEN, DEVICE_ID, SCAN_INTERVAL, HEARTBEAT_SECS

    setup_logging()
    logger.info("PC Security Linux Agent v%s starting …", AGENT_VERSION)
    logger.info("Hostname: %s", DEVICE_NAME)

    cfg = load_config()

    AGENT_TOKEN = cfg.get("agent_token", "")
    if not AGENT_TOKEN:
        logger.warning(
            "No agent_token found in %s — agent will run but may be rejected by server.",
            CONFIG_PATH,
        )

    SCAN_INTERVAL = int(cfg.get("scan_interval", 300))
    HEARTBEAT_SECS = int(cfg.get("heartbeat_interval", 60))

    DEVICE_ID = resolve_device_id(cfg)
    logger.info("Device ID: %s", DEVICE_ID)

    # Immediate startup: check system status before proceeding
    startup_body = send_heartbeat()
    if startup_body.get("heartbeat_paused"):
        _handle_heartbeat_paused()
    else:
        run_scan()

    def _scheduled_heartbeat():
        body = send_heartbeat()
        if body.get("heartbeat_paused"):
            _handle_heartbeat_paused()

    # Schedule recurring tasks
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
