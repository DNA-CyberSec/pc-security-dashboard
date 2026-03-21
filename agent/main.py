"""
PC Security Agent v0.5.0
-------------------------
Public SaaS agent — no service account required.

Setup:
  1. Sign in at https://pcguard-rami.web.app
  2. Copy your AgentToken from the Setup page
  3. Paste it into agent/.env as AGENT_TOKEN=pcg-...
  4. Run: python main.py

Authentication: the agent sends its AgentToken to Firebase Cloud Functions.
The server validates the token and writes data under the correct user's
isolated Firestore path (/users/{uid}/).

SAFETY: READ-ONLY — this agent never modifies any file or system setting.
"""

import os
import sys
import time
import uuid
import socket
import logging
import requests
import schedule
import winreg
from dotenv import load_dotenv

from modules.scanner   import Scanner
from modules.processes import ProcessScanner
from modules.network   import NetworkScanner
from modules.privacy   import PrivacyScanner

# ── Config ────────────────────────────────────────────────────────────────────

load_dotenv()

AGENT_VERSION   = "0.5.0"
AGENT_TOKEN     = os.getenv("AGENT_TOKEN", "")
SCAN_INTERVAL   = int(os.getenv("SCAN_INTERVAL",       "300"))  # seconds
HEARTBEAT_SECS  = int(os.getenv("HEARTBEAT_INTERVAL",  "60"))
READ_ONLY       = True

# Device identity — hardware-based, survives reinstalls
_DEVICE_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_id.txt")

def _get_stable_device_id():
    """
    Returns a permanent, hardware-based ID for this PC.
    Priority: MachineGuid → MAC-UUID → saved file → new UUID
    """
    # 1. Windows MachineGuid — immutable, set during Windows install
    try:
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        guid, _ = winreg.QueryValueEx(k, "MachineGuid")
        winreg.CloseKey(k)
        if guid and guid.strip():
            return guid.strip().lower()
    except Exception:
        pass

    # 2. Primary NIC MAC address → deterministic UUID
    try:
        mac = uuid.getnode()
        if not (mac >> 40) & 1:  # skip multicast / random MACs
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(mac)))
    except Exception:
        pass

    # 3. Previously saved device_id.txt (backward compat)
    if os.path.exists(_DEVICE_ID_FILE):
        with open(_DEVICE_ID_FILE) as f:
            did = f.read().strip()
        if did:
            return did

    # 4. New UUID (last resort)
    return str(uuid.uuid4())

DEVICE_ID   = _get_stable_device_id()
DEVICE_NAME = os.environ.get("COMPUTERNAME", socket.gethostname())

# Cache resolved ID for fast startup
try:
    with open(_DEVICE_ID_FILE, "w") as _f:
        _f.write(DEVICE_ID)
except Exception:
    pass

FUNCTIONS_BASE     = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL      = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL    = f"{FUNCTIONS_BASE}/submitScan"
REALTIME_URL       = f"{FUNCTIONS_BASE}/realtimeHeartbeat"
REQUEST_TIMEOUT = 30  # seconds

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("agent.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("agent")

# ── Heartbeat ─────────────────────────────────────────────────────────────────

def send_heartbeat():
    if not AGENT_TOKEN:
        return
    try:
        r = requests.post(HEARTBEAT_URL, json={
            "token":        AGENT_TOKEN,
            "deviceId":     DEVICE_ID,
            "deviceName":   DEVICE_NAME,
            "hostname":     socket.gethostname(),
            "username":     os.environ.get("USERNAME", "unknown"),
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": READ_ONLY,
            "os":           "Windows",
        }, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            log.debug("Heartbeat sent")
        elif r.status_code == 401:
            log.error("Heartbeat rejected — AgentToken is invalid. Check your .env file.")
        else:
            log.warning(f"Heartbeat returned {r.status_code}: {r.text[:100]}")
    except requests.RequestException as e:
        log.warning(f"Heartbeat failed (network): {e}")

# ── Scan ──────────────────────────────────────────────────────────────────────

def run_scan():
    if not AGENT_TOKEN:
        log.warning("AGENT_TOKEN not set — scan not uploaded. See agent/.env")
        return

    log.info("=" * 60)
    log.info("Starting full system scan...")

    scan = {
        "agentVersion":      AGENT_VERSION,
        "hostname":          socket.gethostname(),
        "healthScore":       None,
        "storage":           _safe("storage",         Scanner().scan_all_drives),
        "tempSummary":       _safe("temp_summary",    Scanner().scan_temp_summary),
        "largeFiles":        _safe("large_files",     Scanner().scan_large_files),
        "startupItems":      _safe("startup_items",   Scanner().scan_startup_items),
        "installedSoftware": _safe("installed_sw",    Scanner().scan_installed_software),
        "vulnerabilities":   _safe("vulnerabilities", Scanner().scan_vulnerabilities),
        "malwareSuspects":   _safe("malware",         Scanner().scan_malware_suspects),
        "startupSecurity":   _safe("startup_sec",     Scanner().scan_startup_security),
        "firewallStatus":    _safe("firewall",        Scanner().scan_firewall_status),
        "processes":         _safe("processes",       ProcessScanner().scan_processes),
        "networkConnections":_safe("network",         NetworkScanner().scan_connections),
        "browserData":       _safe("browser",         PrivacyScanner().scan_browser_data),
    }

    scan["healthScore"] = _health_score(scan)
    log.info(f"Health score: {scan['healthScore']}/100")

    try:
        r = requests.post(SUBMIT_SCAN_URL, json={
            "token":    AGENT_TOKEN,
            "deviceId": DEVICE_ID,
            "scan":     scan,
        }, timeout=REQUEST_TIMEOUT)

        if r.status_code == 200:
            scan_id = r.json().get("scanId", "?")
            log.info(f"Scan uploaded — id: {scan_id}")
        elif r.status_code == 401:
            log.error("Scan rejected — AgentToken is invalid. Check your .env file.")
        else:
            log.error(f"Scan upload failed {r.status_code}: {r.text[:200]}")
    except requests.RequestException as e:
        log.error(f"Scan upload failed (network): {e}")

    log.info("=" * 60)

def _safe(name, fn):
    try:
        result = fn()
        count = len(result) if isinstance(result, list) else len(result) if isinstance(result, dict) else "?"
        log.info(f"  [{name}] OK ({count} items)")
        return result
    except Exception as e:
        log.error(f"  [{name}] FAILED: {e}")
        return [] if name not in ("storage", "temp_summary") else {}

# ── Health score ──────────────────────────────────────────────────────────────

def _health_score(scan: dict) -> int:
    score = 100

    for drive in scan.get("storage", []):
        pct = drive.get("usedPercent", 0)
        if pct >= 90:   score -= 20
        elif pct >= 80: score -= 10

    temp_bytes = scan.get("tempSummary", {}).get("totalBytes", 0)
    if temp_bytes > 1 * 1024 ** 3:
        score -= 10

    for v in scan.get("vulnerabilities", []):
        if v.get("severity") == "critical": score -= 15
        elif v.get("severity") == "high":   score -= 8
        elif v.get("severity") == "medium": score -= 3

    suspicious_procs = sum(1 for p in scan.get("processes", []) if p.get("suspicious"))
    if   suspicious_procs >= 3: score -= 15
    elif suspicious_procs >= 1: score -= 8

    suspicious_conns = sum(1 for c in scan.get("networkConnections", []) if c.get("suspicious"))
    score -= min(suspicious_conns * 5, 20)

    return max(0, min(100, score))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info(f"PC Security Agent v{AGENT_VERSION}  [READ-ONLY: {READ_ONLY}]")

    if not AGENT_TOKEN:
        log.error("─" * 60)
        log.error("AGENT_TOKEN is not set in .env")
        log.error("")
        log.error("  1. Sign in at https://pcguard-rami.web.app")
        log.error("  2. Go to the Setup page")
        log.error("  3. Copy your AgentToken")
        log.error("  4. Add to agent/.env:  AGENT_TOKEN=pcg-...")
        log.error("─" * 60)
        sys.exit(1)

    def send_realtime_heartbeat():
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            procs = []
            for p in psutil.process_iter(["name", "cpu_percent", "memory_info"]):
                try:
                    procs.append({
                        "name":   p.info["name"] or "",
                        "cpu":    round(p.info["cpu_percent"] or 0, 1),
                        "ram_mb": round((p.info["memory_info"].rss if p.info["memory_info"] else 0) / 1e6, 1),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            top5 = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:5]
            temps = []
            try:
                raw = psutil.sensors_temperatures()
                if raw:
                    for name, entries in raw.items():
                        for e in entries:
                            temps.append({"label": e.label or name, "current": round(e.current, 1)})
                    temps = temps[:8]
            except Exception:
                pass
            r = requests.post(REALTIME_URL, json={
                "token":         AGENT_TOKEN,
                "deviceId":      DEVICE_ID,
                "cpu_percent":   round(cpu, 1),
                "ram_percent":   round(mem.percent, 1),
                "ram_used_gb":   round(mem.used  / 1e9, 2),
                "ram_total_gb":  round(mem.total / 1e9, 2),
                "top_processes": top5,
                "temperatures":  temps,
            }, timeout=10)
            if r.status_code != 200:
                log.debug(f"Realtime heartbeat: {r.status_code}")
        except Exception as e:
            log.debug(f"Realtime heartbeat error: {e}")

    # Run immediately on startup
    send_heartbeat()
    run_scan()

    # Schedule recurring tasks
    schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    schedule.every(10).seconds.do(send_realtime_heartbeat)

    log.info(f"Heartbeat every {HEARTBEAT_SECS}s | Scan every {SCAN_INTERVAL}s")
    log.info("Agent running. Press Ctrl+C to stop.")

    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Agent stopped.")
