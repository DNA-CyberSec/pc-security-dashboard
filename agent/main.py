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
import socket
import logging
import requests
import schedule
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

FUNCTIONS_BASE  = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL   = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL = f"{FUNCTIONS_BASE}/submitScan"
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
            "hostname":     socket.gethostname(),
            "username":     os.environ.get("USERNAME", "unknown"),
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": READ_ONLY,
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
        "processes":         _safe("processes",       ProcessScanner().scan_processes),
        "networkConnections":_safe("network",         NetworkScanner().scan_connections),
        "browserData":       _safe("browser",         PrivacyScanner().scan_browser_data),
    }

    scan["healthScore"] = _health_score(scan)
    log.info(f"Health score: {scan['healthScore']}/100")

    try:
        r = requests.post(SUBMIT_SCAN_URL, json={
            "token": AGENT_TOKEN,
            "scan":  scan,
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

    # Run immediately on startup
    send_heartbeat()
    run_scan()

    # Schedule recurring tasks
    schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)

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
