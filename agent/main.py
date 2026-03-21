"""
PC Health & Security Agent
--------------------------
Runs locally on the Windows PC being monitored.
Communicates with Firebase Firestore to:
  - Send heartbeat (so the web app knows the agent is alive)
  - Write scan results
  - Poll for pending actions from the web app (clean/backup commands)

Safety principles enforced here:
  - Read-only mode by default
  - Preview before deletion
  - Auto backup before any cleanup
  - Full undo capability via restore from backup
  - Detailed action log written to Firestore
"""

import os
import sys
import json
import time
import logging
import schedule
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore

from modules.scanner import Scanner
from modules.cleaner import Cleaner
from modules.backup import BackupManager
from modules.privacy import PrivacyScanner

# ── Config ────────────────────────────────────────────────────────────────────

load_dotenv()

FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH", "serviceAccountKey.json")
USER_ID = os.getenv("USER_ID", "")          # Set after first auth via web app
HEARTBEAT_INTERVAL = 30                      # seconds
SCAN_INTERVAL_MINUTES = 60                   # auto-scan every hour
READ_ONLY_MODE = True                        # Safety: default read-only

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("agent.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

# ── Firebase init ─────────────────────────────────────────────────────────────

def init_firebase():
    if not os.path.exists(FIREBASE_CRED_PATH):
        log.error(f"Firebase credentials not found at '{FIREBASE_CRED_PATH}'")
        log.error("Download your service account key from Firebase Console and place it here.")
        sys.exit(1)
    cred = credentials.Certificate(FIREBASE_CRED_PATH)
    firebase_admin.initialize_app(cred)
    return firestore.client()

# ── Heartbeat ─────────────────────────────────────────────────────────────────

def send_heartbeat(db):
    if not USER_ID:
        return
    try:
        db.collection("agents").document(USER_ID).set({
            "lastHeartbeat": firestore.SERVER_TIMESTAMP,
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "agentVersion": "0.1.0",
            "readOnlyMode": READ_ONLY_MODE,
        }, merge=True)
        log.debug("Heartbeat sent")
    except Exception as e:
        log.error(f"Heartbeat failed: {e}")

# ── Scan & upload ─────────────────────────────────────────────────────────────

def run_scan(db):
    if not USER_ID:
        log.warning("USER_ID not set — skipping scan upload")
        return

    log.info("Starting system scan...")
    scanner = Scanner(read_only=True)
    privacy = PrivacyScanner(read_only=True)

    scan_result = {
        "userId": USER_ID,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "agentVersion": "0.1.0",
        "healthScore": None,           # calculated after all modules
        "storage": scanner.scan_storage(),
        "tempFiles": scanner.scan_temp_files(),
        "largeFiles": scanner.scan_large_files(),
        "duplicates": scanner.scan_duplicates(),
        "startupItems": scanner.scan_startup_items(),
        "browserData": privacy.scan_browser_data(),
        "vulnerabilities": scanner.scan_vulnerabilities(),
        "outdatedSoftware": scanner.scan_outdated_software(),
    }

    scan_result["healthScore"] = _calculate_health_score(scan_result)

    doc_ref = db.collection("scans").document()
    doc_ref.set(scan_result)
    log.info(f"Scan complete. Health score: {scan_result['healthScore']}/100. Doc: {doc_ref.id}")
    return doc_ref.id

def _calculate_health_score(result):
    score = 100
    if len(result.get("tempFiles", [])) > 50:
        score -= 10
    if len(result.get("vulnerabilities", [])) > 0:
        score -= 20
    if len(result.get("outdatedSoftware", [])) > 3:
        score -= 10
    storage = result.get("storage", {})
    if storage.get("usedPercent", 0) > 90:
        score -= 15
    return max(0, score)

# ── Action polling ────────────────────────────────────────────────────────────

def poll_pending_actions(db):
    """
    Web app writes pending_actions to Firestore; agent picks them up here.
    Every action creates an audit log entry regardless of outcome.
    """
    if not USER_ID:
        return
    try:
        actions_ref = (
            db.collection("pending_actions")
            .where("userId", "==", USER_ID)
            .where("status", "==", "pending")
            .limit(5)
            .stream()
        )
        for action_doc in actions_ref:
            action = action_doc.to_dict()
            _execute_action(db, action_doc.id, action)
    except Exception as e:
        log.error(f"Action poll error: {e}")

def _execute_action(db, action_id, action):
    action_type = action.get("type")
    payload = action.get("payload", {})
    log.info(f"Executing action: {action_type} | payload keys: {list(payload.keys())}")

    result = {"status": "error", "message": "Unknown action"}

    try:
        if READ_ONLY_MODE and action_type not in ("preview",):
            result = {"status": "blocked", "message": "Agent is in read-only mode"}
        elif action_type == "clean":
            result = _handle_clean(payload)
        elif action_type == "backup":
            result = _handle_backup(payload)
        elif action_type == "undo":
            result = _handle_undo(payload)
        elif action_type == "preview":
            result = {"status": "ok", "preview": payload.get("items", [])}
    except Exception as e:
        result = {"status": "error", "message": str(e)}
        log.exception(f"Action {action_type} failed")

    # Update action doc + write audit log
    db.collection("pending_actions").document(action_id).update({
        "status": result["status"],
        "result": result,
        "completedAt": firestore.SERVER_TIMESTAMP,
    })
    db.collection("action_log").add({
        "userId": USER_ID,
        "actionId": action_id,
        "actionType": action_type,
        "payload": payload,
        "result": result,
        "timestamp": firestore.SERVER_TIMESTAMP,
    })

def _handle_clean(payload):
    cleaner = Cleaner(read_only=READ_ONLY_MODE)
    backup_mgr = BackupManager()

    items = payload.get("items", [])
    if not items:
        return {"status": "error", "message": "No items specified"}

    # Auto backup before clean
    backup_path = backup_mgr.create_backup(items)
    log.info(f"Backup created at: {backup_path}")

    result = cleaner.clean_items(items)
    return {
        "status": "ok",
        "cleaned": result["cleaned"],
        "failed": result["failed"],
        "backupPath": backup_path,
    }

def _handle_backup(payload):
    backup_mgr = BackupManager()
    items = payload.get("items", [])
    backup_path = backup_mgr.create_backup(items)
    return {"status": "ok", "backupPath": backup_path}

def _handle_undo(payload):
    backup_mgr = BackupManager()
    backup_path = payload.get("backupPath")
    if not backup_path:
        return {"status": "error", "message": "No backup path provided"}
    backup_mgr.restore_backup(backup_path)
    return {"status": "ok", "restored": backup_path}

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    log.info("PC Security Agent starting...")
    log.info(f"Read-only mode: {READ_ONLY_MODE}")

    if not USER_ID:
        log.warning(
            "USER_ID is not set in .env — agent will not upload results.\n"
            "Set USER_ID to your Firebase user UID after signing in via the web app."
        )

    db = init_firebase()

    # Initial scan on startup
    run_scan(db)

    # Schedules
    schedule.every(HEARTBEAT_INTERVAL).seconds.do(send_heartbeat, db)
    schedule.every(SCAN_INTERVAL_MINUTES).minutes.do(run_scan, db)
    schedule.every(10).seconds.do(poll_pending_actions, db)

    log.info("Agent running. Press Ctrl+C to stop.")
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
