#!/usr/bin/env bash
# PCGuard — macOS Agent Installer
# Supports: macOS 12+ (Monterey and later)
# Run: curl -sSL https://pcguard-rami.web.app/install-mac.sh | bash
# No sudo required.
#
# Token can be supplied via environment variable to avoid ps aux exposure:
#   PCGUARD_TOKEN=pcg-xxx curl -sSL https://pcguard-rami.web.app/install-mac.sh | bash

set -euo pipefail

INSTALL_DIR="$HOME/Library/Application Support/PCGuard"
LOG_DIR="$HOME/Library/Logs/PCGuard"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_LABEL="com.pcguard.agent"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$PLIST_LABEL.plist"
RELEASE_BASE="https://github.com/DNA-CyberSec/pc-security-dashboard/releases/latest/download"
RELEASE_URL="${RELEASE_BASE}/PCGuard-Mac.tar.gz"
CHECKSUM_URL="${RELEASE_BASE}/PCGuard-Mac.tar.gz.sha256"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── Temp file cleanup on any exit (normal, error, or signal) ─────────────────
TMP_TAR=""
TMP_SHA=""
cleanup() {
  rm -f "$TMP_TAR" "$TMP_SHA" 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   🍎  PCGuard — macOS Agent Installer        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── macOS version check ──────────────────────────────────────────────────────
SW_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "0")
MAJOR=$(echo "$SW_VERSION" | cut -d. -f1)
if [ "$MAJOR" -lt 12 ] 2>/dev/null; then
  echo -e "${RED}✗ macOS 12 (Monterey) or later is required. You have $SW_VERSION.${NC}"
  exit 1
fi
echo -e "  macOS $SW_VERSION — ${GREEN}✓${NC}"
echo ""

# ── Python3 check ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Python 3...${NC}"

PYTHON3=""
for candidate in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
  if command -v "$candidate" &>/dev/null 2>&1; then
    PYTHON3="$candidate"
    break
  fi
done

if [ -z "$PYTHON3" ]; then
  echo ""
  echo -e "${RED}✗ Python 3 not found.${NC}"
  echo ""
  echo "  Install it with one of these options:"
  echo ""
  echo "  Option A — Xcode Command Line Tools (free, recommended):"
  echo "    xcode-select --install"
  echo "    Then re-run this installer."
  echo ""
  echo "  Option B — Homebrew (if you have it):"
  echo "    brew install python3"
  echo "    Then re-run this installer."
  echo ""
  exit 1
fi

PY_VERSION=$("$PYTHON3" --version 2>&1)
echo -e "  $PY_VERSION — ${GREEN}✓${NC}"

# ── Download + verify agent ───────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Downloading and verifying PCGuard agent...${NC}"

mkdir -p "$INSTALL_DIR"

TMP_SHA="$(mktemp /tmp/pcguard-XXXXXX.sha256)"
TMP_TAR="$(mktemp /tmp/pcguard-XXXXXX.tar.gz)"

# Download checksum file first (from HTTPS — provides integrity anchor)
if ! curl -sSLf -o "$TMP_SHA" "$CHECKSUM_URL"; then
  echo -e "${RED}✗ Failed to download checksum file.${NC}"
  exit 1
fi

# Download tarball (--fail: treat HTTP 4xx/5xx as errors, not silent success)
if ! curl -sSLf -o "$TMP_TAR" "$RELEASE_URL"; then
  echo -e "${RED}✗ Download failed. Check internet connection.${NC}"
  exit 1
fi

# Verify SHA256 checksum (macOS uses shasum -a 256)
EXPECTED=$(awk '{print $1}' "$TMP_SHA")
ACTUAL=$(shasum -a 256 "$TMP_TAR" | awk '{print $1}')
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  echo -e "${RED}✗ CHECKSUM MISMATCH — download may be corrupted or tampered with.${NC}"
  echo -e "  Expected: ${EXPECTED}"
  echo -e "  Actual:   ${ACTUAL}"
  exit 1
fi
echo -e "  ${GREEN}✓ SHA256 checksum verified${NC}"

tar -xzf "$TMP_TAR" -C "$INSTALL_DIR"
echo -e "  ${GREEN}✓ Agent extracted${NC}"

# ── Python virtualenv + packages ────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Setting up Python environment...${NC}"

VENV_DIR="$INSTALL_DIR/venv"
"$PYTHON3" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install -q --upgrade pip
"$VENV_DIR/bin/pip" install -q --no-input -r "$INSTALL_DIR/requirements.txt"
echo -e "  ${GREEN}✓ Python environment ready${NC}"

# ── Agent Token ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Configuration${NC}"

# Prefer env var over interactive — env vars are NOT visible in ps aux
# Usage: PCGUARD_TOKEN=pcg-xxx curl -sSL ... | bash
AGENT_TOKEN="${PCGUARD_TOKEN:-}"

if [ -z "$AGENT_TOKEN" ]; then
  echo ""
  echo "  Your Agent Token links this Mac to your PCGuard account."
  echo "  Find it at: https://pcguard-rami.web.app/setup"
  echo ""
  echo "  Tip: set PCGUARD_TOKEN=pcg-... to avoid it appearing in process list."
  echo ""
  while true; do
    printf "  Paste your Agent Token (pcg-...): "
    read -r AGENT_TOKEN < /dev/tty
    if [ -n "$AGENT_TOKEN" ]; then
      break
    fi
    echo -e "  ${RED}✗ Token cannot be empty. Please try again.${NC}"
  done
fi

# Write config — mode 600 (owner-read/write only)
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/config.json" <<EOF
{
  "agent_token": "${AGENT_TOKEN}",
  "scan_interval": 300,
  "heartbeat_interval": 60
}
EOF
chmod 600 "$INSTALL_DIR/config.json"
echo -e "  ${GREEN}✓ Configuration saved (mode 600)${NC}"

# ── launchd plist ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Installing launchd service...${NC}"

mkdir -p "$LAUNCH_AGENTS_DIR"
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

VENV_PYTHON="$VENV_DIR/bin/python3"
AGENT_PY="$INSTALL_DIR/mac_agent.py"
LOG_FILE="$LOG_DIR/agent.log"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV_PYTHON}</string>
        <string>${AGENT_PY}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>${LOG_FILE}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

# Unload previous version if running
launchctl unload "$PLIST_PATH" 2>/dev/null || true

# Load and start the agent
launchctl load "$PLIST_PATH"
echo -e "  ${GREEN}✓ Service installed and started${NC}"

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗"
echo -e "║   ✓  PCGuard installed successfully!         ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Your Mac will appear in the dashboard within ~1 minute."
echo -e "  ${CYAN}🌐 View at: https://pcguard-rami.web.app${NC}"
echo ""
echo "  Useful commands:"
echo "    launchctl list | grep pcguard      — check status"
echo "    tail -f \"$LOG_FILE\"  — view live logs"
echo "    launchctl unload \"$PLIST_PATH\"  — stop agent"
echo "    launchctl load   \"$PLIST_PATH\"  — start agent"
echo ""
