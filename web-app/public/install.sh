#!/usr/bin/env bash
# PC Guard — Linux Agent Installer
# Supports: Ubuntu 18+, Debian 10+
# Run as root: curl -sSL https://pcguard-rami.web.app/install.sh | bash

set -e

INSTALL_DIR="/opt/pcguard"
SERVICE_FILE="/etc/systemd/system/pcguard.service"
RELEASE_URL="https://github.com/DNA-CyberSec/pc-security-dashboard/releases/latest/download/PCGuard-Linux.tar.gz"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   🛡️  PC Guard — Linux Agent Installer       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}✗ This script must be run as root (use sudo).${NC}"
  exit 1
fi

# ── Detect OS ─────────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME="${PRETTY_NAME:-Linux}"
else
  OS_NAME="Linux"
fi
echo -e "  OS: ${OS_NAME}"
echo ""

# ── Install dependencies ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking dependencies...${NC}"

install_pkg() {
  if ! command -v "$1" &>/dev/null; then
    echo "  Installing $1..."
    apt-get install -y -q "$2" 2>/dev/null || yum install -y "$2" 2>/dev/null || true
  fi
}

if command -v apt-get &>/dev/null; then
  apt-get update -q
fi

install_pkg python3 python3
install_pkg curl curl

# python3-venv + python3-full needed on Debian 12+ (PEP 668 externally-managed-environment)
if command -v apt-get &>/dev/null; then
  apt-get install -y -q python3-venv python3-full 2>/dev/null || true
fi

echo -e "  ${GREEN}✓ Dependencies ready${NC}"

# ── Download agent ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Downloading PC Guard agent...${NC}"

mkdir -p "$INSTALL_DIR"

TMP_TAR="$(mktemp /tmp/pcguard-XXXXXX.tar.gz)"
if curl -sSL -o "$TMP_TAR" "$RELEASE_URL"; then
  tar -xzf "$TMP_TAR" -C "$INSTALL_DIR"
  rm -f "$TMP_TAR"
  echo -e "  ${GREEN}✓ Agent downloaded${NC}"
else
  echo -e "  ${RED}✗ Download failed. Check internet connection.${NC}"
  exit 1
fi

# ── Create virtual environment + install packages ─────────────────────────────
echo -e "${YELLOW}[3/5] Setting up Python virtual environment...${NC}"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements-linux.txt"
echo -e "  ${GREEN}✓ Python virtual environment ready${NC}"

# ── Get Agent Token ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Configuration${NC}"

# Support passing token as argument: bash -s -- YOUR_TOKEN
AGENT_TOKEN="${1:-}"

if [ -z "$AGENT_TOKEN" ]; then
  echo ""
  echo "  Your Agent Token links this server to your PC Guard account."
  echo "  Find it at: https://pcguard-rami.web.app/setup"
  echo ""
  # When piped via curl | bash, stdin is the script itself — use /dev/tty
  while true; do
    printf "  Paste your Agent Token (pcg-...): "
    read -r AGENT_TOKEN < /dev/tty
    if [ -n "$AGENT_TOKEN" ]; then
      break
    fi
    echo -e "  ${RED}✗ Token cannot be empty. Please try again.${NC}"
  done
fi

# Write config
cat > "$INSTALL_DIR/config.json" <<EOF
{
  "agent_token": "${AGENT_TOKEN}",
  "scan_interval": 300,
  "heartbeat_interval": 60
}
EOF
chmod 600 "$INSTALL_DIR/config.json"
echo -e "  ${GREEN}✓ Configuration saved${NC}"

# ── Create systemd service ────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Creating systemd service...${NC}"

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=PC Guard Security Agent
Documentation=https://pcguard-rami.web.app
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/pcguard/venv/bin/python3 /opt/pcguard/linux_agent.py
Restart=always
RestartSec=10
StandardOutput=append:/opt/pcguard/agent.log
StandardError=append:/opt/pcguard/agent.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pcguard
systemctl start pcguard

echo -e "  ${GREEN}✓ Service installed and started${NC}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗"
echo -e "║   ✓  PC Guard installed successfully!        ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Your server will appear in the dashboard within ~1 minute."
echo "  🌐 View at: https://pcguard-rami.web.app"
echo ""
echo "  Useful commands:"
echo "    systemctl status pcguard   — check status"
echo "    journalctl -u pcguard -f   — view live logs"
echo "    systemctl stop pcguard     — stop the agent"
echo ""
