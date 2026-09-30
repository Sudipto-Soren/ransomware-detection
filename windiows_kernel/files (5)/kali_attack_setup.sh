#!/usr/bin/env bash
# kali_attack_setup.sh
# Run on Kali Linux — sets up SMB mount and prepares the attack environment.
#
# Network layout:
#   Kali   : this machine (bridged NIC, on LAN)
#   Windows: 10.0.8.35  (victim, SMB share \\10.0.8.35\TestShare)
#   Mac    : 10.0.8.160 (backend :8000, dashboard :5173)
#
# What this does:
#   1. Installs cifs-utils (SMB client for Linux)
#   2. Mounts \\10.0.8.35\TestShare at /mnt/win-sandbox
#   3. Clones the project (if not already present)
#   4. Installs Python dependencies
#   5. Prints next steps

set -e

WINDOWS_IP="10.0.8.35"
MAC_IP="10.0.8.160"
SHARE_PATH="/mnt/win-sandbox"
PROJECT_DIR="$HOME/ransomware-detection"

echo ""
echo "============================================================"
echo "  RansomDet — Kali Attacker Setup"
echo "  Target: \\\\${WINDOWS_IP}\\TestShare"
echo "  Backend: http://${MAC_IP}:8000"
echo "============================================================"
echo ""

# ── 1. Install SMB client ─────────────────────────────────────────────────────
echo "[1/5] Installing cifs-utils (SMB client)..."
apt-get install -y cifs-utils python3-pip python3-venv 2>/dev/null | tail -3

# ── 2. Mount Windows share ────────────────────────────────────────────────────
echo ""
echo "[2/5] Mounting Windows share..."
mkdir -p "$SHARE_PATH"

# Unmount if already mounted
umount "$SHARE_PATH" 2>/dev/null || true

# Mount with guest access (no password — Windows share is open for demo)
mount -t cifs "//${WINDOWS_IP}/TestShare" "$SHARE_PATH" \
    -o username=Guest,password=,vers=2.0,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777 \
    2>/dev/null || \
mount -t cifs "//${WINDOWS_IP}/TestShare" "$SHARE_PATH" \
    -o guest,vers=2.0,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777

echo "  Mounted: ${SHARE_PATH}"
echo "  Contents:"
ls "$SHARE_PATH" | head -10

# ── 3. Set up project ─────────────────────────────────────────────────────────
echo ""
echo "[3/5] Setting up project..."
if [ ! -d "$PROJECT_DIR" ]; then
    echo "  Cloning from GitHub..."
    read -p "  Enter your GitHub repo URL: " REPO_URL
    git clone "$REPO_URL" "$PROJECT_DIR"
else
    echo "  Project already at $PROJECT_DIR"
    cd "$PROJECT_DIR" && git pull --quiet
fi

# ── 4. Python environment ─────────────────────────────────────────────────────
echo ""
echo "[4/5] Installing Python dependencies..."
cd "$PROJECT_DIR/simulator"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q watchdog psutil pandas numpy requests

# ── 5. Print next steps ───────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Setup complete."
echo ""
echo "  Windows share mounted at: $SHARE_PATH"
echo "  Project directory:        $PROJECT_DIR"
echo ""
echo "  To run the ATTACK DEMO:"
echo "    bash kali_run_demo.sh"
echo ""
echo "  Watch the Mac dashboard at: http://${MAC_IP}:5173"
echo "============================================================"
echo ""
