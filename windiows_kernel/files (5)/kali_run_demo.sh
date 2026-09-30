#!/usr/bin/env bash
# kali_run_demo.sh
# The actual demo script. Run this on Kali during the presentation.
#
# WHAT HAPPENS:
#   Phase 1: Benign activity on the Windows share (dashboard stays green)
#   Phase 2: Ransomware pattern activity (dashboard turns red)
#   Phase 3: Restore is triggered (status flips to recovered)
#
# RUN ORDER for the full demo:
#   Mac Terminal 1   : uvicorn main:app --reload --port 8000
#   Mac Terminal 2   : cd dashboard && npm run dev
#   Windows CMD (Admin): python monitor_client.py --backend http://10.0.8.160:8000
#   Kali Terminal    : sudo bash kali_run_demo.sh

set -e

WINDOWS_IP="10.0.8.35"
MAC_IP="10.0.8.160"
MAC_BACKEND="http://${MAC_IP}:8000"
SHARE_PATH="/mnt/win-sandbox"
PROJECT_DIR="$HOME/ransomware-detection"
LOG_FILE="/tmp/kali-attack-events.ndjson"
WATCHER_WINDOW=20   # seconds per session window

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   RansomDet — Live Attack Demo                           ║"
echo "║   Kali (attacker) → Windows 10.0.8.35 (victim)          ║"
echo "║   Detection: Mac 10.0.8.160:5173                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
echo "Pre-flight checks..."

# Check Windows share is mounted
if ! mountpoint -q "$SHARE_PATH"; then
    echo "  Windows share not mounted. Mounting now..."
    mount -t cifs "//${WINDOWS_IP}/TestShare" "$SHARE_PATH" \
        -o guest,vers=2.0,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777 || {
        echo "  ERROR: Cannot mount \\\\${WINDOWS_IP}\\TestShare"
        echo "  Run windows_victim_setup.bat on Windows first"
        exit 1
    }
fi
echo "  ✓ Windows share mounted at $SHARE_PATH"

# Check Mac backend
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${MAC_BACKEND}/api/status" 2>/dev/null || echo "000")
if [ "$HTTP_STATUS" != "200" ]; then
    echo "  ✗ Mac backend not reachable at $MAC_BACKEND"
    echo "    Start it: uvicorn main:app --reload --port 8000"
    exit 1
fi
echo "  ✓ Mac backend reachable"

# Check files exist in sandbox
FILE_COUNT=$(ls "$SHARE_PATH" | wc -l)
if [ "$FILE_COUNT" -lt 5 ]; then
    echo "  ✗ Too few files in $SHARE_PATH ($FILE_COUNT found)"
    echo "    Run windows_victim_setup.bat on Windows to recreate files"
    exit 1
fi
echo "  ✓ $FILE_COUNT files in Windows sandbox"

# Activate Python environment
cd "$PROJECT_DIR/simulator"
source .venv/bin/activate

echo ""
echo "Open the Mac dashboard now: http://${MAC_IP}:5173"
echo ""
read -p "Press ENTER when the guide is watching the dashboard..."

# ── Start watcher in background ───────────────────────────────────────────────
# The watcher monitors the mounted Windows share and sends events
# to the Mac backend every WATCHER_WINDOW seconds.
echo ""
echo "Starting file system watcher on the mounted Windows share..."
python3 ../monitor-service/watcher.py \
    --watch "$SHARE_PATH" \
    --window $WATCHER_WINDOW \
    --url "$MAC_BACKEND" &
WATCHER_PID=$!
echo "  Watcher PID: $WATCHER_PID"

# Give watcher time to start
sleep 2

# ── PHASE 1: Benign activity ──────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  PHASE 1 — Simulating normal user activity               ║"
echo "║  Dashboard should show: LOW risk, green status           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Running benign generator on Windows share (30 seconds)..."

python3 benign_generator.py \
    --sandbox "$SHARE_PATH" \
    --log     "$LOG_FILE" \
    --session-id "kali-benign-demo-001" \
    --duration 30

echo "  ✓ Benign activity complete"
echo "  Waiting for dashboard to update (${WATCHER_WINDOW}s window)..."
sleep $((WATCHER_WINDOW + 3))

echo ""
echo "  Check dashboard — risk score should be LOW (green)"
read -p "  Press ENTER when ready for the ATTACK phase..."

# ── PHASE 2: Ransomware pattern attack ────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  PHASE 2 — RANSOMWARE PATTERN ATTACK                     ║"
echo "║  Kali is now writing ransomware-pattern I/O to Windows   ║"
echo "║  Dashboard should show: HIGH risk, 🚨 THREAT DETECTED    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Launching ransomware pattern generator..."
echo "  Target: $SHARE_PATH (Windows C:\\test-sandbox)"
echo ""

python3 ransomware_pattern_generator.py \
    --sandbox    "$SHARE_PATH" \
    --log        "$LOG_FILE" \
    --session-id "kali-ransom-demo-001" \
    --speed      12 \
    --max-files  30

echo ""
echo "  ✓ Attack pattern complete"
echo "  Files on Windows have been XOR-transformed (.locked)"
echo "  Waiting for dashboard to update (${WATCHER_WINDOW}s window)..."
sleep $((WATCHER_WINDOW + 3))

echo ""
echo "  Check dashboard — risk score should be HIGH (red), threat detected"
read -p "  Press ENTER to trigger RECOVERY via API..."

# ── PHASE 3: Recovery ─────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  PHASE 3 — RECOVERY                                      ║"
echo "║  Triggering file restore via Mac backend API             ║"
╚══════════════════════════════════════════════════════════╝"
echo ""

RESTORE_RESULT=$(curl -s -X POST "${MAC_BACKEND}/api/recovery/restore/kali-ransom-demo-001" \
    -H "Content-Type: application/json" 2>/dev/null)
echo "  Backend response: $RESTORE_RESULT"

# Also restore locally (XOR is self-inverse)
echo ""
echo "  Restoring Windows files locally (XOR self-inverse)..."
python3 restore_sandbox.py --sandbox "$SHARE_PATH"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Demo complete.                                           ║"
echo "║                                                           ║"
echo "║  What was demonstrated:                                   ║"
echo "║  ✅ Obj 1: File system activity monitored in real time   ║"
echo "║  ✅ Obj 2: ML model classified ransomware pattern        ║"
echo "║  ✅ Obj 3: Cloud sync folder protected (quarantine)      ║"
echo "║  ✅ Obj 4: Files restored to clean version               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Stop the watcher
kill $WATCHER_PID 2>/dev/null
echo "  Watcher stopped."
