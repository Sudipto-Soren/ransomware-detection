#!/usr/bin/env bash
# run_dataset_collection.sh
#
# Runs multiple benign and ransomware-pattern sessions back-to-back
# and collects all events into one labeled NDJSON log file.
# Feature-extraction/ then converts that log into a labeled CSV.
#
# What this produces:
#   logs/events.ndjson   — every event from every session, labeled 0 or 1
#
# Usage:
#   chmod +x run_dataset_collection.sh
#   ./run_dataset_collection.sh
#
# Tune the variables below for your machine.
# On a fast Mac you can push RANSOM_SPEED to 30–50.
# On a slow VM, keep it at 5–10.

set -e
cd "$(dirname "$0")"   # Always run from the simulator/ directory

# ─── Configuration ────────────────────────────────────────────────────────────
SANDBOX="./test-sandbox"
LOG="./logs/events.ndjson"

BENIGN_SESSIONS=40          # number of benign runs to collect
RANSOM_SESSIONS=40          # number of ransomware-pattern runs to collect

BENIGN_DURATION=90          # seconds per benign session
RANSOM_SPEED_MIN=5          # files/sec — randomized between min and max
RANSOM_SPEED_MAX=25         #   so each session has different intensity
RANSOM_FILES_MIN=30         # files per ransomware session — also randomized
RANSOM_FILES_MAX=100        #   gives the model varied attack sizes to learn

# ─── Pre-flight checks ────────────────────────────────────────────────────────
if [ ! -d "$SANDBOX" ]; then
    echo "Sandbox not found. Creating it now..."
    python create_sandbox.py --sandbox-path "$SANDBOX" --num-files 150
fi

mkdir -p ./logs

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Dataset Collection"
echo "  $BENIGN_SESSIONS benign + $RANSOM_SESSIONS ransomware-pattern sessions"
echo "  Log: $LOG"
echo "═══════════════════════════════════════════════════════"

# ─── Benign sessions ──────────────────────────────────────────────────────────
# These don't modify files destructively, so no restore is needed between runs.
echo ""
echo "── Phase 1: Benign sessions ────────────────────────────"
for i in $(seq 1 $BENIGN_SESSIONS); do
    SESSION_ID=$(printf "benign-%04d" $i)
    echo ""
    echo "  Benign $i / $BENIGN_SESSIONS  →  session_id: $SESSION_ID"
    python benign_generator.py \
        --sandbox   "$SANDBOX" \
        --log       "$LOG" \
        --session-id "$SESSION_ID" \
        --duration  $BENIGN_DURATION
done

# ─── Ransomware-pattern sessions ──────────────────────────────────────────────
# Restore the sandbox between each run so every session starts from clean files.
echo ""
echo "── Phase 2: Ransomware-pattern sessions ────────────────"
for i in $(seq 1 $RANSOM_SESSIONS); do
    SESSION_ID=$(printf "ransom-%04d" $i)

    # Randomize speed and file count — avoids the model memorizing one pattern
    SPEED=$(python3 -c "import random; print(round(random.uniform($RANSOM_SPEED_MIN, $RANSOM_SPEED_MAX), 1))")
    MAX_FILES=$(python3 -c "import random; print(random.randint($RANSOM_FILES_MIN, $RANSOM_FILES_MAX))")

    echo ""
    echo "  Ransom $i / $RANSOM_SESSIONS  →  session_id: $SESSION_ID  speed=${SPEED}  max_files=${MAX_FILES}"
    python ransomware_pattern_generator.py \
        --sandbox    "$SANDBOX" \
        --log        "$LOG" \
        --session-id "$SESSION_ID" \
        --speed      "$SPEED" \
        --max-files  "$MAX_FILES"

    # Restore before the next session
    python restore_sandbox.py --sandbox "$SANDBOX"
done

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Collection complete."
echo ""
echo "  Events logged to: $LOG"
TOTAL=$(wc -l < "$LOG" | tr -d ' ')
BENIGN_COUNT=$(grep -c '"label": 0' "$LOG" || true)
RANSOM_COUNT=$(grep -c '"label": 1' "$LOG" || true)
echo "  Total events:     $TOTAL"
echo "  Label=0 events:   $BENIGN_COUNT"
echo "  Label=1 events:   $RANSOM_COUNT"
echo ""
echo "  Next step:"
echo "    cd ../feature-extraction"
echo "    python extractor.py --log ../simulator/logs/events.ndjson"
echo "═══════════════════════════════════════════════════════"
