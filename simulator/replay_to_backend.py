"""
simulator/replay_to_backend.py

Reads the collected events.ndjson log and sends each session
to the running FastAPI backend one by one.

This is the glue between the simulator (Track B) and the
backend + dashboard (Tracks C & D). After running this:
  - Every session appears in the dashboard's session feed
  - Ransomware-pattern sessions appear in the threats panel
  - Cloud quarantine shows blocked files
  - The restore button becomes active on flagged sessions

Usage:
  python replay_to_backend.py --log ./logs/events.ndjson
  python replay_to_backend.py --log ./logs/events.ndjson --limit 10
  python replay_to_backend.py --log ./logs/events.ndjson --delay 1.5

  --limit N   only send the first N sessions (good for quick testing)
  --delay S   wait S seconds between sessions (watch the dashboard
              update in real time during a demo)
  --url       backend base URL (default http://localhost:8000)
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path


def load_sessions(log_path: Path) -> dict[str, list[dict]]:
    """Group events by session_id, preserving timestamp order."""
    sessions: dict[str, list[dict]] = defaultdict(list)
    skipped = 0

    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                sid = event.get("session_id")
                if sid:
                    sessions[sid].append(event)
                else:
                    skipped += 1
            except json.JSONDecodeError:
                skipped += 1

    if skipped:
        print(f"  Skipped {skipped} malformed lines")

    # Sort each session's events by timestamp
    for sid in sessions:
        sessions[sid].sort(key=lambda e: e.get("timestamp", ""))

    return dict(sessions)


def post_session(url: str, events: list[dict]) -> dict:
    """POST one session's events to /api/sessions/ingest."""
    payload = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        if e.code == 409:
            return {"_skipped": True, "reason": "already ingested"}
        raise RuntimeError(f"HTTP {e.code}: {body[:200]}")


def check_backend(base_url: str) -> bool:
    """Verify the backend is reachable before starting."""
    try:
        with urllib.request.urlopen(f"{base_url}/api/status", timeout=5) as resp:
            data = json.loads(resp.read())
            print(f"  Backend OK — model: {data.get('model_name', '?')} "
                  f"| loaded: {data.get('model_loaded', False)}")
            if not data.get("model_loaded"):
                print("  ⚠  Model not loaded — run ml-model/train.py first")
                print("     Sessions will be ingested but risk_score will be 0")
            return True
    except Exception as e:
        print(f"  ✗ Cannot reach backend at {base_url}: {e}")
        print("    Make sure uvicorn main:app --reload --port 8000 is running")
        return False


def replay(log_path: Path, base_url: str, limit: int, delay: float) -> None:
    ingest_url = f"{base_url}/api/sessions/ingest"

    print(f"\n{'═'*60}")
    print("  Replay: events.ndjson → FastAPI backend")
    print(f"{'═'*60}")
    print(f"\n  Log file : {log_path}")
    print(f"  Backend  : {base_url}")

    print("\n  Checking backend...")
    if not check_backend(base_url):
        sys.exit(1)

    print(f"\n  Loading sessions from {log_path} ...")
    sessions = load_sessions(log_path)
    session_ids = sorted(sessions.keys())

    if limit:
        session_ids = session_ids[:limit]

    label_0 = sum(1 for sid in session_ids
                  if sessions[sid][0].get("label") == 0)
    label_1 = sum(1 for sid in session_ids
                  if sessions[sid][0].get("label") == 1)

    print(f"  Sessions to send : {len(session_ids)}")
    print(f"  Benign (0)       : {label_0}")
    print(f"  Ransomware (1)   : {label_1}")
    print(f"  Delay between    : {delay}s")
    print()

    sent = skipped = errors = threats = 0

    for i, sid in enumerate(session_ids, 1):
        events = sessions[sid]
        n_events = len(events)
        true_label = events[0].get("label", "?")

        try:
            result = post_session(ingest_url, events)

            if result.get("_skipped"):
                print(f"  [{i:>3}/{len(session_ids)}]  {sid:<20}  SKIP (already ingested)")
                skipped += 1
            else:
                is_ransom  = result.get("is_ransomware", False)
                risk_score = result.get("risk_score", 0)

                icon  = "🚨" if is_ransom else "✅"
                label = "RANSOMWARE" if is_ransom else "benign    "
                risk_col = f"\033[91m{risk_score:>5.1f}\033[0m" if risk_score >= 70 \
                           else f"\033[93m{risk_score:>5.1f}\033[0m" if risk_score >= 40 \
                           else f"\033[92m{risk_score:>5.1f}\033[0m"

                print(f"  [{i:>3}/{len(session_ids)}]  {sid:<20}  "
                      f"{icon} {label}  risk={risk_col}  "
                      f"events={n_events}  true_label={true_label}")

                sent += 1
                if is_ransom:
                    threats += 1

        except RuntimeError as e:
            print(f"  [{i:>3}/{len(session_ids)}]  {sid:<20}  ✗ ERROR: {e}")
            errors += 1

        if delay > 0 and i < len(session_ids):
            time.sleep(delay)

    print(f"\n{'═'*60}")
    print(f"  Done.")
    print(f"  Sent    : {sent}")
    print(f"  Threats : {threats}")
    print(f"  Skipped : {skipped}")
    print(f"  Errors  : {errors}")
    print(f"\n  Open the dashboard: http://localhost:5173")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay event log to backend")
    parser.add_argument("--log",   required=True, type=Path,
                        help="Path to events.ndjson from the simulator")
    parser.add_argument("--url",   default="http://localhost:8000",
                        help="Backend base URL (default: http://localhost:8000)")
    parser.add_argument("--limit", default=0, type=int,
                        help="Only send first N sessions (0 = all)")
    parser.add_argument("--delay", default=0.5, type=float,
                        help="Seconds to wait between sessions (default 0.5)")
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Log file not found: {args.log}")
        print("Run ./run_dataset_collection.sh first")
        sys.exit(1)

    replay(args.log, args.url, args.limit, args.delay)
