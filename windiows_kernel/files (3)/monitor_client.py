"""
monitor-service/monitor_client.py
Windows user-mode monitor — connects to the RansomDet kernel driver
and forwards events to the FastAPI backend.

This runs on the WINDOWS machine (VirtualBox VM).
The backend runs on the Mac at the IP you configure below.

HOW IT WORKS:
  1. Connects to the kernel driver's communication port (\\RansomDetPort)
     using the Windows FilterLib API via ctypes.
  2. Loops calling FilterGetMessage() to receive events as they arrive.
  3. Converts each event to our JSON schema (docs/event-schema.json).
  4. Groups events into sessions (30-second sliding windows).
  5. When a window closes, POSTs the session to the backend.

REQUIREMENTS (Windows only):
  pip install pywin32 requests

RUN AS ADMINISTRATOR — the driver port requires elevated access.

Usage:
  python monitor_client.py --backend http://192.168.1.100:8000
  python monitor_client.py --backend http://192.168.1.100:8000 --window 30

  Replace 192.168.1.100 with your Mac's IP on the VirtualBox host-only network.
  To find your Mac's IP: on Mac run: ipconfig getifaddr en0
"""

import argparse
import ctypes
import ctypes.wintypes
import json
import sys
import time
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Windows-only check ────────────────────────────────────────────────────────
if sys.platform != "win32":
    print("This script runs on Windows only.")
    print("On macOS, use monitor-service/watcher.py instead.")
    sys.exit(1)

import urllib.request
import urllib.error

# ── Load Windows Filter Library ───────────────────────────────────────────────
try:
    fltlib = ctypes.WinDLL("fltlib.dll")
except OSError:
    print("ERROR: fltlib.dll not found.")
    print("This script must run on Windows with the Filter Manager installed.")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
PORT_NAME           = "\\\\.\\RansomDetPort"  # user-mode path to kernel port
MAX_PATH            = 260
MAX_PROCNAME        = 64
WINDOW_SECONDS      = 30                      # session window size

# Operation codes — must match RansomDet.h
OP_CREATE    = 0
OP_WRITE     = 1
OP_RENAME    = 2
OP_DELETE    = 3
OP_SET_INFO  = 4

OP_NAMES = {
    OP_CREATE:   "CREATE",
    OP_WRITE:    "WRITE",
    OP_RENAME:   "RENAME",
    OP_DELETE:   "DELETE",
    OP_SET_INFO: "SET_INFO",
}

# ── C structures (must match RansomDet.h exactly) ────────────────────────────
class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [
        ("ReplyLength",  ctypes.c_ulong),
        ("MessageId",    ctypes.c_ulonglong),
    ]

class RANSOMDET_EVENT(ctypes.Structure):
    _fields_ = [
        ("Operation",   ctypes.c_ulong),
        ("ProcessId",   ctypes.c_ulong),
        ("ProcessName", ctypes.c_wchar * MAX_PROCNAME),
        ("FilePath",    ctypes.c_wchar * MAX_PATH),
        ("NewFilePath", ctypes.c_wchar * MAX_PATH),
        ("Timestamp",   ctypes.c_longlong),
        ("FileSize",    ctypes.c_ulonglong),
    ]

class RANSOMDET_MESSAGE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Header", FILTER_MESSAGE_HEADER),
        ("Event",  RANSOMDET_EVENT),
    ]

# ── FilterGetMessage signature ────────────────────────────────────────────────
# HRESULT FilterGetMessage(
#     HANDLE hPort, PFILTER_MESSAGE_HEADER lpMessageBuffer,
#     DWORD dwMessageBufferSize, LPOVERLAPPED lpOverlapped);
fltlib.FilterGetMessage.restype  = ctypes.c_long   # HRESULT
fltlib.FilterGetMessage.argtypes = [
    ctypes.c_void_p,          # hPort
    ctypes.POINTER(FILTER_MESSAGE_HEADER),
    ctypes.c_ulong,
    ctypes.c_void_p,          # OVERLAPPED — NULL for synchronous
]

# ── FilterConnectCommunicationPort ────────────────────────────────────────────
fltlib.FilterConnectCommunicationPort.restype  = ctypes.c_long
fltlib.FilterConnectCommunicationPort.argtypes = [
    ctypes.c_wchar_p,         # lpPortName
    ctypes.c_ulong,           # dwOptions
    ctypes.c_void_p,          # lpContext
    ctypes.c_ushort,          # wSizeOfContext
    ctypes.c_void_p,          # lpSecurityAttributes
    ctypes.POINTER(ctypes.c_void_p),  # hPort (out)
]

# ── FILETIME conversion ───────────────────────────────────────────────────────
EPOCH_DIFF = 116444736000000000  # 100-ns ticks between 1601-01-01 and 1970-01-01

def filetime_to_iso(filetime: int) -> str:
    """Convert Windows FILETIME to ISO 8601 UTC string."""
    try:
        unix_ns = (filetime - EPOCH_DIFF) * 100  # nanoseconds
        unix_s  = unix_ns / 1_000_000_000
        dt = datetime.fromtimestamp(unix_s, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return datetime.now(timezone.utc).isoformat()


# ── Event → JSON schema ───────────────────────────────────────────────────────
def event_to_dict(evt: RANSOMDET_EVENT, session_id: str) -> dict:
    """
    Convert a raw kernel event to our shared event schema.
    This must match docs/event-schema.json exactly so the backend
    and feature extractor need zero changes.
    """
    ext_before = Path(evt.FilePath).suffix if evt.FilePath else None
    ext_after  = (
        Path(evt.NewFilePath).suffix
        if evt.NewFilePath and evt.NewFilePath != evt.FilePath
        else ext_before
    )

    return {
        "event_id":              str(uuid.uuid4()),
        "session_id":            session_id,
        "timestamp":             filetime_to_iso(evt.Timestamp),
        "pid":                   evt.ProcessId,
        "process_name":          evt.ProcessName or "unknown",
        "process_path":          None,
        "operation":             OP_NAMES.get(evt.Operation, "UNKNOWN"),
        "file_path":             evt.FilePath or "",
        "file_extension_before": ext_before,
        "file_extension_after":  ext_after,
        "file_size_bytes":       evt.FileSize or None,
        "source":                "kernel_driver",
        "label":                 None,   # unknown — live monitoring
    }


# ── Session window manager ────────────────────────────────────────────────────
class SessionManager:
    """
    Groups incoming events into fixed time windows (sessions).
    When a window closes, sends the accumulated events to the backend.
    """

    def __init__(self, backend_url: str, window_seconds: int):
        self.backend     = backend_url
        self.window      = window_seconds
        self._events     = []
        self._session_id = self._new_sid()
        self._lock       = threading.Lock()
        self._start_timer()

    def _new_sid(self) -> str:
        ts = datetime.now().strftime("%H%M%S")
        return f"win-{ts}-{uuid.uuid4().hex[:4]}"

    def _start_timer(self):
        self._timer = threading.Timer(self.window, self._flush)
        self._timer.daemon = True
        self._timer.start()

    def add(self, event_dict: dict):
        with self._lock:
            self._events.append(event_dict)

    def _flush(self):
        with self._lock:
            events     = list(self._events)
            session_id = self._session_id
            self._events     = []
            self._session_id = self._new_sid()

        self._start_timer()

        if len(events) < 3:
            print(f"  [{session_id}] {len(events)} events — too few, skipped")
            return

        self._post(session_id, events)

    def _post(self, session_id: str, events: list):
        url     = f"{self.backend}/api/sessions/ingest"
        payload = json.dumps({"events": events}).encode("utf-8")
        req     = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result     = json.loads(resp.read())
                is_ransom  = result.get("is_ransomware", False)
                risk       = result.get("risk_score", 0)
                icon       = "🚨 RANSOMWARE" if is_ransom else "✅ benign    "
                print(f"  [{session_id}]  {len(events):>4} events  "
                      f"{icon}  risk={risk:.1f}/100")
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print(f"  [{session_id}] already ingested — skipping")
            else:
                print(f"  [{session_id}] Backend error {e.code}")
        except Exception as e:
            print(f"  [{session_id}] Cannot reach backend: {e}")
            print(f"    Check that uvicorn is running on the Mac at {self.backend}")


# ── Main monitoring loop ──────────────────────────────────────────────────────
def run(backend_url: str, window_seconds: int):
    print(f"\n{'═'*58}")
    print("  RansomDet — Windows Kernel Monitor")
    print(f"{'═'*58}")
    print(f"  Backend  : {backend_url}")
    print(f"  Window   : {window_seconds}s per session")
    print(f"  Port     : {PORT_NAME}")
    print()

    # ── Connect to the kernel port ────────────────────────────────────────
    hPort = ctypes.c_void_p()
    hr = fltlib.FilterConnectCommunicationPort(
        PORT_NAME,
        0, None, 0, None,
        ctypes.byref(hPort)
    )
    if hr != 0:
        print(f"ERROR: FilterConnectCommunicationPort failed: HRESULT=0x{hr & 0xFFFFFFFF:08X}")
        print()
        print("  Possible causes:")
        print("  1. The driver is not loaded. Run: sc start RansomDet")
        print("  2. This script is not running as Administrator.")
        print("  3. Test signing is not enabled.")
        print("     Run in elevated cmd: bcdedit /set testsigning on  then reboot.")
        sys.exit(1)

    print(f"  ✓ Connected to kernel driver port")
    print(f"  Monitoring started. Events will appear below.")
    print(f"{'─'*58}")

    mgr = SessionManager(backend_url, window_seconds)

    # Pre-allocate the message buffer
    msg     = RANSOMDET_MESSAGE()
    msg_ptr = ctypes.cast(ctypes.byref(msg), ctypes.POINTER(FILTER_MESSAGE_HEADER))

    try:
        while True:
            # Blocking call — waits until the driver sends an event
            hr = fltlib.FilterGetMessage(
                hPort,
                msg_ptr,
                ctypes.sizeof(RANSOMDET_MESSAGE),
                None   # synchronous (no OVERLAPPED)
            )
            if hr != 0:
                print(f"FilterGetMessage error: 0x{hr & 0xFFFFFFFF:08X} — retrying...")
                time.sleep(0.1)
                continue

            evt = msg.Event
            # Skip system processes (PID 0 = System Idle, 4 = System)
            if evt.ProcessId in (0, 4):
                continue

            # Update session ID in the event dict before adding
            event_dict = event_to_dict(evt, mgr._session_id)
            mgr.add(event_dict)

            # Print each event to the terminal as it arrives
            op   = OP_NAMES.get(evt.Operation, "?")
            name = (evt.ProcessName or "?")[:20]
            path = (evt.FilePath or "")[-50:]  # last 50 chars of path
            print(f"  {op:<10} [{evt.ProcessId:>6}] {name:<20} ...{path}")

    except KeyboardInterrupt:
        print(f"\n\n  Stopping monitor...")
    finally:
        # Close the port handle
        ctypes.windll.kernel32.CloseHandle(hPort)
        print("  Monitor stopped.")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RansomDet user-mode monitor (Windows only, run as Administrator)"
    )
    parser.add_argument(
        "--backend", default="http://192.168.56.1:8000",
        help=(
            "FastAPI backend URL. For VirtualBox host-only network:\n"
            "  Mac IP is usually 192.168.56.1\n"
            "  Find it on Mac with: ipconfig getifaddr vboxnet0"
        )
    )
    parser.add_argument(
        "--window", default=WINDOW_SECONDS, type=int,
        help=f"Session window in seconds (default {WINDOW_SECONDS})"
    )
    args = parser.parse_args()
    run(args.backend, args.window)
