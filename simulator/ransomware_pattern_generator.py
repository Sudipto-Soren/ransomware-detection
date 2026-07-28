"""
ransomware_pattern_generator.py — safe ransomware I/O pattern simulator.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT THIS IS:
  A behavioral simulator for the OBSERVABLE FILE-SYSTEM PATTERN of
  ransomware. It does NOT implement any real encryption, key exchange,
  C2 communication, or destructive payload.

WHAT THE TRANSFORM IS:
  Single-byte XOR with key 0xA5. This is a classical, publicly documented
  cipher used in undergraduate crypto textbooks. It's self-inverse:
      XOR( XOR(data, 0xA5), 0xA5 ) == data
  Run restore_sandbox.py (or run this script again) to fully reverse it.

WHAT IT ONLY TOUCHES:
  The --sandbox folder you point it at. Never anything else.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Why this teaches your model:
  ┌─────────────────────────┬──────────────────────────────────────────────┐
  │ Feature                 │ Ransomware-pattern signature                  │
  ├─────────────────────────┼──────────────────────────────────────────────┤
  │ files modified/sec      │ HIGH — machine speed (5–50/sec)               │
  │ overwrite ratio         │ VERY HIGH — every file fully overwritten      │
  │ extension changes       │ ALL files: .docx → .docx.locked               │
  │ directory access spread │ sorted/sequential — NOT scattered             │
  │ entropy delta           │ positive — output bytes more uniform          │
  │ sequential pattern      │ strong — alphabetical, depth-first traversal  │
  └─────────────────────────┴──────────────────────────────────────────────┘

Session label: 1  (ransomware pattern)

Usage:
  python ransomware_pattern_generator.py \\
      --sandbox   ./test-sandbox \\
      --log       ./logs/events.ndjson \\
      --speed     10        # files/sec target (default 10)
      --max-files 80        # 0 = all files (default 0)

  Restore: python restore_sandbox.py --sandbox ./test-sandbox
"""

import argparse
import math
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from utils.event_logger import EventLogger, make_event

LABEL   = 1       # ground truth for this generator
XOR_KEY = 0xA5    # 10100101 — single-byte XOR, trivially reversible


# ─── Helpers ──────────────────────────────────────────────────────────────────

def xor_transform(data: bytes, key: int = XOR_KEY) -> bytes:
    """
    Reversible byte-level transform.
    For ASCII text (bytes 0x20–0x7E), XOR with 0xA5 shifts output into
    the 0x80–0xFF range, producing non-printable high-byte output that
    looks like encrypted data to the file system.
    """
    return bytes(b ^ key for b in data)


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits/byte.
    Perfectly uniform random data → 8.0
    English plain text         → ~4.5
    After XOR(text, 0xA5)      → ~4.5 (bijection preserves entropy)
    The DELTA across a session is the real feature: ransomware runs
    always show a positive delta on text files.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum(
        (f / n) * math.log2(f / n)
        for f in freq if f > 0
    )


# ─── Per-file operation ───────────────────────────────────────────────────────

def _process_file(
    fpath:      Path,
    session_id: str,
    logger:     EventLogger,
    delay:      float,          # seconds — derived from --speed
) -> None:
    """
    Simulates what ransomware does to one file:
      1. Read original content & measure entropy
      2. Overwrite with XOR-transformed content  → WRITE event
      3. Rename to add .locked extension         → RENAME event
    """
    try:
        ext_before   = fpath.suffix
        original     = fpath.read_bytes()
        size         = len(original)
        ent_before   = shannon_entropy(original)

        transformed  = xor_transform(original)
        ent_after    = shannon_entropy(transformed)

        # ── WRITE event (logged before writing, as the kernel would capture it)
        logger.log(make_event(
            operation="WRITE",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext_before,
            file_extension_after=ext_before,   # extension changes on RENAME
            file_size_bytes=size,
            extra={
                "entropy_before": round(ent_before, 4),
                "entropy_after":  round(ent_after,  4),
                "entropy_delta":  round(ent_after - ent_before, 4),
            },
        ))
        fpath.write_bytes(transformed)

        # ── RENAME event (.docx → .docx.locked)
        new_ext  = ext_before + ".locked"
        new_path = fpath.with_suffix(new_ext)  # fpath.parent / (fpath.stem + new_ext)
        logger.log(make_event(
            operation="RENAME",
            file_path=str(fpath),
            session_id=session_id,
            label=LABEL,
            file_extension_before=ext_before,
            file_extension_after=new_ext,      # ← the critical extension-churn signal
            file_size_bytes=size,
        ))
        fpath.rename(new_path)

        time.sleep(delay)   # pace to hit target files/sec

    except (PermissionError, FileNotFoundError, OSError):
        pass   # skip locked / already-processed files


# ─── Session runner ───────────────────────────────────────────────────────────

def run_session(
    sandbox:    Path,
    session_id: str,
    log_path:   Path,
    speed:      float,   # files/sec
    max_files:  int,     # 0 = all
) -> None:
    delay = 1.0 / speed

    # KEY POINT: sorted() traversal.
    # Real ransomware iterates the file system programmatically, so it
    # processes directories in sorted order — alphabetically, depth-first.
    # Benign users' access patterns are random/scattered.
    # This is one of the strongest distinguishing features in the dataset.
    all_files = sorted(
        (f for f in sandbox.rglob("*") if f.is_file()),
        key=lambda p: str(p),
    )
    if max_files and max_files < len(all_files):
        all_files = all_files[:max_files]

    print(f"[ransom-pattern] {session_id}")
    print(f"  Sandbox : {sandbox.resolve()}")
    print(f"  Files   : {len(all_files)}")
    print(f"  Speed   : {speed} files/sec  (delay {delay*1000:.0f} ms/file)")
    print(f"  XOR key : 0x{XOR_KEY:02X}  (self-inverse — restore_sandbox.py reverses this)")

    start = time.time()

    with EventLogger(log_path) as logger:
        for i, fpath in enumerate(all_files):
            _process_file(fpath, session_id, logger, delay)

            if (i + 1) % 25 == 0:
                elapsed = time.time() - start
                actual  = (i + 1) / elapsed
                print(f"  [{i+1:>4}/{len(all_files)}]  {actual:.1f} files/sec")

    elapsed = time.time() - start
    actual  = len(all_files) / elapsed if elapsed > 0 else 0
    print(f"[ransom-pattern] Done. {len(all_files)} files in {elapsed:.1f}s "
          f"→ {actual:.1f} files/sec")
    print(f"  Restore: python restore_sandbox.py --sandbox {sandbox}")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ransomware I/O pattern simulator — safe, reversible, sandbox-only"
    )
    parser.add_argument("--sandbox",    required=True, type=Path)
    parser.add_argument("--log",        required=True, type=Path)
    parser.add_argument("--session-id", default=None,  type=str)
    parser.add_argument("--speed",      default=10.0,  type=float,
                        help="Target files/sec (default 10)")
    parser.add_argument("--max-files",  default=0,     type=int,
                        help="Max files to process per session (0 = all)")
    args = parser.parse_args()

    if not args.sandbox.exists():
        print(f"Sandbox not found: {args.sandbox}. Run create_sandbox.py first.")
        sys.exit(1)

    session_id = args.session_id or f"ransom-{uuid.uuid4().hex[:8]}"
    run_session(args.sandbox, session_id, args.log, args.speed, args.max_files)
