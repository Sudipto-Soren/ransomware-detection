"""
simulator/hard_cases_generator.py

Generates the edge cases that a clean simulator misses.
These are the sessions most likely to cause errors during your presentation.

WHY THIS EXISTS:
  Your original simulator generates sessions with very clean separation:
    - Benign: always slow, scattered, no extension changes
    - Ransomware: always fast, sequential, 100% extension change

  Real-world behaviour is messier. This script generates four types
  of hard cases that teach the model where the real boundary is:

  HARD BENIGN (label=0) — looks suspicious but is legitimate:
    1. backup_software   — fast sequential writes, same extension (rsync/TimeMachine)
    2. antivirus_scan    — reads every file in sorted order (sequential + many dirs)
    3. video_encoder     — many large fast writes, no extension change
    4. git_checkout      — many small rapid writes scattered across dirs

  HARD RANSOMWARE (label=1) — subtle, easy to miss:
    5. slow_ransomware   — throttled to 1-3 files/sec (evades rate-based detection)
    6. partial_ransomware — only encrypts 20-40% of files (evades coverage-based detection)
    7. extension_mimic   — changes extension to a real one (.docx → .pdf) not .locked

Usage:
  python hard_cases_generator.py --sandbox ./test-sandbox --log ./logs/events.ndjson
"""

import argparse
import random
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from utils.event_logger import EventLogger, make_event

XOR_KEY = 0xA5


def xor_transform(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def _all_files(sandbox: Path) -> list[Path]:
    return [f for f in sandbox.rglob("*") if f.is_file()
            and ".locked" not in f.name]


# ─── Hard Benign 1: Backup software ──────────────────────────────────────────
def run_backup_software(sandbox: Path, session_id: str,
                        log_path: Path, speed: float = 8.0):
    """
    Mimics rsync / Time Machine / robocopy.
    Writes many files fast in sequential directory order.
    LOOKS LIKE ransomware: fast + sequential + many dirs touched.
    IS benign: same extension, content is a copy (not encrypted).
    """
    all_files = sorted(sandbox.rglob("*"), key=lambda p: str(p))
    all_files = [f for f in all_files if f.is_file()]
    delay = 1.0 / speed

    print(f"[hard-benign] backup_software | {session_id} | {len(all_files)} files @ {speed}/sec")

    with EventLogger(log_path) as logger:
        for fpath in all_files:
            try:
                ext = fpath.suffix
                content = fpath.read_bytes()
                backup_path = fpath.parent / f"backup_{fpath.name}"
                backup_path.write_bytes(content)   # copy, not transform

                logger.log(make_event("CREATE", str(backup_path), session_id, label=0,
                                      file_extension_before=ext,
                                      file_extension_after=ext,
                                      file_size_bytes=len(content)))
                logger.log(make_event("WRITE", str(backup_path), session_id, label=0,
                                      file_extension_before=ext,
                                      file_extension_after=ext,
                                      file_size_bytes=len(content)))
                time.sleep(delay)
            except (PermissionError, OSError):
                pass

    # Clean up backup files
    for f in sandbox.rglob("backup_*"):
        try:
            f.unlink()
        except OSError:
            pass


# ─── Hard Benign 2: Antivirus scan ───────────────────────────────────────────
def run_antivirus_scan(sandbox: Path, session_id: str,
                       log_path: Path, speed: float = 20.0):
    """
    Mimics Windows Defender / ClamAV scanning.
    Reads every file in sorted order — sequential + many directories.
    LOOKS LIKE ransomware: high sequential_score, many dirs, fast.
    IS benign: READ only, no writes, no extension changes.
    """
    all_files = sorted(sandbox.rglob("*"), key=lambda p: str(p))
    all_files = [f for f in all_files if f.is_file()]
    delay = 1.0 / speed

    print(f"[hard-benign] antivirus_scan | {session_id} | {len(all_files)} files @ {speed}/sec")

    with EventLogger(log_path) as logger:
        for fpath in all_files:
            try:
                _ = fpath.read_bytes()
                ext = fpath.suffix
                logger.log(make_event("READ", str(fpath), session_id, label=0,
                                      file_extension_before=ext,
                                      file_extension_after=ext,
                                      file_size_bytes=fpath.stat().st_size))
                time.sleep(delay)
            except (PermissionError, OSError):
                pass


# ─── Hard Benign 3: Video encoder ────────────────────────────────────────────
def run_video_encoder(sandbox: Path, session_id: str, log_path: Path):
    """
    Mimics FFmpeg / video transcoder writing large output files fast.
    LOOKS LIKE ransomware: burst of large fast writes.
    IS benign: writing to new files with same or standard extensions.
    """
    output_dir = sandbox / "Documents" / "Exports"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[hard-benign] video_encoder | {session_id}")

    with EventLogger(log_path) as logger:
        for i in range(random.randint(10, 25)):
            fname = output_dir / f"export_{i:04d}.mp4"
            size  = random.randint(500_000, 5_000_000)
            content = bytes(random.randint(0, 255) for _ in range(size))  # high entropy video data
            fname.write_bytes(content)

            logger.log(make_event("CREATE", str(fname), session_id, label=0,
                                  file_extension_before=".mp4",
                                  file_extension_after=".mp4",
                                  file_size_bytes=size))
            logger.log(make_event("WRITE", str(fname), session_id, label=0,
                                  file_extension_before=".mp4",
                                  file_extension_after=".mp4",
                                  file_size_bytes=size))
            time.sleep(random.uniform(0.05, 0.2))

    # Clean up
    import shutil
    shutil.rmtree(output_dir, ignore_errors=True)


# ─── Hard Benign 4: Git checkout ─────────────────────────────────────────────
def run_git_checkout(sandbox: Path, session_id: str, log_path: Path):
    """
    Mimics `git checkout` / `npm install` writing many small files fast.
    LOOKS LIKE ransomware: many files/sec, scattered dirs.
    IS benign: writing new files (not overwriting), no extension change.
    """
    extensions = [".py", ".js", ".ts", ".json", ".md", ".txt", ".yaml", ".css"]
    dirs = list(sandbox.rglob("*"))
    dirs = [d for d in dirs if d.is_dir()]

    print(f"[hard-benign] git_checkout | {session_id}")

    with EventLogger(log_path) as logger:
        n_files = random.randint(30, 80)
        for i in range(n_files):
            target_dir = random.choice(dirs) if dirs else sandbox
            ext = random.choice(extensions)
            fname = target_dir / f"checkout_{uuid.uuid4().hex[:8]}{ext}"
            size  = random.randint(100, 8000)
            content = b"# auto-generated\n" * (size // 18)
            fname.write_bytes(content)

            logger.log(make_event("CREATE", str(fname), session_id, label=0,
                                  file_extension_before=ext,
                                  file_extension_after=ext,
                                  file_size_bytes=len(content)))
            time.sleep(random.uniform(0.01, 0.05))  # fast but not machine-fast

    # Clean up
    for f in sandbox.rglob("checkout_*"):
        try:
            f.unlink()
        except OSError:
            pass


# ─── Hard Ransomware 1: Slow / throttled ─────────────────────────────────────
def run_slow_ransomware(sandbox: Path, session_id: str,
                        log_path: Path, speed: float = 2.0):
    """
    Ransomware that deliberately throttles itself to evade rate-based detection.
    Real examples: some Maze variants, MedusaLocker at low priority.
    HARD TO DETECT: files_modified_per_sec is low (looks benign).
    STILL RANSOMWARE: overwrite_ratio=1.0, extension_change_ratio=1.0.
    """
    all_files = sorted(sandbox.rglob("*"), key=lambda p: str(p))
    all_files = [f for f in all_files if f.is_file()]
    max_files = random.randint(15, 35)
    all_files = all_files[:max_files]
    delay = 1.0 / speed

    print(f"[hard-ransom] slow_ransomware | {session_id} | {speed}/sec | {len(all_files)} files")

    with EventLogger(log_path) as logger:
        for fpath in all_files:
            try:
                ext_before = fpath.suffix
                data = fpath.read_bytes()
                transformed = xor_transform(data)

                logger.log(make_event("WRITE", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=ext_before,
                                      file_size_bytes=len(data)))
                fpath.write_bytes(transformed)

                new_ext  = ext_before + ".locked"
                new_path = fpath.with_suffix(new_ext)
                logger.log(make_event("RENAME", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=new_ext,
                                      file_size_bytes=len(data)))
                fpath.rename(new_path)
                time.sleep(delay)

            except (PermissionError, OSError):
                pass


# ─── Hard Ransomware 2: Partial encryption ────────────────────────────────────
def run_partial_ransomware(sandbox: Path, session_id: str, log_path: Path):
    """
    Ransomware that only encrypts a fraction of files — enough to
    make recovery impossible, not enough to trigger coverage-based detection.
    Real examples: BlackCat/ALPHV's 'auto' encryption mode.
    """
    all_files = [f for f in sandbox.rglob("*") if f.is_file()]
    fraction  = random.uniform(0.20, 0.45)
    n_target  = max(5, int(len(all_files) * fraction))
    targets   = random.sample(all_files, min(n_target, len(all_files)))
    targets   = sorted(targets, key=lambda p: str(p))  # still sequential

    print(f"[hard-ransom] partial_ransomware | {session_id} | {len(targets)}/{len(all_files)} files ({fraction:.0%})")

    with EventLogger(log_path) as logger:
        for fpath in targets:
            try:
                ext_before = fpath.suffix
                data = fpath.read_bytes()
                transformed = xor_transform(data)

                logger.log(make_event("WRITE", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=ext_before,
                                      file_size_bytes=len(data)))
                fpath.write_bytes(transformed)

                new_ext  = ext_before + ".locked"
                new_path = fpath.with_suffix(new_ext)
                logger.log(make_event("RENAME", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=new_ext,
                                      file_size_bytes=len(data)))
                fpath.rename(new_path)
                time.sleep(random.uniform(0.05, 0.3))
            except (PermissionError, OSError):
                pass


# ─── Hard Ransomware 3: Extension mimic ──────────────────────────────────────
def run_extension_mimic_ransomware(sandbox: Path, session_id: str, log_path: Path):
    """
    Ransomware that renames files to a LEGITIMATE extension (.docx → .pdf)
    instead of .locked — evades simple extension-change detection.
    """
    mimic_extensions = [".pdf", ".bak", ".tmp", ".dat", ".bin"]
    all_files = sorted(
        [f for f in sandbox.rglob("*") if f.is_file()],
        key=lambda p: str(p)
    )
    max_files = random.randint(20, 50)
    all_files = all_files[:max_files]

    print(f"[hard-ransom] extension_mimic | {session_id} | {len(all_files)} files")

    with EventLogger(log_path) as logger:
        for fpath in all_files:
            try:
                ext_before = fpath.suffix
                fake_ext   = random.choice(mimic_extensions)
                data = fpath.read_bytes()
                transformed = xor_transform(data)

                logger.log(make_event("WRITE", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=ext_before,
                                      file_size_bytes=len(data)))
                fpath.write_bytes(transformed)

                new_path = fpath.with_suffix(fake_ext)
                logger.log(make_event("RENAME", str(fpath), session_id, label=1,
                                      file_extension_before=ext_before,
                                      file_extension_after=fake_ext,
                                      file_size_bytes=len(data)))
                fpath.rename(new_path)
                time.sleep(random.uniform(0.03, 0.1))
            except (PermissionError, OSError):
                pass


# ─── Restore helper ───────────────────────────────────────────────────────────
def restore_sandbox(sandbox: Path):
    """Reverse all XOR transforms after ransomware runs."""
    for fpath in sandbox.rglob("*"):
        if not fpath.is_file():
            continue
        # Restore .locked files
        if fpath.suffix == ".locked":
            data = fpath.read_bytes()
            fpath.write_bytes(xor_transform(data))
            original = fpath.parent / fpath.stem
            fpath.rename(original)
        # Restore mimic-extension files (heuristic: if content is XOR-transformed)
        elif fpath.suffix in [".pdf", ".bak", ".tmp", ".dat", ".bin"]:
            try:
                data = fpath.read_bytes()
                # Only restore if content looks transformed
                fpath.write_bytes(xor_transform(data))
            except OSError:
                pass


# ─── Main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate hard edge-case sessions")
    parser.add_argument("--sandbox", required=True, type=Path)
    parser.add_argument("--log",     required=True, type=Path)
    parser.add_argument("--sessions", default=5, type=int,
                        help="Repetitions of each hard case (default 5)")
    args = parser.parse_args()

    if not args.sandbox.exists():
        print(f"Sandbox not found: {args.sandbox}. Run create_sandbox.py first.")
        sys.exit(1)

    args.log.parent.mkdir(parents=True, exist_ok=True)

    # ── Hard benign cases ──────────────────────────────────────────────────
    print("\n═══ Hard Benign Cases ═══════════════════════════════════════")
    for i in range(1, args.sessions + 1):
        run_backup_software(args.sandbox, f"hard-benign-backup-{i:04d}", args.log,
                            speed=random.uniform(5, 15))
        run_antivirus_scan(args.sandbox, f"hard-benign-avscan-{i:04d}", args.log,
                           speed=random.uniform(10, 30))
        run_video_encoder(args.sandbox,  f"hard-benign-video-{i:04d}", args.log)
        run_git_checkout(args.sandbox,   f"hard-benign-git-{i:04d}", args.log)

    # ── Hard ransomware cases ──────────────────────────────────────────────
    print("\n═══ Hard Ransomware Cases ═══════════════════════════════════")
    for i in range(1, args.sessions + 1):
        run_slow_ransomware(args.sandbox, f"hard-ransom-slow-{i:04d}", args.log,
                            speed=random.uniform(1, 3))
        restore_sandbox(args.sandbox)

        run_partial_ransomware(args.sandbox, f"hard-ransom-partial-{i:04d}", args.log)
        restore_sandbox(args.sandbox)

        run_extension_mimic_ransomware(args.sandbox, f"hard-ransom-mimic-{i:04d}", args.log)
        restore_sandbox(args.sandbox)

    print("\n═══ Hard cases complete ════════════════════════════════════")
    print(f"  Events logged to: {args.log}")
    print(f"  Next: run extractor.py and retrain the model")
