"""
restore_sandbox.py — undoes a ransomware_pattern_generator.py run.

The XOR transform is its own inverse:
    XOR( XOR(data, 0xA5), 0xA5 ) == data

So this script simply reads every .locked file, XORs its bytes again,
and renames it back to its original extension.

Usage:
  python restore_sandbox.py --sandbox ./test-sandbox
"""

import argparse
import sys
from pathlib import Path

XOR_KEY = 0xA5  # Must match ransomware_pattern_generator.py


def xor_transform(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def restore(sandbox: Path) -> None:
    locked = sorted(sandbox.rglob("*.locked"))

    if not locked:
        print("No .locked files found — sandbox is already clean.")
        return

    print(f"Restoring {len(locked)} files in {sandbox.resolve()} ...")

    restored = 0
    for fpath in locked:
        try:
            data          = fpath.read_bytes()
            original_data = xor_transform(data)

            # Strip the .locked suffix: "report_1234.docx.locked"
            #   fpath.stem  == "report_1234.docx"
            #   fpath.suffix == ".locked"
            original_path = fpath.parent / fpath.stem

            fpath.write_bytes(original_data)
            fpath.rename(original_path)
            restored += 1
        except (PermissionError, OSError) as e:
            print(f"  Skipped {fpath.name}: {e}")

    print(f"Done. {restored}/{len(locked)} files restored.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore sandbox after ransomware-pattern run")
    parser.add_argument("--sandbox", required=True, type=Path)
    args = parser.parse_args()

    if not args.sandbox.exists():
        print(f"Sandbox not found: {args.sandbox}")
        sys.exit(1)

    restore(args.sandbox)
