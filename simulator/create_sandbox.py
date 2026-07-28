"""
create_sandbox.py — creates a disposable test folder full of dummy files.

Run this ONCE before either generator. Everything lives inside
--sandbox-path (default: ./test-sandbox). Safe to delete entirely at
any time: rm -rf ./test-sandbox

Why this exists:
  Both generators need real files to operate on. Real files let us
  measure genuine file sizes and compute real entropy deltas. We use
  dummy content (not your actual files) so nothing important is ever
  at risk — even if something goes wrong.

What it creates:
  ~150 files spread across 7 subdirectories, with varied:
    - Extensions (.txt .docx .pdf .xlsx .jpg .png .csv .py .json)
    - Sizes (500 B → 500 KB)
    - Content entropy (text files ≈ 4–5 bits/byte,
                       "binary" files ≈ 6–7 bits/byte)

Usage:
  python create_sandbox.py
  python create_sandbox.py --sandbox-path ./my-sandbox --num-files 200
"""

import argparse
import random
import string
from pathlib import Path

# ─── Directory layout ─────────────────────────────────────────────────────────
# Mirrors a realistic Windows user-profile folder structure.
DIRECTORIES = [
    "Documents/Reports",
    "Documents/Invoices",
    "Documents/Contracts",
    "Pictures/2024",
    "Pictures/Screenshots",
    "Downloads",
    "Projects/Code",
]

# ─── File templates: (extension, (min_bytes, max_bytes), content_type) ────────
FILE_TEMPLATES = [
    (".txt",  (500,    5_000),   "text"),
    (".docx", (10_000, 80_000),  "binary"),
    (".pdf",  (20_000, 150_000), "binary"),
    (".xlsx", (8_000,  50_000),  "binary"),
    (".jpg",  (50_000, 500_000), "binary"),
    (".png",  (10_000, 200_000), "binary"),
    (".csv",  (1_000,  20_000),  "text"),
    (".py",   (500,    8_000),   "text"),
    (".json", (200,    5_000),   "text"),
]

NAME_PREFIXES = [
    "report", "invoice", "contract", "summary", "notes", "backup",
    "document", "analysis", "data", "project", "readme", "config",
    "photo", "image", "screenshot", "export", "statement", "letter",
]

# ─── Content generators ───────────────────────────────────────────────────────

_WORDS = [
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "her",
    "was", "one", "our", "out", "day", "get", "has", "him", "his", "how",
    "project", "report", "invoice", "contract", "analysis", "data", "system",
    "network", "security", "information", "technology", "management",
    "development", "implementation", "requirements", "review", "budget",
    "quarterly", "annual", "summary", "findings", "recommendation",
]


def _text_content(size_bytes: int) -> bytes:
    """
    Produces realistic-looking document text.
    Shannon entropy ≈ 4–5 bits/byte (typical for English prose).
    """
    parts = []
    total = 0
    while total < size_bytes:
        sentence_len = random.randint(6, 14)
        sentence = " ".join(random.choices(_WORDS, k=sentence_len)).capitalize() + ". "
        parts.append(sentence)
        total += len(sentence)
    return "".join(parts)[:size_bytes].encode("utf-8")


def _binary_content(size_bytes: int) -> bytes:
    """
    Produces plausible binary content:
      - A 4-byte magic header (ZIP/Office format signature)
      - Body bytes drawn from a skewed distribution (not purely random,
        so entropy ≈ 6–7 bits/byte rather than 8.0)

    Why not os.urandom()?  Truly random bytes give entropy = 8.0, which
    is the AFTER state for a ransomware-pattern run. Starting there would
    make our entropy-delta feature invisible.
    """
    header = bytes([0x50, 0x4B, 0x03, 0x04])  # ZIP / OOXML magic
    # Skewed body: bias toward mid-range byte values
    body = bytes(
        min(255, max(0, int(random.gauss(128, 60))))
        for _ in range(size_bytes - 4)
    )
    return header + body


def _random_filename(ext: str) -> str:
    return f"{random.choice(NAME_PREFIXES)}_{random.randint(100, 9999)}{ext}"


# ─── Main ─────────────────────────────────────────────────────────────────────

def create_sandbox(sandbox_path: Path, num_files: int = 150) -> Path:
    print(f"Creating sandbox at: {sandbox_path.resolve()}")

    # Build directory tree
    dirs: list[Path] = []
    for d in DIRECTORIES:
        full = sandbox_path / d
        full.mkdir(parents=True, exist_ok=True)
        dirs.append(full)

    created = 0
    for _ in range(num_files):
        ext, size_range, ctype = random.choice(FILE_TEMPLATES)
        size = random.randint(*size_range)
        fpath = random.choice(dirs) / _random_filename(ext)

        if fpath.exists():       # extremely unlikely but safe
            continue

        content = _text_content(size) if ctype == "text" else _binary_content(size)
        fpath.write_bytes(content)
        created += 1

    print(f"  ✓ {created} files across {len(dirs)} directories")
    print(f"  Safe to delete: rm -rf {sandbox_path.resolve()}")
    return sandbox_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a disposable sandbox for simulator testing")
    parser.add_argument("--sandbox-path", default="./test-sandbox", type=Path)
    parser.add_argument("--num-files",    default=150, type=int,
                        help="Number of dummy files to generate (default: 150)")
    args = parser.parse_args()

    if args.sandbox_path.exists():
        print(
            f"Sandbox already exists at {args.sandbox_path.resolve()}.\n"
            "Delete it first if you want a fresh one:\n"
            f"  rm -rf {args.sandbox_path.resolve()}"
        )
    else:
        create_sandbox(args.sandbox_path, args.num_files)
