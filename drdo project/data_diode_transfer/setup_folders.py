"""
setup_folders.py — One-time setup: creates all required zone directories.
Run this once before launching the application.

Usage:
    python setup_folders.py
"""

from pathlib import Path
from config import ALL_DIRS, GATEWAY_PROC
from logger_setup import get_logger

log = get_logger("setup")


def create_directories() -> None:
    quarantine = GATEWAY_PROC.parent / "quarantine"
    dirs = list(ALL_DIRS) + [quarantine]

    print("\n  Data-Diode Transfer — Folder Setup")
    print("  " + "─" * 40)

    for d in dirs:
        d = Path(d)
        d.mkdir(parents=True, exist_ok=True)
        status = "created" if not d.exists() else "ok"
        print(f"  ✓  {d.relative_to(Path(__file__).parent)}")
        log.info("Directory ready: %s", d)

    print("\n  ✅  All directories are ready.")
    print("\n  Zone layout:")
    print("  zones/")
    print("  ├── zone_i/")
    print("  │   └── input/            ← Drop files here (Zone I upload point)")
    print("  ├── gateway/")
    print("  │   ├── processing/       ← Scan / encrypt staging (temp)")
    print("  │   ├── encrypted/        ← Encrypted file staging (temp)")
    print("  │   └── quarantine/       ← Flagged / infected files")
    print("  └── zone_l/")
    print("      ├── incoming/         ← Encrypted files awaiting decryption")
    print("      └── decrypted/        ← Final plaintext output\n")


if __name__ == "__main__":
    create_directories()
