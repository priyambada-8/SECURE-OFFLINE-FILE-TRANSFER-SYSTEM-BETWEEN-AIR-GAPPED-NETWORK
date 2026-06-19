"""
cli_runner.py — Headless CLI alternative to the Tkinter GUI.

Use this on servers / CI environments where a display is not available.

Usage:
    python cli_runner.py

Controls (interactive prompts):
    • The watcher runs in the background.
    • When a file appears in zone_i/input you will be prompted for a password.
    • Type  decrypt  to decrypt a file that has arrived in zone_l/incoming.
    • Type  status   to show the current gateway state.
    • Type  quit     to exit cleanly.
"""

import sys
import threading
import time
from pathlib import Path

from config import ALL_DIRS, ZONE_L_INCOMING, GatewayState
from gateway import Gateway
from watcher import ZoneIWatcher
from logger_setup import get_logger

log = get_logger("cli")

# ── Shared state ───────────────────────────────────────────────────────────────
gateway         = Gateway()
_pending_files  = []          # files detected but not yet processed
_pending_lock   = threading.Lock()


# ── Callbacks ──────────────────────────────────────────────────────────────────

def _on_new_file(path: Path) -> None:
    with _pending_lock:
        _pending_files.append(path)
    print(f"\n  [ZONE I]  New file detected: '{path.name}'")
    print("  Enter encryption password (or press Enter to skip): ", end="", flush=True)


def _on_state_change(state: GatewayState) -> None:
    icons = {
        GatewayState.IDLE:      "🟢",
        GatewayState.RECEIVING: "🟠",
        GatewayState.SENDING:   "🔵",
        GatewayState.ERROR:     "🔴",
    }
    print(f"\n  {icons.get(state,'●')} Gateway → {state.name}")


def _on_file_ready(filename: str) -> None:
    print(f"\n  [ZONE L]  Ready to decrypt: '{filename}'")
    print("  Type 'decrypt' to decrypt it.")


gateway.on_state_change           = _on_state_change
gateway.on_file_ready_for_decrypt = _on_file_ready


# ── Main CLI loop ──────────────────────────────────────────────────────────────

def main() -> None:
    # Ensure all directories exist
    for d in ALL_DIRS:
        Path(d).mkdir(parents=True, exist_ok=True)

    print("\n  ╔══════════════════════════════════════════════╗")
    print("  ║  Data-Diode Secure Transfer — CLI Runner    ║")
    print("  ╚══════════════════════════════════════════════╝")
    print("  Commands:  decrypt | status | reset | quit\n")

    watcher = ZoneIWatcher(on_new_file=_on_new_file)
    watcher.start()

    try:
        while True:
            # Check for pending files first
            with _pending_lock:
                pending = _pending_files.copy()
                _pending_files.clear()

            for file_path in pending:
                _process_pending(file_path)

            # Read user command (non-blocking via timeout trick)
            try:
                cmd = _read_input("  > ").strip().lower()
            except EOFError:
                break

            if not cmd:
                continue
            elif cmd == "quit":
                break
            elif cmd == "status":
                _cmd_status()
            elif cmd == "decrypt":
                _cmd_decrypt()
            elif cmd == "reset":
                gateway.reset_error()
                print("  Gateway error cleared.")
            else:
                print(f"  Unknown command: '{cmd}'")
                print("  Available: decrypt | status | reset | quit")

    except KeyboardInterrupt:
        print("\n  Interrupted by user.")
    finally:
        watcher.stop()
        print("  Watcher stopped. Goodbye.\n")


def _process_pending(file_path: Path) -> None:
    password = _read_input(
        f"  Encryption password for '{file_path.name}': "
    ).strip()
    if not password:
        print(f"  Skipped '{file_path.name}' (no password entered).")
        return

    t = threading.Thread(
        target=gateway.process_file,
        args=(file_path, password),
        daemon=True,
        name=f"pipeline-{file_path.name}",
    )
    t.start()
    print(f"  Pipeline started for '{file_path.name}' — processing in background...")


def _cmd_status() -> None:
    state = gateway.state
    print(f"  Gateway state : {state.name}")
    files = [f.name for f in ZONE_L_INCOMING.iterdir() if f.is_file()]
    if files:
        print(f"  Zone L queue  : {', '.join(files)}")
    else:
        print("  Zone L queue  : (empty)")


def _cmd_decrypt() -> None:
    files = [f for f in ZONE_L_INCOMING.iterdir() if f.is_file()]
    if not files:
        print("  No encrypted files in Zone L incoming.")
        return

    print("  Encrypted files in Zone L:")
    for i, f in enumerate(files, 1):
        print(f"    [{i}] {f.name}")

    choice = _read_input("  Select number (or 0 to cancel): ").strip()
    try:
        idx = int(choice) - 1
    except ValueError:
        print("  Invalid selection.")
        return

    if idx < 0:
        return
    if idx >= len(files):
        print("  Out of range.")
        return

    filename = files[idx].name
    password = _read_input(f"  Decryption password for '{filename}': ").strip()
    if not password:
        print("  No password entered — cancelled.")
        return

    try:
        result = gateway.decrypt_request(filename, password)
        print(f"\n  ✅  Decrypted successfully → {result}")
    except ValueError as exc:
        print(f"\n  ❌  Decryption failed: {exc}")
    except RuntimeError as exc:
        print(f"\n  ❌  Access denied: {exc}")
    except Exception as exc:
        print(f"\n  ❌  Error: {exc}")


def _read_input(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise


if __name__ == "__main__":
    main()
