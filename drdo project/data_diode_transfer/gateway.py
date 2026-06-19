"""
gateway.py — Core orchestrator and directional state machine.

GatewayState transitions
────────────────────────
  IDLE ──► RECEIVING  (new file detected from Zone I)
        ──► SENDING   (encryption done, transferring to Zone L)
        ──► IDLE      (pipeline complete, cleanup done)
        ──► ERROR     (unrecoverable fault → operator must call reset_error())

Directional isolation (data-diode enforcement)
──────────────────────────────────────────────
  RECEIVING state: Zone I pipeline is active → Zone L is LOGICALLY LOCKED
  SENDING   state: Zone L transfer is active → Zone I is LOGICALLY LOCKED

  _assert_zone_i_allowed() / _assert_zone_l_allowed() gate every cross-zone call.
  threading.Lock ensures no two files are ever processed concurrently.
"""

import shutil
import time
import threading
from pathlib import Path
from typing import Callable, Optional

from config import (
    GatewayState,
    ZONE_I_INPUT,
    GATEWAY_PROC,
    GATEWAY_ENC,
    ZONE_L_INCOMING,
    FILE_SETTLE_DELAY,
)
from scanner import FileScanner
from crypto_utils import encrypt_file
from transfer import TransferManager
from logger_setup import get_logger

log = get_logger(__name__)


class Gateway:
    """
    Stateful orchestrator that enforces directional data-diode logic.

    Public interface
    ────────────────
    process_file(path, password)     – watcher calls this when a new file arrives
    decrypt_request(name, pwd)       – UI Zone L panel calls this
    reset_error()                    – operator-triggered ERROR → IDLE recovery
    state                            – read-only current GatewayState
    on_state_change                  – optional callback(new_state: GatewayState)
    on_file_ready_for_decrypt        – optional callback(filename: str)
    """

    def __init__(self):
        self._state    = GatewayState.IDLE
        self._lock     = threading.Lock()
        self._scanner  = FileScanner()
        self._transfer = TransferManager()

        # Paths of the current in-flight file (cleared on cleanup / error)
        self._proc_path: Optional[Path] = None
        self._enc_path:  Optional[Path] = None

        # Callbacks registered by the UI layer
        self.on_state_change:           Optional[Callable[[GatewayState], None]] = None
        self.on_file_ready_for_decrypt: Optional[Callable[[str], None]]          = None

    # ── State management ───────────────────────────────────────────────────────

    @property
    def state(self) -> GatewayState:
        return self._state

    def _set_state(self, new_state: GatewayState) -> None:
        self._state = new_state
        log.info("Gateway state ──► %s", new_state.name)
        if self.on_state_change:
            self.on_state_change(new_state)

    # ── Zone access guards (data-diode enforcement) ───────────────────────────

    def _assert_zone_i_allowed(self) -> None:
        """Raise RuntimeError if Zone I operations are currently blocked."""
        if self._state == GatewayState.SENDING:
            raise RuntimeError(
                "Zone I access DENIED — gateway is in SENDING state "
                "(Zone L transfer is active)."
            )

    def _assert_zone_l_allowed(self) -> None:
        """Raise RuntimeError if Zone L operations are currently blocked."""
        if self._state == GatewayState.RECEIVING:
            raise RuntimeError(
                "Zone L access DENIED — gateway is in RECEIVING state "
                "(Zone I processing is active)."
            )

    # ── Main pipeline ──────────────────────────────────────────────────────────

    def process_file(self, src_path: Path, password: str) -> bool:
        """
        Full pipeline for one file: move → scan → encrypt → transfer.

        Called from a watcher/background thread.
        The _lock prevents concurrent processing of multiple files.
        Returns True on success, False on soft failure or when already busy.
        """
        if not self._lock.acquire(blocking=False):
            log.warning(
                "Gateway busy processing another file — skipping '%s'. "
                "It will need to be re-uploaded after the current file completes.",
                src_path.name,
            )
            return False

        try:
            return self._run_pipeline(src_path, password)
        finally:
            self._lock.release()

    def _run_pipeline(self, src_path: Path, password: str) -> bool:
        """Internal pipeline — called only while _lock is held."""

        # ══ PHASE 1: RECEIVING  (Zone L is locked) ════════════════════════════
        self._set_state(GatewayState.RECEIVING)

        # Step 1 — File settle delay: allow the writer process to finish flushing
        log.debug("Waiting %.1f s for file to settle: '%s'", FILE_SETTLE_DELAY, src_path.name)
        time.sleep(FILE_SETTLE_DELAY)

        if not src_path.exists():
            log.warning("File disappeared before processing began: '%s'", src_path.name)
            self._set_state(GatewayState.IDLE)
            return False

        # Step 2 — Move file from Zone I input → gateway/processing
        try:
            self._proc_path = self._move_to_processing(src_path)
        except FileExistsError as exc:
            log.error("Duplicate file detected on move: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False
        except Exception as exc:
            log.error("Failed to move file to processing: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False

        # Step 3 — AV scan
        log.info("Starting AV scan for: '%s'", self._proc_path.name)
        try:
            scan_result = self._scanner.scan(self._proc_path)
        except FileNotFoundError as exc:
            log.error("Scanner could not find file (was it deleted?): %s", exc)
            self._set_state(GatewayState.ERROR)
            return False
        except Exception as exc:
            log.error("Unexpected scanner exception: %s", exc)
            self._quarantine(self._proc_path, reason="SCAN_EXCEPTION")
            self._proc_path = None
            self._set_state(GatewayState.ERROR)
            return False

        if not scan_result.passed:
            log.error(
                "SCAN FAILED — '%s'  threat=%s  detail=%s",
                self._proc_path.name, scan_result.threat_name, scan_result.detail,
            )
            self._quarantine(self._proc_path, reason=scan_result.threat_name)
            self._proc_path = None
            self._set_state(GatewayState.ERROR)
            return False

        log.info("Scan PASSED: %s", scan_result.detail)

        # Step 4 — Encrypt
        log.info("Encrypting: '%s'", self._proc_path.name)
        try:
            self._enc_path = encrypt_file(self._proc_path, GATEWAY_ENC, password)
        except ValueError as exc:
            log.error("Encryption parameter error: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False
        except FileExistsError as exc:
            log.error("Encrypted output already exists (duplicate): %s", exc)
            self._set_state(GatewayState.ERROR)
            return False
        except Exception as exc:
            log.error("Encryption failed: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False

        # ══ PHASE 2: SENDING  (Zone I is locked) ══════════════════════════════
        self._set_state(GatewayState.SENDING)

        # Step 5 — Transfer encrypted file to Zone L
        log.info("Transferring '%s' to Zone L...", self._enc_path.name)
        try:
            zone_l_dest = self._transfer.deliver_to_zone_l(self._enc_path)
        except FileExistsError as exc:
            log.error("Duplicate file in Zone L: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False
        except Exception as exc:
            log.error("Transfer to Zone L failed: %s", exc)
            self._set_state(GatewayState.ERROR)
            return False

        # Step 6 — Gateway cleanup (remove processing + encrypted staging files)
        self._transfer.cleanup_gateway(self._proc_path, self._enc_path)
        self._proc_path = None
        self._enc_path  = None

        # ══ Back to IDLE ═══════════════════════════════════════════════════════
        self._set_state(GatewayState.IDLE)
        log.info(
            "Pipeline complete ✓  '%s' is ready for Zone L decryption.",
            zone_l_dest.name,
        )

        if self.on_file_ready_for_decrypt:
            self.on_file_ready_for_decrypt(zone_l_dest.name)

        return True

    # ── Zone L decryption request ──────────────────────────────────────────────

    def decrypt_request(self, enc_filename: str, password: str) -> Path:
        """
        Decrypt a file in zone_l/incoming.  Called from the UI Zone L panel.

        Enforces that Zone L is not blocked (i.e., state must not be RECEIVING).
        Returns path to decrypted file.
        Raises RuntimeError  if Zone L is currently locked.
        Raises ValueError    on wrong password or corrupted file.
        Raises FileNotFoundError if the file doesn't exist.
        """
        self._assert_zone_l_allowed()

        log.info("Zone L decrypt request for: '%s'", enc_filename)
        dest = self._transfer.decrypt_incoming(enc_filename, password)

        # Remove the staging copy from zone_l/incoming after successful decrypt
        incoming_path = ZONE_L_INCOMING / enc_filename
        self._transfer.cleanup_zone_l_incoming(incoming_path)

        return dest

    # ── Error recovery ─────────────────────────────────────────────────────────

    def reset_error(self) -> None:
        """
        Operator-triggered reset from ERROR state back to IDLE.
        Clears any stale in-flight file references.
        """
        if self._state == GatewayState.ERROR:
            self._proc_path = None
            self._enc_path  = None
            self._set_state(GatewayState.IDLE)
            log.info("Gateway error state cleared by operator. Ready for next file.")
        else:
            log.warning(
                "reset_error() called but state is %s — no action taken.",
                self._state.name,
            )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _move_to_processing(self, src: Path) -> Path:
        """Move *src* from zone_i/input to gateway/processing."""
        dest = GATEWAY_PROC / src.name
        if dest.exists():
            raise FileExistsError(
                f"File already exists in processing folder: '{src.name}'. "
                "Possible duplicate upload."
            )
        shutil.move(str(src), dest)
        log.info("Moved to processing: '%s'", src.name)
        return dest

    def _quarantine(self, filepath: Path, reason: str) -> None:
        """
        Move a flagged/infected file to gateway/quarantine so it won't be
        retried and can be inspected by an operator later.
        """
        from config import GATEWAY_QUARANTINE
        GATEWAY_QUARANTINE.mkdir(exist_ok=True)

        dest = GATEWAY_QUARANTINE / filepath.name
        try:
            shutil.move(str(filepath), dest)
            log.warning(
                "QUARANTINED '%s'  reason=%s  location=%s",
                filepath.name, reason, dest,
            )
        except Exception as exc:
            log.error(
                "Quarantine move FAILED for '%s': %s  (file may remain in processing/)",
                filepath.name, exc,
            )
