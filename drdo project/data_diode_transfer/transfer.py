"""
transfer.py — Moves encrypted files from the gateway to Zone L,
and handles Zone L decryption requests.

Kept deliberately thin: calls crypto_utils for crypto work,
handles only file-system moves and cleanup here.
The gateway's state machine enforces the directional lock BEFORE calling here.
"""

import shutil
from pathlib import Path

from config import GATEWAY_ENC, ZONE_L_INCOMING, ZONE_L_DECRYPTED
from crypto_utils import decrypt_file
from logger_setup import get_logger

log = get_logger(__name__)


class TransferManager:
    """Handles the gateway→Zone-L file move and the Zone-L decrypt step."""

    # ── Gateway → Zone L ───────────────────────────────────────────────────────

    def deliver_to_zone_l(self, enc_path: Path) -> Path:
        """
        Copy *enc_path* from gateway/encrypted → zone_l/incoming.

        Returns the destination path.
        Raises FileExistsError if the file is already in Zone L (duplicate).
        Raises FileNotFoundError if enc_path has vanished.
        """
        if not enc_path.exists():
            raise FileNotFoundError(
                f"deliver_to_zone_l: source file missing: {enc_path.name}"
            )

        dest = ZONE_L_INCOMING / enc_path.name
        if dest.exists():
            raise FileExistsError(
                f"File already present in Zone L incoming: {enc_path.name}. "
                "Possible duplicate transfer."
            )

        shutil.copy2(enc_path, dest)
        log.info("Delivered to Zone L incoming: '%s'  (%d bytes)",
                 enc_path.name, dest.stat().st_size)
        return dest

    # ── Zone L decryption ──────────────────────────────────────────────────────

    def decrypt_incoming(self, enc_filename: str, password: str) -> Path:
        """
        Decrypt a named file from zone_l/incoming using *password*.

        Returns path to the recovered plaintext in zone_l/decrypted.
        Propagates ValueError on wrong password / corruption.
        Propagates FileNotFoundError if the file is missing.
        """
        src = ZONE_L_INCOMING / enc_filename
        if not src.exists():
            raise FileNotFoundError(
                f"Encrypted file not found in Zone L incoming: {enc_filename}"
            )

        result = decrypt_file(src, ZONE_L_DECRYPTED, password)
        log.info("Zone L decryption complete → '%s'", result.name)
        return result

    # ── Cleanup ────────────────────────────────────────────────────────────────

    def cleanup_gateway(self, proc_path: Path | None, enc_path: Path | None) -> None:
        """
        Delete temporary files from gateway/processing and gateway/encrypted
        after a successful end-to-end transfer.
        """
        deleted = []
        for p in (proc_path, enc_path):
            if p and p.exists():
                p.unlink()
                deleted.append(p.name)
                log.debug("Cleaned up gateway temp: %s", p.name)

        if deleted:
            log.info("Gateway cleanup — removed: %s", ", ".join(deleted))
        else:
            log.debug("Gateway cleanup — nothing to remove.")

    def cleanup_zone_l_incoming(self, enc_path: Path | None) -> None:
        """Remove the encrypted staging file from zone_l/incoming after decryption."""
        if enc_path and enc_path.exists():
            enc_path.unlink()
            log.debug("Removed Zone L incoming staging file: %s", enc_path.name)
