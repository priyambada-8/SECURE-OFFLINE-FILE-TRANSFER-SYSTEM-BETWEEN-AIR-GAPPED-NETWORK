"""
crypto_utils.py — Symmetric file encryption / decryption.

Algorithm: AES-256-GCM via cryptography library's hazmat primitives,
with password-based key derivation via PBKDF2-HMAC-SHA256.

.diode file format
┌─────────────────────────────────────────────┐
│  MAGIC     (5 bytes)  b"DIODE"              │
│  SALT      (16 bytes) random per-file       │
│  NONCE     (12 bytes) random per-file       │
│  CIPHERTEXT (variable)                      │
│  GCM TAG   (16 bytes) authentication tag    │
└─────────────────────────────────────────────┘
AESGCM.encrypt returns ciphertext + 16-byte tag appended together.
Any bit-flip or wrong password raises InvalidTag before any plaintext
is produced — authenticated encryption guarantees.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from config import ENCRYPTED_SUFFIX
from logger_setup import get_logger

log = get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
MAGIC          = b"DIODE"
SALT_LEN       = 16
NONCE_LEN      = 12      # GCM standard nonce
KDF_ITERATIONS = 390_000  # OWASP 2023 minimum for PBKDF2-SHA256
KEY_LEN        = 32       # 256-bit key


# ── Key derivation ─────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from *password* using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ── Encryption ─────────────────────────────────────────────────────────────────

def encrypt_file(src: Path, dest_dir: Path, password: str) -> Path:
    """
    Encrypt *src* with *password* and write to *dest_dir/<name>.diode*.

    Returns the path of the encrypted output file.
    Raises ValueError       on empty password.
    Raises FileNotFoundError if *src* is gone before we read it.
    Raises FileExistsError   if output already exists (duplicate guard).
    """
    if not password:
        raise ValueError("Encryption password must not be empty.")
    if not src.exists():
        raise FileNotFoundError(f"encrypt_file: source not found → {src}")

    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _derive_key(password, salt)

    plaintext      = src.read_bytes()
    aesgcm         = AESGCM(key)
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, None)

    out_name = src.name + ENCRYPTED_SUFFIX
    out_path = dest_dir / out_name

    if out_path.exists():
        raise FileExistsError(f"Encrypted file already exists: {out_path}")

    with out_path.open("wb") as fh:
        fh.write(MAGIC)
        fh.write(salt)
        fh.write(nonce)
        fh.write(ciphertext_tag)

    log.info("Encrypted '%s' → '%s'  (%d bytes)",
             src.name, out_name, out_path.stat().st_size)
    return out_path


# ── Decryption ─────────────────────────────────────────────────────────────────

def decrypt_file(src: Path, dest_dir: Path, password: str) -> Path:
    """
    Decrypt a *.diode* file back to its original filename inside *dest_dir*.

    Returns the path of the recovered plaintext file.
    Raises ValueError        on wrong password / corrupted file (bad GCM tag).
    Raises FileNotFoundError if *src* is missing.
    Raises RuntimeError      on malformed header magic.
    Raises FileExistsError   if output already exists.
    """
    if not src.exists():
        raise FileNotFoundError(f"decrypt_file: source not found → {src}")

    raw = src.read_bytes()

    # ── Header validation ──────────────────────────────────────────────────────
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(raw) < header_len + 16:   # at least 1 cipher byte + 16-byte GCM tag
        raise RuntimeError(
            f"File too small to be a valid .diode file: {src.name} "
            f"({len(raw)} bytes)"
        )

    offset = 0
    magic  = raw[offset:offset + len(MAGIC)]; offset += len(MAGIC)
    if magic != MAGIC:
        raise RuntimeError(
            f"Bad magic bytes — not a .diode file: {src.name}  "
            f"(got {magic!r})"
        )

    salt           = raw[offset:offset + SALT_LEN];  offset += SALT_LEN
    nonce          = raw[offset:offset + NONCE_LEN];  offset += NONCE_LEN
    ciphertext_tag = raw[offset:]

    key    = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_tag, None)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: wrong password or file is corrupted / tampered."
        )

    # Strip the .diode suffix to recover original filename
    original_name = src.name
    if original_name.endswith(ENCRYPTED_SUFFIX):
        original_name = original_name[: -len(ENCRYPTED_SUFFIX)]

    out_path = dest_dir / original_name
    if out_path.exists():
        raise FileExistsError(
            f"Decrypted output already exists: {out_path}. "
            "Remove it manually before decrypting again."
        )

    out_path.write_bytes(plaintext)
    log.info("Decrypted '%s' → '%s'  (%d bytes)",
             src.name, original_name, len(plaintext))
    return out_path
