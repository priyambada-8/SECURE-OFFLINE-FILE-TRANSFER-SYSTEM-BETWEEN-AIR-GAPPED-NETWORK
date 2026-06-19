"""
tests/test_crypto_utils.py — Unit tests for encryption / decryption logic.

Run:  pytest tests/ -v
"""

import os
import pytest
from pathlib import Path

# Allow imports from project root
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto_utils import encrypt_file, decrypt_file, MAGIC, SALT_LEN, NONCE_LEN


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_src(tmp_path):
    """A small plaintext source file."""
    src = tmp_path / "hello.txt"
    src.write_text("Hello, Data-Diode! This is test content. 🔒")
    return src


@pytest.fixture
def enc_dir(tmp_path):
    d = tmp_path / "encrypted"
    d.mkdir()
    return d


@pytest.fixture
def dec_dir(tmp_path):
    d = tmp_path / "decrypted"
    d.mkdir()
    return d


# ── Encryption tests ───────────────────────────────────────────────────────────

class TestEncryptFile:

    def test_creates_output_file(self, tmp_src, enc_dir):
        out = encrypt_file(tmp_src, enc_dir, "password123")
        assert out.exists()

    def test_output_has_diode_suffix(self, tmp_src, enc_dir):
        out = encrypt_file(tmp_src, enc_dir, "password123")
        assert out.name == "hello.txt.diode"

    def test_output_starts_with_magic(self, tmp_src, enc_dir):
        out = encrypt_file(tmp_src, enc_dir, "password123")
        raw = out.read_bytes()
        assert raw[:5] == b"DIODE"

    def test_output_larger_than_input(self, tmp_src, enc_dir):
        out = encrypt_file(tmp_src, enc_dir, "password123")
        # header + nonce + ciphertext + tag  > plaintext
        assert out.stat().st_size > tmp_src.stat().st_size

    def test_same_file_different_passwords_produce_different_ciphertext(self, tmp_src, enc_dir, tmp_path):
        # encrypt two copies of the same content with different passwords
        src2 = tmp_path / "hello2.txt"
        src2.write_bytes(tmp_src.read_bytes())

        enc_dir_a = tmp_path / "enc_a"; enc_dir_a.mkdir()
        enc_dir_b = tmp_path / "enc_b"; enc_dir_b.mkdir()

        out1 = encrypt_file(tmp_src, enc_dir_a, "password_aaa")
        out2 = encrypt_file(src2,    enc_dir_b, "password_bbb")
        assert out1.read_bytes() != out2.read_bytes()

    def test_two_encryptions_same_password_differ(self, tmp_src, enc_dir, tmp_path):
        # Fresh source copy needed for second encrypt
        src2 = tmp_path / "hello_copy.txt"
        src2.write_bytes(tmp_src.read_bytes())
        out1 = encrypt_file(tmp_src, enc_dir, "same_pwd")
        # Rename output so we can encrypt again
        out1.rename(enc_dir / "first.diode")
        out2 = encrypt_file(src2, enc_dir, "same_pwd")
        # Random salt + nonce means ciphertexts must differ
        assert (enc_dir / "first.diode").read_bytes() != out2.read_bytes()

    def test_empty_password_raises(self, tmp_src, enc_dir):
        with pytest.raises(ValueError, match="empty"):
            encrypt_file(tmp_src, enc_dir, "")

    def test_missing_source_raises(self, tmp_path, enc_dir):
        ghost = tmp_path / "ghost.txt"
        with pytest.raises(FileNotFoundError):
            encrypt_file(ghost, enc_dir, "pwd")

    def test_duplicate_output_raises(self, tmp_src, enc_dir, tmp_path):
        encrypt_file(tmp_src, enc_dir, "pwd")
        src2 = tmp_path / "hello.txt"
        src2.write_text("different content")
        with pytest.raises(FileExistsError):
            encrypt_file(src2, enc_dir, "pwd")


# ── Decryption tests ───────────────────────────────────────────────────────────

class TestDecryptFile:

    def _round_trip_setup(self, tmp_src, enc_dir, dec_dir, password="testpwd"):
        enc = encrypt_file(tmp_src, enc_dir, password)
        return enc

    def test_round_trip_recovers_content(self, tmp_src, enc_dir, dec_dir):
        enc = self._round_trip_setup(tmp_src, enc_dir, dec_dir)
        out = decrypt_file(enc, dec_dir, "testpwd")
        assert out.read_bytes() == tmp_src.read_bytes()

    def test_round_trip_recovers_filename(self, tmp_src, enc_dir, dec_dir):
        enc = self._round_trip_setup(tmp_src, enc_dir, dec_dir)
        out = decrypt_file(enc, dec_dir, "testpwd")
        assert out.name == "hello.txt"

    def test_wrong_password_raises_value_error(self, tmp_src, enc_dir, dec_dir):
        enc = self._round_trip_setup(tmp_src, enc_dir, dec_dir)
        with pytest.raises(ValueError, match="wrong password"):
            decrypt_file(enc, dec_dir, "wrongpassword")

    def test_missing_file_raises(self, tmp_path, dec_dir):
        ghost = tmp_path / "ghost.diode"
        with pytest.raises(FileNotFoundError):
            decrypt_file(ghost, dec_dir, "pwd")

    def test_bad_magic_raises_runtime_error(self, tmp_path, dec_dir):
        bad = tmp_path / "bad.diode"
        # Write enough bytes but wrong magic
        bad.write_bytes(b"XXXXX" + os.urandom(SALT_LEN + NONCE_LEN + 17))
        with pytest.raises(RuntimeError, match="magic"):
            decrypt_file(bad, dec_dir, "pwd")

    def test_truncated_file_raises_runtime_error(self, tmp_path, dec_dir):
        tiny = tmp_path / "tiny.diode"
        tiny.write_bytes(b"DIO")   # too short
        with pytest.raises(RuntimeError, match="too small"):
            decrypt_file(tiny, dec_dir, "pwd")

    def test_bitflip_raises_value_error(self, tmp_src, enc_dir, dec_dir):
        enc = self._round_trip_setup(tmp_src, enc_dir, dec_dir)
        raw = bytearray(enc.read_bytes())
        raw[-1] ^= 0xFF            # flip last byte (GCM tag)
        enc.write_bytes(bytes(raw))
        with pytest.raises(ValueError):
            decrypt_file(enc, dec_dir, "testpwd")

    def test_duplicate_output_raises(self, tmp_src, enc_dir, dec_dir):
        enc = self._round_trip_setup(tmp_src, enc_dir, dec_dir)
        decrypt_file(enc, dec_dir, "testpwd")
        # Re-encrypt fresh copy and try to decrypt to same dest
        src2 = enc_dir / "hello.txt"
        src2.write_bytes(tmp_src.read_bytes())
        enc2_name = "hello.txt.v2.diode"
        # Manually build a second diode file with same original name
        import shutil
        enc2 = enc_dir / enc2_name
        shutil.copy2(enc, enc2)
        # Patch its name so decrypt_file thinks it should produce hello.txt again
        # (use a fresh enc since the first was already decrypted)
        with pytest.raises(FileExistsError):
            decrypt_file(enc, dec_dir, "testpwd")   # hello.txt already in dec_dir

    def test_binary_file_round_trip(self, tmp_path, enc_dir, dec_dir):
        src = tmp_path / "data.bin"
        src.write_bytes(os.urandom(8192))
        enc = encrypt_file(src, enc_dir, "binpwd")
        out = decrypt_file(enc, dec_dir, "binpwd")
        assert out.read_bytes() == src.read_bytes()

    def test_large_file_round_trip(self, tmp_path, enc_dir, dec_dir):
        src = tmp_path / "large.bin"
        src.write_bytes(os.urandom(1024 * 1024))   # 1 MB
        enc = encrypt_file(src, enc_dir, "largepwd")
        out = decrypt_file(enc, dec_dir, "largepwd")
        assert out.read_bytes() == src.read_bytes()

    def test_unicode_password(self, tmp_src, enc_dir, dec_dir):
        pwd = "日本語パスワード🔑"
        enc = encrypt_file(tmp_src, enc_dir, pwd)
        out = decrypt_file(enc, dec_dir, pwd)
        assert out.read_bytes() == tmp_src.read_bytes()

    def test_unicode_password_wrong_raises(self, tmp_src, enc_dir, dec_dir):
        enc = encrypt_file(tmp_src, enc_dir, "日本語パスワード🔑")
        with pytest.raises(ValueError):
            decrypt_file(enc, dec_dir, "wrong")
