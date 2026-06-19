"""
tests/test_transfer.py — Unit tests for TransferManager.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import transfer as tr_mod
from transfer import TransferManager


@pytest.fixture
def dirs(tmp_path):
    d = {
        "gateway_enc":      tmp_path / "gateway" / "encrypted",
        "zone_l_incoming":  tmp_path / "zone_l"  / "incoming",
        "zone_l_decrypted": tmp_path / "zone_l"  / "decrypted",
    }
    for v in d.values():
        v.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def enc_file(dirs):
    """A fake .diode file sitting in gateway/encrypted."""
    f = dirs["gateway_enc"] / "document.pdf.diode"
    f.write_bytes(b"fake encrypted content " * 10)
    return f


@pytest.fixture
def tm(dirs):
    """TransferManager with patched path constants."""
    with (
        patch.object(tr_mod, "GATEWAY_ENC",      dirs["gateway_enc"]),
        patch.object(tr_mod, "ZONE_L_INCOMING",   dirs["zone_l_incoming"]),
        patch.object(tr_mod, "ZONE_L_DECRYPTED",  dirs["zone_l_decrypted"]),
    ):
        yield TransferManager(), dirs


class TestDeliverToZoneL:

    def test_file_appears_in_incoming(self, tm, enc_file):
        manager, dirs = tm
        dest = manager.deliver_to_zone_l(enc_file)
        assert dest.exists()
        assert dest.parent == dirs["zone_l_incoming"]

    def test_dest_has_same_name(self, tm, enc_file):
        manager, _ = tm
        dest = manager.deliver_to_zone_l(enc_file)
        assert dest.name == enc_file.name

    def test_dest_has_same_content(self, tm, enc_file):
        manager, _ = tm
        dest = manager.deliver_to_zone_l(enc_file)
        assert dest.read_bytes() == enc_file.read_bytes()

    def test_duplicate_raises_file_exists(self, tm, enc_file):
        manager, dirs = tm
        manager.deliver_to_zone_l(enc_file)
        # Try to deliver same file again
        with pytest.raises(FileExistsError):
            manager.deliver_to_zone_l(enc_file)

    def test_missing_source_raises(self, tm, dirs):
        manager, _ = tm
        ghost = dirs["gateway_enc"] / "ghost.diode"
        with pytest.raises(FileNotFoundError):
            manager.deliver_to_zone_l(ghost)


class TestCleanupGateway:

    def test_removes_proc_and_enc(self, tm, dirs):
        manager, _ = tm
        proc = dirs["gateway_enc"].parent.parent / "processing" / "file.txt"
        proc.parent.mkdir(parents=True, exist_ok=True)
        proc.write_text("proc")
        enc  = dirs["gateway_enc"] / "file.txt.diode"
        enc.write_bytes(b"enc")

        manager.cleanup_gateway(proc, enc)
        assert not proc.exists()
        assert not enc.exists()

    def test_handles_none_paths(self, tm):
        manager, _ = tm
        # Should not raise
        manager.cleanup_gateway(None, None)

    def test_handles_already_deleted(self, tm, dirs):
        manager, _ = tm
        ghost = dirs["gateway_enc"] / "already_gone.diode"
        # File does not exist — should not raise
        manager.cleanup_gateway(None, ghost)


class TestCleanupZoneLIncoming:

    def test_removes_incoming_file(self, tm, dirs):
        manager, _ = tm
        f = dirs["zone_l_incoming"] / "some.diode"
        f.write_bytes(b"data")
        manager.cleanup_zone_l_incoming(f)
        assert not f.exists()

    def test_handles_none(self, tm):
        manager, _ = tm
        manager.cleanup_zone_l_incoming(None)

    def test_handles_missing_file(self, tm, dirs):
        manager, _ = tm
        ghost = dirs["zone_l_incoming"] / "ghost.diode"
        manager.cleanup_zone_l_incoming(ghost)   # should not raise
