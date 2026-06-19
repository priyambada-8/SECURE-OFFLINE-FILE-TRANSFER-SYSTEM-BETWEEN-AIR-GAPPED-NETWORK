"""
tests/test_gateway.py — Integration tests for the Gateway state machine.

These tests patch the zone folder paths to tmp_path so no real
zone directories are touched during testing.
"""

import os
import shutil
import threading
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from config import GatewayState
from gateway import Gateway


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def zone_dirs(tmp_path):
    """Create a complete set of zone directories under tmp_path."""
    dirs = {
        "zone_i_input":     tmp_path / "zones" / "zone_i"  / "input",
        "gateway_proc":     tmp_path / "zones" / "gateway" / "processing",
        "gateway_enc":      tmp_path / "zones" / "gateway" / "encrypted",
        "gateway_quarantine": tmp_path / "zones" / "gateway" / "quarantine",
        "zone_l_incoming":  tmp_path / "zones" / "zone_l"  / "incoming",
        "zone_l_decrypted": tmp_path / "zones" / "zone_l"  / "decrypted",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


@pytest.fixture
def patched_gateway(zone_dirs):
    """A Gateway whose folder constants are redirected to tmp_path."""
    with (
        patch.object(config, "ZONE_I_INPUT",     zone_dirs["zone_i_input"]),
        patch.object(config, "GATEWAY_PROC",     zone_dirs["gateway_proc"]),
        patch.object(config, "GATEWAY_ENC",      zone_dirs["gateway_enc"]),
        patch.object(config, "GATEWAY_QUARANTINE", zone_dirs["gateway_quarantine"]),
        patch.object(config, "ZONE_L_INCOMING",  zone_dirs["zone_l_incoming"]),
        patch.object(config, "ZONE_L_DECRYPTED", zone_dirs["zone_l_decrypted"]),
    ):
        # Also patch inside submodules that imported config values at load time
        import gateway as gw_mod
        import transfer as tr_mod
        import crypto_utils as cu_mod
        with (
            patch.object(gw_mod, "GATEWAY_PROC", zone_dirs["gateway_proc"]),
            patch.object(gw_mod, "GATEWAY_ENC",  zone_dirs["gateway_enc"]),
            patch.object(gw_mod, "ZONE_L_INCOMING", zone_dirs["zone_l_incoming"]),
            patch.object(tr_mod, "GATEWAY_ENC",  zone_dirs["gateway_enc"]),
            patch.object(tr_mod, "ZONE_L_INCOMING", zone_dirs["zone_l_incoming"]),
            patch.object(tr_mod, "ZONE_L_DECRYPTED", zone_dirs["zone_l_decrypted"]),
        ):
            gw = Gateway()
            # Speed up tests: skip settle delay
            with patch("gateway.FILE_SETTLE_DELAY", 0):
                yield gw, zone_dirs


@pytest.fixture
def sample_file(zone_dirs):
    """A clean test file sitting in zone_i/input."""
    f = zone_dirs["zone_i_input"] / "report.txt"
    f.write_text("Confidential report content. " * 50)
    return f


# ── State machine tests ────────────────────────────────────────────────────────

class TestGatewayStateMachine:

    def test_initial_state_is_idle(self, patched_gateway):
        gw, _ = patched_gateway
        assert gw.state == GatewayState.IDLE

    def test_state_change_callback_fires(self, patched_gateway, sample_file):
        gw, dirs = patched_gateway
        states_seen = []
        gw.on_state_change = lambda s: states_seen.append(s)

        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd123")

        assert GatewayState.RECEIVING in states_seen
        assert GatewayState.SENDING   in states_seen
        assert GatewayState.IDLE      in states_seen

    def test_file_ready_callback_fires(self, patched_gateway, sample_file):
        gw, _ = patched_gateway
        ready_files = []
        gw.on_file_ready_for_decrypt = lambda name: ready_files.append(name)

        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd123")

        assert len(ready_files) == 1
        assert ready_files[0].endswith(".diode")

    def test_zone_l_locked_during_receiving(self, patched_gateway, sample_file):
        """During RECEIVING state, Zone L decrypt_request must raise RuntimeError."""
        gw, _ = patched_gateway
        # Manually put gateway into RECEIVING state
        gw._state = GatewayState.RECEIVING
        with pytest.raises(RuntimeError, match="DENIED"):
            gw._assert_zone_l_allowed()

    def test_zone_i_locked_during_sending(self, patched_gateway, sample_file):
        """During SENDING state, Zone I assert must raise RuntimeError."""
        gw, _ = patched_gateway
        gw._state = GatewayState.SENDING
        with pytest.raises(RuntimeError, match="DENIED"):
            gw._assert_zone_i_allowed()


# ── Pipeline success tests ────────────────────────────────────────────────────

class TestGatewayPipelineSuccess:

    def test_full_pipeline_returns_true(self, patched_gateway, sample_file):
        gw, _ = patched_gateway
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            result = gw.process_file(sample_file, "secure_password")
        assert result is True

    def test_source_file_removed_from_zone_i(self, patched_gateway, sample_file):
        gw, _ = patched_gateway
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd")
        assert not sample_file.exists()

    def test_gateway_temps_cleaned_up(self, patched_gateway, sample_file, zone_dirs):
        gw, _ = patched_gateway
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd")
        assert list(zone_dirs["gateway_proc"].iterdir()) == []
        assert list(zone_dirs["gateway_enc"].iterdir())  == []

    def test_encrypted_file_arrives_in_zone_l(self, patched_gateway, sample_file, zone_dirs):
        gw, _ = patched_gateway
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd")
        files = list(zone_dirs["zone_l_incoming"].iterdir())
        assert len(files) == 1
        assert files[0].name == "report.txt.diode"

    def test_state_returns_to_idle_after_success(self, patched_gateway, sample_file):
        gw, _ = patched_gateway
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, "pwd")
        assert gw.state == GatewayState.IDLE


# ── Pipeline failure tests ────────────────────────────────────────────────────

class TestGatewayPipelineFailures:

    def test_missing_file_returns_false(self, patched_gateway, zone_dirs):
        gw, _ = patched_gateway
        ghost = zone_dirs["zone_i_input"] / "ghost.txt"
        # Don't create it — it should vanish during settle delay
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            result = gw.process_file(ghost, "pwd")
        assert result is False

    def test_threat_file_goes_to_quarantine(self, patched_gateway, zone_dirs):
        gw, _ = patched_gateway
        threat = zone_dirs["zone_i_input"] / "malware_payload.exe"
        threat.write_bytes(b"bad stuff" * 100)

        with patch("gateway.FILE_SETTLE_DELAY", 0):
            result = gw.process_file(threat, "pwd")

        assert result is False
        assert gw.state == GatewayState.ERROR
        quarantined = list(zone_dirs["gateway_quarantine"].iterdir())
        assert len(quarantined) == 1

    def test_error_state_after_threat(self, patched_gateway, zone_dirs):
        gw, _ = patched_gateway
        bad = zone_dirs["zone_i_input"] / "virus_x.bat"
        bad.write_bytes(b"x" * 50)
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(bad, "pwd")
        assert gw.state == GatewayState.ERROR

    def test_reset_error_clears_state(self, patched_gateway, zone_dirs):
        gw, _ = patched_gateway
        bad = zone_dirs["zone_i_input"] / "trojan.exe"
        bad.write_bytes(b"x" * 50)
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(bad, "pwd")
        assert gw.state == GatewayState.ERROR
        gw.reset_error()
        assert gw.state == GatewayState.IDLE

    def test_gateway_busy_returns_false(self, patched_gateway, sample_file):
        gw, dirs = patched_gateway
        # Acquire the lock externally to simulate a busy gateway
        gw._lock.acquire()
        try:
            result = gw.process_file(sample_file, "pwd")
        finally:
            gw._lock.release()
        assert result is False

    def test_duplicate_file_in_processing_triggers_error(self, patched_gateway, zone_dirs):
        gw, _ = patched_gateway
        # Pre-place a file with the same name in processing
        src = zone_dirs["zone_i_input"] / "dup.txt"
        src.write_text("original")
        dup = zone_dirs["gateway_proc"] / "dup.txt"
        dup.write_text("already here")

        with patch("gateway.FILE_SETTLE_DELAY", 0):
            result = gw.process_file(src, "pwd")

        assert result is False
        assert gw.state == GatewayState.ERROR


# ── Decryption request tests ──────────────────────────────────────────────────

class TestGatewayDecryptRequest:

    def _deliver_file(self, gw, sample_file, dirs, password="mypwd"):
        """Helper: run pipeline and return the .diode filename in zone_l/incoming."""
        with patch("gateway.FILE_SETTLE_DELAY", 0):
            gw.process_file(sample_file, password)
        files = list(dirs["zone_l_incoming"].iterdir())
        return files[0].name if files else None

    def test_decrypt_request_succeeds(self, patched_gateway, sample_file, zone_dirs):
        gw, dirs = patched_gateway
        fname = self._deliver_file(gw, sample_file, dirs, "mypwd")
        result = gw.decrypt_request(fname, "mypwd")
        assert result.exists()
        assert result.name == "report.txt"

    def test_decrypt_restores_original_content(self, patched_gateway, sample_file, zone_dirs):
        gw, dirs = patched_gateway
        original_bytes = sample_file.read_bytes()
        fname = self._deliver_file(gw, sample_file, dirs, "mypwd")
        result = gw.decrypt_request(fname, "mypwd")
        assert result.read_bytes() == original_bytes

    def test_decrypt_wrong_password_raises_value_error(self, patched_gateway, sample_file, zone_dirs):
        gw, dirs = patched_gateway
        fname = self._deliver_file(gw, sample_file, dirs, "correct")
        with pytest.raises(ValueError):
            gw.decrypt_request(fname, "wrong")

    def test_decrypt_cleans_zone_l_incoming(self, patched_gateway, sample_file, zone_dirs):
        gw, dirs = patched_gateway
        fname = self._deliver_file(gw, sample_file, dirs, "mypwd")
        gw.decrypt_request(fname, "mypwd")
        assert not (dirs["zone_l_incoming"] / fname).exists()

    def test_decrypt_blocked_when_receiving(self, patched_gateway):
        gw, _ = patched_gateway
        gw._state = GatewayState.RECEIVING
        with pytest.raises(RuntimeError, match="DENIED"):
            gw.decrypt_request("any.diode", "pwd")

    def test_decrypt_missing_file_raises(self, patched_gateway):
        gw, _ = patched_gateway
        with pytest.raises(FileNotFoundError):
            gw.decrypt_request("nonexistent.diode", "pwd")


# ── Thread-safety smoke test ──────────────────────────────────────────────────

class TestGatewayConcurrency:

    def test_only_one_file_processed_concurrently(self, patched_gateway, zone_dirs):
        """Fire two threads simultaneously; only one should succeed (lock)."""
        gw, dirs = patched_gateway

        f1 = dirs["zone_i_input"] / "file1.txt"
        f2 = dirs["zone_i_input"] / "file2.txt"
        f1.write_text("content one" * 100)
        f2.write_text("content two" * 100)

        results = []

        def run(path):
            with patch("gateway.FILE_SETTLE_DELAY", 0):
                results.append(gw.process_file(path, "pwd"))

        t1 = threading.Thread(target=run, args=(f1,))
        t2 = threading.Thread(target=run, args=(f2,))
        t1.start(); t2.start()
        t1.join();  t2.join()

        # Exactly one True (processed) and one False (skipped / busy)
        assert results.count(True) == 1
        assert results.count(False) == 1
