"""
tests/test_integration.py — Full pipeline integration tests.

These tests run the complete Zone I → Gateway → Zone L cycle with
all real components (no mocks except path redirection and settle delay).
"""

import os
import shutil
import threading
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
import gateway as gw_mod
import transfer as tr_mod
from config import GatewayState
from gateway import Gateway


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def zones(tmp_path):
    """Full zone layout under tmp_path; all config constants patched."""
    dirs = {
        "zone_i_input":       tmp_path / "zone_i"   / "input",
        "gateway_proc":       tmp_path / "gateway"  / "processing",
        "gateway_enc":        tmp_path / "gateway"  / "encrypted",
        "gateway_quarantine": tmp_path / "gateway"  / "quarantine",
        "zone_l_incoming":    tmp_path / "zone_l"   / "incoming",
        "zone_l_decrypted":   tmp_path / "zone_l"   / "decrypted",
    }
    for d in dirs.values():
        d.mkdir(parents=True)

    with (
        patch.object(config,   "ZONE_I_INPUT",       dirs["zone_i_input"]),
        patch.object(config,   "GATEWAY_PROC",        dirs["gateway_proc"]),
        patch.object(config,   "GATEWAY_ENC",         dirs["gateway_enc"]),
        patch.object(config,   "GATEWAY_QUARANTINE",  dirs["gateway_quarantine"]),
        patch.object(config,   "ZONE_L_INCOMING",     dirs["zone_l_incoming"]),
        patch.object(config,   "ZONE_L_DECRYPTED",    dirs["zone_l_decrypted"]),
        patch.object(gw_mod,   "GATEWAY_PROC",        dirs["gateway_proc"]),
        patch.object(gw_mod,   "GATEWAY_ENC",         dirs["gateway_enc"]),
        patch.object(gw_mod,   "ZONE_L_INCOMING",     dirs["zone_l_incoming"]),
        patch.object(tr_mod,   "GATEWAY_ENC",         dirs["gateway_enc"]),
        patch.object(tr_mod,   "ZONE_L_INCOMING",     dirs["zone_l_incoming"]),
        patch.object(tr_mod,   "ZONE_L_DECRYPTED",    dirs["zone_l_decrypted"]),
        patch("gateway.FILE_SETTLE_DELAY", 0),
    ):
        yield dirs


@pytest.fixture
def gw(zones):
    return Gateway()


def _src(zones, name="doc.txt", content=b"secret payload " * 200):
    f = zones["zone_i_input"] / name
    f.write_bytes(content)
    return f


# ── Happy-path: complete round-trip ──────────────────────────────────────────

class TestFullRoundTrip:

    def test_plaintext_matches_after_round_trip(self, gw, zones):
        content = b"TOP SECRET\n" * 1000
        src = _src(zones, "report.pdf", content)
        assert gw.process_file(src, "pwd123")
        files = list(zones["zone_l_incoming"].iterdir())
        result = gw.decrypt_request(files[0].name, "pwd123")
        assert result.read_bytes() == content

    def test_gateway_temps_absent_after_success(self, gw, zones):
        _src(zones)
        gw.process_file(zones["zone_i_input"] / "doc.txt", "pwd")
        assert list(zones["gateway_proc"].iterdir()) == []
        assert list(zones["gateway_enc"].iterdir())  == []

    def test_zone_l_incoming_cleared_after_decrypt(self, gw, zones):
        src = _src(zones)
        gw.process_file(src, "pwd")
        fname = list(zones["zone_l_incoming"].iterdir())[0].name
        gw.decrypt_request(fname, "pwd")
        assert list(zones["zone_l_incoming"].iterdir()) == []

    def test_output_filename_matches_original(self, gw, zones):
        src = _src(zones, "quarterly_report.xlsx")
        gw.process_file(src, "pwd")
        fname = list(zones["zone_l_incoming"].iterdir())[0].name
        result = gw.decrypt_request(fname, "pwd")
        assert result.name == "quarterly_report.xlsx"

    def test_state_is_idle_throughout_after_success(self, gw, zones):
        src = _src(zones)
        gw.process_file(src, "pwd")
        gw.decrypt_request(
            list(zones["zone_l_incoming"].iterdir())[0].name, "pwd"
        )
        assert gw.state == GatewayState.IDLE

    def test_binary_content_round_trip(self, gw, zones):
        content = os.urandom(64 * 1024)   # 64 KB random bytes
        src = _src(zones, "blob.bin", content)
        gw.process_file(src, "binpass")
        fname = list(zones["zone_l_incoming"].iterdir())[0].name
        result = gw.decrypt_request(fname, "binpass")
        assert result.read_bytes() == content

    def test_multiple_sequential_files(self, gw, zones):
        """Process three files back-to-back; all should succeed cleanly."""
        for i in range(3):
            src = zones["zone_i_input"] / f"file_{i}.txt"
            src.write_text(f"Content of file {i}")
            assert gw.process_file(src, f"pass_{i}")
            fname = list(zones["zone_l_incoming"].iterdir())[0].name
            result = gw.decrypt_request(fname, f"pass_{i}")
            assert result.read_bytes() == f"Content of file {i}".encode()

    def test_zone_i_file_removed_after_pipeline(self, gw, zones):
        src = _src(zones)
        path = zones["zone_i_input"] / "doc.txt"
        gw.process_file(path, "pwd")
        assert not path.exists()


# ── Threat / quarantine path ──────────────────────────────────────────────────

class TestThreatHandling:

    def test_threat_file_quarantined(self, gw, zones):
        bad = zones["zone_i_input"] / "malware_x.exe"
        bad.write_bytes(b"payload" * 100)
        gw.process_file(bad, "pwd")
        q = list(zones["gateway_quarantine"].iterdir())
        assert len(q) == 1 and q[0].name == "malware_x.exe"

    def test_threat_pipeline_returns_false(self, gw, zones):
        bad = zones["zone_i_input"] / "trojan_loader.bin"
        bad.write_bytes(b"bad" * 100)
        assert gw.process_file(bad, "pwd") is False

    def test_threat_leaves_zone_l_empty(self, gw, zones):
        bad = zones["zone_i_input"] / "ransomware.bat"
        bad.write_bytes(b"evil" * 100)
        gw.process_file(bad, "pwd")
        assert list(zones["zone_l_incoming"].iterdir()) == []

    def test_gateway_recovers_after_threat(self, gw, zones):
        bad = zones["zone_i_input"] / "virus_drop.vbs"
        bad.write_bytes(b"x" * 50)
        gw.process_file(bad, "pwd")
        assert gw.state == GatewayState.ERROR
        gw.reset_error()
        # Now process a clean file successfully
        good = zones["zone_i_input"] / "clean_doc.txt"
        good.write_text("all good")
        assert gw.process_file(good, "pwd") is True

    def test_empty_file_rejected(self, gw, zones):
        empty = zones["zone_i_input"] / "empty.txt"
        empty.write_bytes(b"")
        result = gw.process_file(empty, "pwd")
        assert result is False
        assert gw.state == GatewayState.ERROR


# ── Wrong password / corrupt decrypt ──────────────────────────────────────────

class TestDecryptErrors:

    def _setup_incoming(self, gw, zones, password="correct"):
        src = _src(zones)
        gw.process_file(src, password)
        return list(zones["zone_l_incoming"].iterdir())[0].name

    def test_wrong_password_raises_value_error(self, gw, zones):
        fname = self._setup_incoming(gw, zones, "correct")
        with pytest.raises(ValueError, match="wrong password"):
            gw.decrypt_request(fname, "wrong")

    def test_wrong_password_leaves_incoming_intact(self, gw, zones):
        fname = self._setup_incoming(gw, zones, "correct")
        try:
            gw.decrypt_request(fname, "wrong")
        except ValueError:
            pass
        assert (zones["zone_l_incoming"] / fname).exists()

    def test_bitflip_raises_value_error(self, gw, zones):
        fname = self._setup_incoming(gw, zones, "correct")
        enc_path = zones["zone_l_incoming"] / fname
        raw = bytearray(enc_path.read_bytes())
        raw[-1] ^= 0xFF
        enc_path.write_bytes(bytes(raw))
        with pytest.raises(ValueError):
            gw.decrypt_request(fname, "correct")

    def test_decrypt_missing_file_raises(self, gw, zones):
        with pytest.raises(FileNotFoundError):
            gw.decrypt_request("ghost.diode", "pwd")

    def test_decrypt_blocked_in_receiving_state(self, gw, zones):
        gw._state = GatewayState.RECEIVING
        with pytest.raises(RuntimeError, match="DENIED"):
            gw.decrypt_request("any.diode", "pwd")


# ── Directional isolation enforcement ────────────────────────────────────────

class TestDirectionalIsolation:

    def test_zone_l_locked_in_receiving(self, gw, zones):
        gw._state = GatewayState.RECEIVING
        with pytest.raises(RuntimeError):
            gw._assert_zone_l_allowed()

    def test_zone_i_locked_in_sending(self, gw, zones):
        gw._state = GatewayState.SENDING
        with pytest.raises(RuntimeError):
            gw._assert_zone_i_allowed()

    def test_both_open_in_idle(self, gw, zones):
        gw._state = GatewayState.IDLE
        gw._assert_zone_i_allowed()   # must not raise
        gw._assert_zone_l_allowed()   # must not raise

    def test_both_open_in_error(self, gw, zones):
        gw._state = GatewayState.ERROR
        gw._assert_zone_i_allowed()   # ERROR does not block either zone
        gw._assert_zone_l_allowed()

    def test_state_sequence_during_clean_run(self, gw, zones):
        sequence = []
        gw.on_state_change = lambda s: sequence.append(s)
        src = _src(zones)
        gw.process_file(src, "pwd")
        assert sequence == [
            GatewayState.RECEIVING,
            GatewayState.SENDING,
            GatewayState.IDLE,
        ]


# ── Concurrency ───────────────────────────────────────────────────────────────

class TestConcurrency:

    def test_lock_prevents_concurrent_pipelines(self, gw, zones):
        f1 = zones["zone_i_input"] / "a.txt"; f1.write_text("aaa" * 100)
        f2 = zones["zone_i_input"] / "b.txt"; f2.write_text("bbb" * 100)

        results = []

        def run(p):
            results.append(gw.process_file(p, "pwd"))

        t1 = threading.Thread(target=run, args=(f1,))
        t2 = threading.Thread(target=run, args=(f2,))
        t1.start(); t2.start()
        t1.join();  t2.join()

        assert sorted(results) == [False, True]

    def test_gateway_idle_after_concurrent_attempt(self, gw, zones):
        f1 = zones["zone_i_input"] / "x.txt"; f1.write_text("x" * 100)
        f2 = zones["zone_i_input"] / "y.txt"; f2.write_text("y" * 100)
        results = []
        threads = [threading.Thread(target=lambda p=p: results.append(
            gw.process_file(p, "pwd")
        )) for p in (f1, f2)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert gw.state == GatewayState.IDLE
