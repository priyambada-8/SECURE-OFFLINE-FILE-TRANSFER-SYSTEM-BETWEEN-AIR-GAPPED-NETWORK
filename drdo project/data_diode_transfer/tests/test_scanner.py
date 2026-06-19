"""
tests/test_scanner.py — Unit tests for the FileScanner (simulated mode).
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import FileScanner, ScanResult


@pytest.fixture
def scanner():
    return FileScanner()


@pytest.fixture
def clean_file(tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"PDF content here " * 100)
    return f


@pytest.fixture
def threat_file(tmp_path):
    f = tmp_path / "malware_payload.exe"
    f.write_bytes(b"some bytes")
    return f


@pytest.fixture
def empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    return f


class TestScanResult:

    def test_repr_clean(self):
        r = ScanResult(passed=True, detail="Clean (1024 bytes)")
        assert "CLEAN" in repr(r)

    def test_repr_threat(self):
        r = ScanResult(passed=False, threat_name="VIRUS")
        assert "THREAT(VIRUS)" in repr(r)


class TestFileScanner:

    def test_clean_file_passes(self, scanner, clean_file):
        result = scanner.scan(clean_file)
        assert result.passed is True

    def test_threat_filename_fails(self, scanner, threat_file):
        result = scanner.scan(threat_file)
        assert result.passed is False
        assert result.threat_name == "MALWARE"

    def test_empty_file_fails(self, scanner, empty_file):
        result = scanner.scan(empty_file)
        assert result.passed is False
        assert result.threat_name == "EMPTY_FILE"

    def test_missing_file_raises(self, scanner, tmp_path):
        ghost = tmp_path / "ghost.txt"
        with pytest.raises(FileNotFoundError):
            scanner.scan(ghost)

    def test_eicar_pattern_detected(self, scanner, tmp_path):
        f = tmp_path / "eicar_test.com"
        f.write_bytes(b"data")
        result = scanner.scan(f)
        assert not result.passed
        assert result.threat_name == "EICAR"

    def test_trojan_pattern_detected(self, scanner, tmp_path):
        f = tmp_path / "trojan_dropper.bin"
        f.write_bytes(b"x" * 100)
        result = scanner.scan(f)
        assert not result.passed

    def test_ransomware_pattern_detected(self, scanner, tmp_path):
        f = tmp_path / "ransomware_enc.dat"
        f.write_bytes(b"y" * 100)
        result = scanner.scan(f)
        assert not result.passed

    def test_normal_names_not_flagged(self, scanner, tmp_path):
        for name in ["document.pdf", "photo.jpg", "notes.txt", "archive.zip"]:
            f = tmp_path / name
            f.write_bytes(b"content" * 50)
            result = scanner.scan(f)
            assert result.passed, f"Expected '{name}' to pass scan"

    def test_detail_contains_size_for_clean(self, scanner, clean_file):
        result = scanner.scan(clean_file)
        assert "bytes" in result.detail

    def test_threat_detail_mentions_pattern(self, scanner, threat_file):
        result = scanner.scan(threat_file)
        assert "malware" in result.detail.lower()
