"""
scanner.py — Antivirus / threat-scan step.

SIMULATED_SCAN=True  →  pattern-match on filename (demo / CI safe)
SIMULATED_SCAN=False →  shells out to REAL_SCANNER_CMD (e.g. ClamAV)

To swap in a real scanner:
  1. Install ClamAV  (or any CLI scanner)
  2. Set SIMULATED_SCAN = False in config.py
  3. Update REAL_SCANNER_CMD with the correct binary path + flags
"""

import subprocess
from pathlib import Path

from config import SIMULATED_SCAN, REAL_SCANNER_CMD, SIMULATED_THREAT_PATTERNS
from logger_setup import get_logger

log = get_logger(__name__)


class ScanResult:
    """Value object returned by every scan operation."""

    __slots__ = ("passed", "threat_name", "detail")

    def __init__(self, passed: bool, threat_name: str = "", detail: str = ""):
        self.passed      = passed
        self.threat_name = threat_name
        self.detail      = detail

    def __repr__(self):
        status = "CLEAN" if self.passed else f"THREAT({self.threat_name})"
        return f"ScanResult({status})"


class FileScanner:
    """Encapsulates the scan strategy chosen via config."""

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, filepath: Path) -> ScanResult:
        """
        Scan *filepath* and return a ScanResult.
        Raises FileNotFoundError if the file has gone missing before scan.
        """
        if not filepath.exists():
            raise FileNotFoundError(f"Scanner: file not found → {filepath}")

        log.info("Scanning: %s  [mode=%s]",
                 filepath.name, "SIMULATED" if SIMULATED_SCAN else "REAL")

        if SIMULATED_SCAN:
            return self._simulated_scan(filepath)
        return self._real_scan(filepath)

    # ── Internal strategies ───────────────────────────────────────────────────

    def _simulated_scan(self, filepath: Path) -> ScanResult:
        """
        Simulate AV by checking the filename for known threat keywords.
        In production, replace this entire method body with a real SDK call.
        """
        name_lower = filepath.name.lower()
        for pattern in SIMULATED_THREAT_PATTERNS:
            if pattern in name_lower:
                log.warning("Simulated threat detected: '%s' in '%s'",
                            pattern, filepath.name)
                return ScanResult(
                    passed=False,
                    threat_name=pattern.upper(),
                    detail=f"Filename matched threat pattern '{pattern}'",
                )

        size = filepath.stat().st_size
        if size == 0:
            return ScanResult(
                passed=False,
                threat_name="EMPTY_FILE",
                detail="File is zero bytes — rejected",
            )

        log.info("Simulated scan PASSED for '%s' (%d bytes)", filepath.name, size)
        return ScanResult(passed=True, detail=f"Clean ({size} bytes)")

    def _real_scan(self, filepath: Path) -> ScanResult:
        """
        Invoke an external scanner binary (e.g. ClamAV).
        Return codes:
          0  → clean
          1  → threat found
          2  → scanner error
        """
        cmd = REAL_SCANNER_CMD + [str(filepath)]
        log.debug("Invoking scanner: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            stdout = result.stdout.strip()
            if result.returncode == 0:
                log.info("Real scanner PASSED: %s", filepath.name)
                return ScanResult(passed=True, detail=stdout)
            elif result.returncode == 1:
                log.warning("Real scanner THREAT in %s: %s", filepath.name, stdout)
                return ScanResult(passed=False, threat_name="DETECTED", detail=stdout)
            else:
                log.error("Scanner process error (rc=%d): %s", result.returncode, stdout)
                return ScanResult(
                    passed=False,
                    threat_name="SCANNER_ERROR",
                    detail=f"rc={result.returncode}: {stdout}",
                )
        except subprocess.TimeoutExpired:
            log.error("Scanner timed out on %s", filepath.name)
            return ScanResult(passed=False, threat_name="TIMEOUT",
                              detail="Scanner process exceeded 60 s")
        except FileNotFoundError:
            log.critical("Scanner binary not found: %s", REAL_SCANNER_CMD[0])
            return ScanResult(passed=False, threat_name="SCANNER_MISSING",
                              detail=f"Binary '{REAL_SCANNER_CMD[0]}' not found on PATH")
