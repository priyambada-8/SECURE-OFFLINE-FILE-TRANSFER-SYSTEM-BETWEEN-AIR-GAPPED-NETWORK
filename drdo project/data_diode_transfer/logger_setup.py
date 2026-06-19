"""
logger_setup.py — Centralised, rotating-file logger with console + UI hooks.
Every module imports get_logger(__name__) from here.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config import LOG_DIR, LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT

# Ensure log directory exists before any handler tries to write
LOG_DIR.mkdir(parents=True, exist_ok=True)

_FMT  = "%(asctime)s  [%(levelname)-8s]  %(name)-22s  %(message)s"
_DATE = "%Y-%m-%d %H:%M:%S"

# Module-level UI callback — set by app.py after the UI is built
_ui_log_callback = None


def set_ui_callback(fn):
    """Register a callable(level: str, message: str) to push logs to the UI."""
    global _ui_log_callback
    _ui_log_callback = fn


class _UIHandler(logging.Handler):
    """Forwards log records to the registered UI callback (thread-safe)."""

    def emit(self, record):
        if _ui_log_callback:
            try:
                _ui_log_callback(record.levelname, self.format(record))
            except Exception:
                pass   # Never let a UI error crash the logging system


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger wired to:
      - Rotating file  (logs/diode.log)
      - Console (stdout)
      - UI panel (when callback is registered)
    """
    logger = logging.getLogger(name)

    if logger.handlers:          # Already configured in this process
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(_FMT, datefmt=_DATE)

    # ── File handler ──────────────────────────────────────────────────────────
    fh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    # ── Console handler ───────────────────────────────────────────────────────
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    # ── UI handler ────────────────────────────────────────────────────────────
    uh = _UIHandler()
    uh.setLevel(logging.INFO)
    uh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.addHandler(uh)

    return logger
