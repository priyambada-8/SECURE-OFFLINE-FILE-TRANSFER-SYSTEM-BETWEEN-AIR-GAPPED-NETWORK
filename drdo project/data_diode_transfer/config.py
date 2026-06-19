"""
config.py — Central configuration, paths, and gateway state definitions.
All magic strings and tunable constants live here.
"""

import os
from enum import Enum, auto
from pathlib import Path

# ── Base directory (project root) ──────────────────────────────────────────
BASE_DIR  = Path(__file__).parent.resolve()
ZONES_DIR = BASE_DIR / "zones"

# ── Zone folder paths ───────────────────────────────────────────────────────
ZONE_I_INPUT     = ZONES_DIR / "zone_i"  / "input"
GATEWAY_PROC     = ZONES_DIR / "gateway" / "processing"
GATEWAY_ENC      = ZONES_DIR / "gateway" / "encrypted"
ZONE_L_INCOMING  = ZONES_DIR / "zone_l"  / "incoming"
ZONE_L_DECRYPTED = ZONES_DIR / "zone_l"  / "decrypted"
GATEWAY_QUARANTINE = ZONES_DIR / "gateway" / "quarantine"

ALL_DIRS = [
    ZONE_I_INPUT,
    GATEWAY_PROC,
    GATEWAY_ENC,
    GATEWAY_QUARANTINE,
    ZONE_L_INCOMING,
    ZONE_L_DECRYPTED,
]

# ── Encrypted file extension ─────────────────────────────────────────────────
ENCRYPTED_SUFFIX = ".diode"

# ── Gateway state machine ─────────────────────────────────────────────────────
class GatewayState(Enum):
    IDLE      = auto()   # Waiting — both zones logically accessible
    RECEIVING = auto()   # Zone I active  → Zone L LOCKED
    SENDING   = auto()   # Zone L active  → Zone I LOCKED
    ERROR     = auto()   # Hard fault — operator must reset

# ── Watcher / polling ─────────────────────────────────────────────────────────
WATCHER_POLL_INTERVAL = 2      # seconds between directory polls
FILE_SETTLE_DELAY     = 1.0    # seconds to wait after creation before processing

# ── Scanner ───────────────────────────────────────────────────────────────────
# Swap SIMULATED_SCAN = False and provide a real scanner command to go live.
SIMULATED_SCAN = True
REAL_SCANNER_CMD = ["clamscan", "--no-summary"]  # example: ClamAV

# Simulated threat keywords (lowercased filename substrings)
SIMULATED_THREAT_PATTERNS = ["eicar", "malware", "virus", "trojan", "ransomware"]

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_DIR          = BASE_DIR / "logs"
LOG_FILE         = LOG_DIR  / "diode.log"
LOG_MAX_BYTES    = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT = 3

# ── UI ────────────────────────────────────────────────────────────────────────
APP_TITLE    = "Data-Diode Secure Transfer"
APP_GEOMETRY = "980x680"
FONT_MONO    = ("Courier", 9)
FONT_LABEL   = ("Helvetica", 10)
FONT_TITLE   = ("Helvetica", 13, "bold")

# ── Colours ───────────────────────────────────────────────────────────────────
COLOUR_IDLE      = "#27ae60"
COLOUR_RECEIVING = "#e67e22"
COLOUR_SENDING   = "#2980b9"
COLOUR_ERROR     = "#c0392b"
COLOUR_BG        = "#1e1e2e"
COLOUR_PANEL     = "#2a2a3e"
COLOUR_TEXT      = "#cdd6f4"
COLOUR_ACCENT    = "#89b4fa"
