# Data-Diode Secure Transfer System

A Python simulation of a hardware data-diode — a unidirectional security gateway
that transfers files from an internet-connected zone (Zone I) to an offline zone
(Zone L) with enforced directional isolation, AV scanning, and AES-256-GCM encryption.

---

## Project Structure

```
data_diode_transfer/
│
├── app.py               ← Tkinter GUI entry point
├── cli_runner.py        ← Headless CLI alternative
├── gateway.py           ← Core state machine + pipeline orchestrator
├── watcher.py           ← Watchdog file monitor (Zone I input)
├── scanner.py           ← AV scan module (simulated, swappable)
├── crypto_utils.py      ← AES-256-GCM encrypt / decrypt
├── transfer.py          ← Zone L delivery + cleanup
├── config.py            ← All constants, paths, state definitions
├── logger_setup.py      ← Centralised rotating logger
├── setup_folders.py     ← One-time directory initialiser
│
├── requirements.txt
│
├── tests/
│   ├── test_crypto_utils.py   (21 tests)
│   ├── test_scanner.py        (12 tests)
│   ├── test_gateway.py        (22 tests)
│   └── test_transfer.py       (12 tests)
│
└── zones/               ← Created by setup_folders.py
    ├── zone_i/
    │   └── input/             ← Drop files here (Zone I upload point)
    ├── gateway/
    │   ├── processing/        ← Scan + encrypt staging (auto-cleaned)
    │   ├── encrypted/         ← Encrypted staging (auto-cleaned)
    │   └── quarantine/        ← Flagged / infected files
    └── zone_l/
        ├── incoming/          ← Encrypted files awaiting decryption
        └── decrypted/         ← Final plaintext output
```

---

## Installation

```bash
# 1. Clone / unzip the project
cd data_diode_transfer

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create zone folders (run once)
python setup_folders.py
```

### Tkinter note
- **Windows / macOS**: ships with Python — no extra step needed.
- **Ubuntu / Debian**: `sudo apt install python3-tk`
- **No display** (server/CI): use `python cli_runner.py` instead.

---

## Running

### GUI mode (recommended)
```bash
python app.py
```

### CLI mode (headless)
```bash
python cli_runner.py
```

### Run tests
```bash
pytest tests/ -v
```

---

## How It Works

### State machine (directional isolation)

```
Zone I input/                  GATEWAY                    Zone L
─────────────            ────────────────────           ──────────
                         [IDLE]
                            │
file dropped ──────────►    │ → RECEIVING
                            │   Zone L: 🔒 LOCKED
                            │   • Move file to processing/
                            │   • AV scan
                            │     ├── FAIL → quarantine/, ERROR state
                            │     └── PASS ↓
                            │   • AES-256-GCM encrypt
                            │
                            │ → SENDING
   Zone I: 🔒 LOCKED        │   • Copy .diode to zone_l/incoming/
                            │   • Delete gateway temps
                            │
                            │ → IDLE
                                (both zones open, loop continues)
```

The `threading.Lock` in `Gateway` ensures **only one pipeline runs at a time**.
`GatewayState` (enum) makes the current phase explicit.  
`_assert_zone_i_allowed()` / `_assert_zone_l_allowed()` raise `RuntimeError`
if code attempts a cross-zone operation during the wrong phase.

### Encryption format (.diode file)

```
┌──────────────────────────────────────────────┐
│  MAGIC     5 bytes   b"DIODE"                │
│  SALT     16 bytes   random (per-file)        │
│  NONCE    12 bytes   random (per-file)        │
│  CIPHERTEXT          AES-256-GCM output       │
│  GCM TAG  16 bytes   authentication tag       │
└──────────────────────────────────────────────┘
```

- Key derivation: PBKDF2-HMAC-SHA256, 390 000 iterations (OWASP 2023)
- Any bit-flip or wrong password → `InvalidTag` before any plaintext is produced
- Random salt + nonce per file: same password + same plaintext → different ciphertext every time

---

## Sample Run Flow

```
1. Launch: python app.py

2. Zone I panel:
   - Click "Browse & Upload File" → select quarterly_report.pdf
   - Enter password: "S3cur3!Pass"
   - File is copied to zones/zone_i/input/

3. Watchdog detects quarterly_report.pdf

4. Gateway → RECEIVING
   Zone L badge: 🔒 LOCKED
   ├─ Moved  → gateway/processing/quarterly_report.pdf
   ├─ Scanned → PASSED  (Clean, 142 KB)
   └─ Encrypted → gateway/encrypted/quarterly_report.pdf.diode

5. Gateway → SENDING
   Zone I badge: 🔒 LOCKED
   ├─ Copied → zone_l/incoming/quarterly_report.pdf.diode
   └─ Gateway temps deleted

6. Gateway → IDLE
   Zone L listbox shows: quarterly_report.pdf.diode

7. Zone L panel:
   - Select quarterly_report.pdf.diode
   - Enter password: "S3cur3!Pass"
   - Click "Decrypt Selected File"
   → Saved to zone_l/decrypted/quarterly_report.pdf ✅
   → zone_l/incoming/ staging file deleted

8. Loop resets — gateway ready for next file
```

---

## Simulated AV → Real AV (swap guide)

1. Install ClamAV: `sudo apt install clamav && freshclam`
2. In `config.py`:
   ```python
   SIMULATED_SCAN   = False
   REAL_SCANNER_CMD = ["/usr/bin/clamscan", "--no-summary"]
   ```
3. That's it. The `FileScanner._real_scan()` branch handles the rest.

---

## Error handling reference

| Condition | Behaviour |
|---|---|
| Wrong decrypt password | `ValueError` → UI error dialog |
| Corrupted .diode file (bit-flip) | `ValueError` (GCM tag fails) → UI error dialog |
| Threat detected in scan | File quarantined, Gateway → ERROR, UI error dialog |
| Empty file uploaded | Scan rejects (EMPTY_FILE), Gateway → ERROR |
| Duplicate filename in processing | `FileExistsError`, Gateway → ERROR |
| Duplicate in Zone L incoming | `FileExistsError`, Gateway → ERROR |
| File vanishes during settle delay | Logged as warning, soft False return, Gateway → IDLE |
| Decrypted output already exists | `FileExistsError` → UI error dialog |
| Gateway busy (concurrent upload) | Second file skipped with warning log |

---

## Future Improvements

| Area | Improvement |
|---|---|
| Real AV | ClamAV / Windows Defender CLI via `SIMULATED_SCAN=False` |
| Asymmetric crypto | RSA/X25519 key-pair so no shared secret crosses zones |
| HMAC manifest | SHA-256 hash file alongside each transfer for integrity audit |
| Upload queue | `queue.Queue` in watcher for burst-handling multiple drops |
| Audit database | SQLite log: filename, SHA-256, timestamp, operator ID |
| Rate limiting | Max N files/hour per zone to prevent flooding |
| File size cap | Configurable max upload size with early rejection |
| REST API mode | Flask wrapper for non-desktop Zone I clients |
| Hardware diode | GPIO pin read (Raspberry Pi) to replace software state |
| GUI drag-and-drop | Allow dragging files directly onto the Zone I panel |
