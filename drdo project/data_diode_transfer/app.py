"""
app.py — Tkinter GUI entry point for the Data-Diode Secure Transfer System.

Three-panel layout
──────────────────
  ┌──────────────────┬────────────────────────────┬──────────────────┐
  │   ZONE I         │        GATEWAY              │    ZONE L        │
  │  (Internet)      │   State machine + logs      │   (Offline)      │
  │                  │                             │                  │
  │  • Select file   │  • State LED (colour)       │  • File list     │
  │  • Set password  │  • Zone I / L lock badges   │  • Set password  │
  │  • Upload btn    │  • Live activity log pane   │  • Decrypt btn   │
  │                  │  • Reset Error button       │  • Result path   │
  └──────────────────┴────────────────────────────┴──────────────────┘

Threading model
───────────────
  Main thread   : Tkinter event loop (all UI mutations happen here)
  Watcher thread: watchdog Observer (daemon)
  Pipeline thread: one daemon thread per file (gateway.process_file)
  All cross-thread UI calls go through root.after(0, fn) — Tkinter is not
  thread-safe; this keeps every widget update on the main thread.
"""

import threading
import shutil
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from pathlib import Path

from config import (
    APP_TITLE, APP_GEOMETRY, FONT_MONO, FONT_LABEL, FONT_TITLE,
    COLOUR_BG, COLOUR_PANEL, COLOUR_TEXT, COLOUR_ACCENT,
    COLOUR_IDLE, COLOUR_RECEIVING, COLOUR_SENDING, COLOUR_ERROR,
    GatewayState, ZONE_I_INPUT, ZONE_L_INCOMING, ALL_DIRS,
)
from logger_setup import get_logger, set_ui_callback
from gateway import Gateway
from watcher import ZoneIWatcher

log = get_logger(__name__)

# GatewayState → indicator colour
STATE_COLOURS = {
    GatewayState.IDLE:      COLOUR_IDLE,
    GatewayState.RECEIVING: COLOUR_RECEIVING,
    GatewayState.SENDING:   COLOUR_SENDING,
    GatewayState.ERROR:     COLOUR_ERROR,
}

STATE_DESCRIPTIONS = {
    GatewayState.IDLE:      "Waiting for new files",
    GatewayState.RECEIVING: "Processing Zone I file (Zone L locked)",
    GatewayState.SENDING:   "Transferring to Zone L (Zone I locked)",
    GatewayState.ERROR:     "Error — check log and press Reset",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main application class
# ─────────────────────────────────────────────────────────────────────────────

class DataDiodeApp:

    def __init__(self, root: tk.Tk):
        self.root    = root
        self.gateway = Gateway()
        self._ensure_dirs()
        self._build_ui()
        self._wire_callbacks()
        self._start_watcher()
        log.info("Data-Diode Transfer application started.")

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _ensure_dirs(self):
        """Create zone directories if they don't exist (idempotent)."""
        for d in ALL_DIRS:
            Path(d).mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.title(APP_TITLE)
        self.root.geometry(APP_GEOMETRY)
        self.root.configure(bg=COLOUR_BG)
        self.root.minsize(820, 560)

        self._build_title_bar()
        self._build_main_panels()
        self._build_status_bar()

    # ── Title bar ─────────────────────────────────────────────────────────────

    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg="#12121e", height=42)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        tk.Label(
            bar,
            text="  ⬡  DATA-DIODE  SECURE  TRANSFER  SYSTEM",
            font=("Courier", 12, "bold"),
            fg=COLOUR_ACCENT, bg="#12121e",
        ).pack(side=tk.LEFT, padx=12, pady=8)

        tk.Label(
            bar,
            text="AES-256-GCM  ·  PBKDF2-SHA256  ·  Directional Isolation",
            font=("Courier", 8),
            fg="#585878", bg="#12121e",
        ).pack(side=tk.RIGHT, padx=12)

    # ── Three-panel body ──────────────────────────────────────────────────────

    def _build_main_panels(self):
        body = tk.Frame(self.root, bg=COLOUR_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(6, 0))
        body.columnconfigure(0, weight=1, minsize=220)
        body.columnconfigure(1, weight=2, minsize=300)
        body.columnconfigure(2, weight=1, minsize=220)
        body.rowconfigure(0, weight=1)

        self._build_zone_i_panel(body)
        self._build_gateway_panel(body)
        self._build_zone_l_panel(body)

    def _make_panel(self, parent, col: int, header: str, hdr_bg: str) -> tk.Frame:
        """Create a standard panel: coloured header strip + dark content area."""
        outer = tk.Frame(parent, bg=hdr_bg)
        outer.grid(row=0, column=col, sticky="nsew", padx=4, pady=4)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        tk.Label(
            outer, text=header,
            font=("Courier", 10, "bold"),
            fg="white", bg=hdr_bg, pady=5,
        ).grid(row=0, column=0, sticky="ew")

        inner = tk.Frame(outer, bg=COLOUR_PANEL)
        inner.grid(row=1, column=0, sticky="nsew", padx=2, pady=(0, 2))
        inner.columnconfigure(0, weight=1)
        return inner

    # ── Zone I panel ──────────────────────────────────────────────────────────

    def _build_zone_i_panel(self, parent):
        f = self._make_panel(parent, col=0,
                             header="  ZONE I  (Internet-connected)",
                             hdr_bg="#5c2e00")

        self._lbl(f, "1. Select a file to transfer:").pack(padx=10, pady=(14, 2), anchor=tk.W)

        tk.Button(
            f, text="📂  Browse & Upload File",
            command=self._on_upload_file,
            bg="#7a3e0a", fg="white", font=FONT_LABEL,
            relief=tk.FLAT, padx=8, pady=7, cursor="hand2",
            activebackground="#9a5e2a", activeforeground="white",
        ).pack(padx=10, pady=4, fill=tk.X)

        self._sep(f)

        self._lbl(f, "2. Set Encryption Password:").pack(padx=10, pady=(8, 2), anchor=tk.W)
        self.enc_pwd_var = tk.StringVar()
        enc_entry = self._pwd_entry(f, self.enc_pwd_var)
        enc_entry.pack(padx=10, fill=tk.X)
        self._show_toggle(f, enc_entry).pack(padx=10, anchor=tk.W, pady=(0, 2))

        self._sep(f)
        self._lbl(f, "Queued file:").pack(padx=10, pady=(8, 2), anchor=tk.W)
        self.queued_file_var = tk.StringVar(value="—  (none)")
        tk.Label(
            f, textvariable=self.queued_file_var,
            font=("Courier", 8), fg=COLOUR_ACCENT, bg=COLOUR_PANEL,
            wraplength=195, justify=tk.LEFT,
        ).pack(padx=10, anchor=tk.W, pady=(0, 10))

        self._sep(f)
        self._lbl(f, "Zone I access:").pack(padx=10, pady=(6, 0), anchor=tk.W)
        self._zone_i_badge = tk.Label(
            f, text="✅  OPEN", font=("Helvetica", 9, "bold"),
            fg="#27ae60", bg=COLOUR_PANEL,
        )
        self._zone_i_badge.pack(padx=10, anchor=tk.W, pady=(0, 10))

    # ── Gateway panel ─────────────────────────────────────────────────────────

    def _build_gateway_panel(self, parent):
        f = self._make_panel(parent, col=1,
                             header="  GATEWAY  (Intermediary / Data-Diode)",
                             hdr_bg="#1a1a2e")

        # State row
        state_row = tk.Frame(f, bg=COLOUR_PANEL)
        state_row.pack(fill=tk.X, padx=10, pady=(10, 4))

        self._lbl(state_row, "State:").pack(side=tk.LEFT)

        self._state_led = tk.Label(
            state_row, text=" ● IDLE ",
            font=("Helvetica", 10, "bold"),
            fg=COLOUR_IDLE, bg=COLOUR_PANEL,
        )
        self._state_led.pack(side=tk.LEFT, padx=6)

        tk.Button(
            state_row, text="↺ Reset Error",
            command=self._on_reset_error,
            bg="#4a1010", fg="#ffaaaa",
            font=("Helvetica", 8), relief=tk.FLAT,
            padx=5, pady=2, cursor="hand2",
            activebackground="#6a2020",
        ).pack(side=tk.RIGHT)

        self._state_desc = tk.Label(
            f, text="Waiting for new files",
            font=("Helvetica", 8, "italic"),
            fg="#888aaa", bg=COLOUR_PANEL,
        )
        self._state_desc.pack(padx=10, anchor=tk.W)

        # Pipeline progress bar
        self._progress = ttk.Progressbar(f, mode="indeterminate", length=200)
        self._progress.pack(padx=10, pady=(4, 2), fill=tk.X)

        self._sep(f)

        # Zone lock badges
        badge_row = tk.Frame(f, bg=COLOUR_PANEL)
        badge_row.pack(fill=tk.X, padx=10, pady=4)
        self._zone_i_gw_badge = tk.Label(
            badge_row, text="Zone I: ✅ OPEN",
            font=("Helvetica", 9, "bold"), fg="#27ae60", bg=COLOUR_PANEL,
        )
        self._zone_i_gw_badge.pack(side=tk.LEFT, padx=(0, 30))
        self._zone_l_badge = tk.Label(
            badge_row, text="Zone L: ✅ OPEN",
            font=("Helvetica", 9, "bold"), fg="#27ae60", bg=COLOUR_PANEL,
        )
        self._zone_l_badge.pack(side=tk.LEFT)

        self._sep(f)

        # Log pane
        self._lbl(f, "Activity Log:").pack(padx=10, pady=(4, 2), anchor=tk.W)

        log_frame = tk.Frame(f, bg=COLOUR_PANEL)
        log_frame.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=("Courier", 8),
            bg="#0e0e1a", fg=COLOUR_TEXT,
            insertbackground=COLOUR_TEXT,
            relief=tk.FLAT, wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Log level colour tags
        self.log_text.tag_config("DEBUG",    foreground="#585878")
        self.log_text.tag_config("INFO",     foreground="#a6e3a1")
        self.log_text.tag_config("WARNING",  foreground="#f9e2af")
        self.log_text.tag_config("ERROR",    foreground="#f38ba8")
        self.log_text.tag_config("CRITICAL", foreground="#ff79c6")

        # Log controls
        ctrl_row = tk.Frame(f, bg=COLOUR_PANEL)
        ctrl_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        tk.Button(
            ctrl_row, text="Clear Log",
            command=self._clear_log,
            bg="#2a2a3e", fg="#888aaa",
            font=("Helvetica", 8), relief=tk.FLAT, padx=6,
        ).pack(side=tk.RIGHT)

    # ── Zone L panel ──────────────────────────────────────────────────────────

    def _build_zone_l_panel(self, parent):
        f = self._make_panel(parent, col=2,
                             header="  ZONE L  (Offline / Air-gapped)",
                             hdr_bg="#0a3a0a")

        self._lbl(f, "Encrypted files awaiting\ndecryption:").pack(
            padx=10, pady=(12, 2), anchor=tk.W
        )

        list_frame = tk.Frame(f, bg=COLOUR_PANEL)
        list_frame.pack(padx=10, fill=tk.BOTH, expand=True)

        sb = tk.Scrollbar(list_frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=sb.set,
            bg="#0e1a0e", fg=COLOUR_ACCENT,
            selectbackground="#2a5a2a",
            selectforeground="white",
            font=("Courier", 8),
            relief=tk.FLAT,
            selectmode=tk.SINGLE,
            activestyle="none",
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self.file_listbox.yview)

        tk.Button(
            f, text="🔄  Refresh List",
            command=self._refresh_zone_l_list,
            bg="#1a3a1a", fg="#88cc88",
            font=("Helvetica", 8), relief=tk.FLAT, padx=6, pady=3,
            cursor="hand2",
        ).pack(padx=10, pady=4, fill=tk.X)

        self._sep(f)

        self._lbl(f, "Decryption Password:").pack(padx=10, pady=(8, 2), anchor=tk.W)
        self.dec_pwd_var = tk.StringVar()
        dec_entry = self._pwd_entry(f, self.dec_pwd_var)
        dec_entry.pack(padx=10, fill=tk.X)
        self._show_toggle(f, dec_entry).pack(padx=10, anchor=tk.W, pady=(0, 2))

        tk.Button(
            f, text="🔓  Decrypt Selected File",
            command=self._on_decrypt,
            bg="#1a5a1a", fg="white",
            font=FONT_LABEL, relief=tk.FLAT,
            padx=8, pady=7, cursor="hand2",
            activebackground="#2a7a2a",
        ).pack(padx=10, pady=(10, 4), fill=tk.X)

        self._sep(f)
        self._lbl(f, "Last decrypted file:").pack(padx=10, pady=(6, 2), anchor=tk.W)
        self.dec_result_var = tk.StringVar(value="—  (none)")
        tk.Label(
            f, textvariable=self.dec_result_var,
            font=("Courier", 8), fg=COLOUR_ACCENT,
            bg=COLOUR_PANEL, wraplength=195, justify=tk.LEFT,
        ).pack(padx=10, anchor=tk.W, pady=(0, 10))

        self._lbl(f, "Zone L access:").pack(padx=10, pady=(4, 0), anchor=tk.W)
        self._zone_l_access_badge = tk.Label(
            f, text="✅  OPEN",
            font=("Helvetica", 9, "bold"), fg="#27ae60", bg=COLOUR_PANEL,
        )
        self._zone_l_access_badge.pack(padx=10, anchor=tk.W, pady=(0, 10))

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg="#12121e", height=24)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(
            bar, textvariable=self._status_var,
            font=("Courier", 8), fg="#888aaa", bg="#12121e",
        ).pack(side=tk.LEFT, padx=10)

        tk.Label(
            bar,
            text="Logs → logs/diode.log",
            font=("Courier", 8), fg="#585878", bg="#12121e",
        ).pack(side=tk.RIGHT, padx=10)

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _lbl(self, parent, text: str) -> tk.Label:
        return tk.Label(parent, text=text, font=FONT_LABEL,
                        fg=COLOUR_TEXT, bg=COLOUR_PANEL)

    def _sep(self, parent):
        tk.Frame(parent, bg="#3a3a5e", height=1).pack(fill=tk.X, padx=8, pady=4)

    def _pwd_entry(self, parent, var: tk.StringVar) -> tk.Entry:
        return tk.Entry(
            parent, textvariable=var,
            show="●", font=FONT_LABEL,
            bg="#1e1e32", fg=COLOUR_TEXT,
            insertbackground=COLOUR_TEXT,
            relief=tk.FLAT,
        )

    def _show_toggle(self, parent, entry: tk.Entry) -> tk.Checkbutton:
        var = tk.BooleanVar(value=False)
        return tk.Checkbutton(
            parent, text="Show password", variable=var,
            command=lambda: entry.config(show="" if var.get() else "●"),
            fg="#888aaa", bg=COLOUR_PANEL,
            selectcolor=COLOUR_PANEL, activebackground=COLOUR_PANEL,
            font=("Helvetica", 8),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Callback wiring
    # ─────────────────────────────────────────────────────────────────────────

    def _wire_callbacks(self):
        # Gateway state changes → update LED + lock badges
        self.gateway.on_state_change = lambda s: self.root.after(
            0, self._update_state_ui, s
        )
        # File arrives in Zone L → refresh list
        self.gateway.on_file_ready_for_decrypt = lambda name: self.root.after(
            0, self._on_file_ready, name
        )
        # Logger → UI log pane (thread-safe via root.after)
        set_ui_callback(
            lambda level, msg: self.root.after(0, self._append_log, level, msg)
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Watcher start / stop
    # ─────────────────────────────────────────────────────────────────────────

    def _start_watcher(self):
        self._watcher = ZoneIWatcher(on_new_file=self._on_new_file_detected)
        self._watcher.start()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─────────────────────────────────────────────────────────────────────────
    # User event handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _on_upload_file(self):
        """User picks a file → copy it into zone_i/input to trigger the pipeline."""
        filepath = filedialog.askopenfilename(title="Select file to transfer to Zone L")
        if not filepath:
            return

        password = self.enc_pwd_var.get().strip()
        if not password:
            messagebox.showwarning(
                "Password Required",
                "Please enter an encryption password before uploading a file.",
            )
            return

        src  = Path(filepath)
        dest = ZONE_I_INPUT / src.name

        try:
            if dest.exists():
                raise FileExistsError(
                    f"'{src.name}' already exists in Zone I input folder."
                )
            shutil.copy2(src, dest)
            self.queued_file_var.set(src.name)
            self._set_status(f"Uploaded: {src.name}")
            log.info("User uploaded file to Zone I input: '%s'", src.name)
        except FileExistsError as exc:
            messagebox.showerror("Duplicate File", str(exc))
        except PermissionError as exc:
            messagebox.showerror("Permission Error", str(exc))
        except Exception as exc:
            messagebox.showerror("Upload Error", str(exc))
            log.error("Upload error: %s", exc)

    def _on_new_file_detected(self, path: Path):
        """
        Called on the watchdog thread when a file lands in zone_i/input.
        Validates password, then hands off to a pipeline daemon thread.
        """
        password = self.enc_pwd_var.get().strip()
        if not password:
            log.warning(
                "File '%s' detected but no encryption password is set — skipping.",
                path.name,
            )
            self.root.after(
                0, messagebox.showwarning,
                "No Password",
                f"File '{path.name}' was detected in Zone I input but no "
                "encryption password is set.\n\nSet a password and re-upload the file.",
            )
            return

        log.info("Handing '%s' to pipeline thread (password set).", path.name)
        t = threading.Thread(
            target=self._pipeline_thread,
            args=(path, password),
            daemon=True,
            name=f"pipeline-{path.name}",
        )
        t.start()

    def _pipeline_thread(self, path: Path, password: str):
        """Daemon thread: run the gateway pipeline, report errors back to UI."""
        self.root.after(0, self._progress.start, 12)
        ok = self.gateway.process_file(path, password)
        self.root.after(0, self._progress.stop)
        self.root.after(0, self._progress.config, {"value": 0})

        if not ok:
            if self.gateway.state == GatewayState.ERROR:
                self.root.after(
                    0, messagebox.showerror,
                    "Pipeline Error",
                    f"The gateway encountered an error while processing "
                    f"'{path.name}'.\n\n"
                    "Check the Activity Log for details, then press "
                    "'↺ Reset Error' to resume.",
                )

    def _on_decrypt(self):
        """User clicks Decrypt — decrypt selected file from Zone L incoming."""
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("No File Selected",
                                   "Please select an encrypted file from the list.")
            return

        filename = self.file_listbox.get(selection[0])
        password = self.dec_pwd_var.get().strip()
        if not password:
            messagebox.showwarning("No Password",
                                   "Please enter the decryption password.")
            return

        try:
            result_path = self.gateway.decrypt_request(filename, password)
            self.dec_result_var.set(result_path.name)
            self._refresh_zone_l_list()
            self._set_status(f"Decrypted: {result_path.name}")
            messagebox.showinfo(
                "Decryption Successful",
                f"File decrypted successfully!\n\n"
                f"Saved to:\n{result_path}",
            )
        except RuntimeError as exc:
            messagebox.showerror("Access Denied", str(exc))
        except ValueError as exc:
            messagebox.showerror(
                "Decryption Failed",
                f"Wrong password or the file is corrupted / tampered.\n\n{exc}",
            )
        except FileNotFoundError as exc:
            messagebox.showerror("File Not Found", str(exc))
            self._refresh_zone_l_list()
        except FileExistsError as exc:
            messagebox.showerror("Already Exists", str(exc))
        except Exception as exc:
            messagebox.showerror("Unexpected Error", str(exc))
            log.error("Zone L decrypt error: %s", exc)

    def _on_reset_error(self):
        self.gateway.reset_error()
        self._set_status("Error state cleared. Ready.")

    def _on_file_ready(self, filename: str):
        """Called (via root.after) when a file lands in zone_l/incoming."""
        self._refresh_zone_l_list()
        self._set_status(f"Ready to decrypt: {filename}")

    def _on_close(self):
        self._watcher.stop()
        self.root.destroy()

    # ─────────────────────────────────────────────────────────────────────────
    # UI update helpers — all must be called from the main thread
    # ─────────────────────────────────────────────────────────────────────────

    def _update_state_ui(self, state: GatewayState):
        colour = STATE_COLOURS.get(state, COLOUR_IDLE)
        self._state_led.config(text=f" ● {state.name} ", fg=colour)
        self._state_desc.config(text=STATE_DESCRIPTIONS.get(state, ""))
        self._set_status(STATE_DESCRIPTIONS.get(state, state.name))

        if state == GatewayState.RECEIVING:
            zi_text, zi_col = "✅  OPEN",   "#27ae60"
            zl_text, zl_col = "🔒  LOCKED", "#e74c3c"
        elif state == GatewayState.SENDING:
            zi_text, zi_col = "🔒  LOCKED", "#e74c3c"
            zl_text, zl_col = "✅  OPEN",   "#27ae60"
        else:
            zi_text, zi_col = "✅  OPEN",   "#27ae60"
            zl_text, zl_col = "✅  OPEN",   "#27ae60"

        for badge, text, col in [
            (self._zone_i_badge,        zi_text, zi_col),
            (self._zone_i_gw_badge,     f"Zone I: {zi_text}", zi_col),
            (self._zone_l_badge,        f"Zone L: {zl_text}", zl_col),
            (self._zone_l_access_badge, zl_text, zl_col),
        ]:
            badge.config(text=text, fg=col)

    def _append_log(self, level: str, msg: str):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n", level)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _refresh_zone_l_list(self):
        self.file_listbox.delete(0, tk.END)
        files = sorted(p for p in ZONE_L_INCOMING.iterdir() if p.is_file())
        for f in files:
            self.file_listbox.insert(tk.END, f.name)
        if not files:
            self.file_listbox.insert(tk.END, "(no files)")

    def _set_status(self, msg: str):
        self._status_var.set(msg)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    # Ensure all zone directories exist before the UI tries to list them
    for d in ALL_DIRS:
        Path(d).mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    app  = DataDiodeApp(root)
    app._refresh_zone_l_list()  # populate the Zone L list on startup
    root.mainloop()


if __name__ == "__main__":
    main()
