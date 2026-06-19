"""
watcher.py — Monitors zone_i/input for new files using watchdog.

When a FileCreatedEvent fires, the registered callback is invoked with the
Path of the new file on the watchdog thread.  The Gateway is responsible for
all further processing; this module stays deliberately thin.
"""

from pathlib import Path
from typing import Callable

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent

from config import ZONE_I_INPUT
from logger_setup import get_logger

log = get_logger(__name__)


class _ZoneIHandler(FileSystemEventHandler):
    """Internal watchdog handler — fires the registered callback on file creation."""

    def __init__(self, on_new_file: Callable[[Path], None]):
        super().__init__()
        self._on_new_file = on_new_file

    def on_created(self, event: FileCreatedEvent):
        if event.is_directory:
            return
        path = Path(event.src_path)
        # Ignore hidden / temp files that editors or OS may create
        if path.name.startswith(".") or path.name.endswith(".tmp"):
            log.debug("Ignoring temp/hidden file: %s", path.name)
            return
        log.info("Zone I — new file detected: '%s'", path.name)
        self._on_new_file(path)


class ZoneIWatcher:
    """
    Wraps the watchdog Observer with a simple start/stop interface.

    on_new_file(path: Path) is invoked on the watchdog background thread,
    so it must either be thread-safe or hand work off via a queue.
    """

    def __init__(self, on_new_file: Callable[[Path], None]):
        self._handler  = _ZoneIHandler(on_new_file)
        self._observer = Observer()
        self._observer.schedule(
            self._handler,
            str(ZONE_I_INPUT),
            recursive=False,
        )

    def start(self) -> None:
        self._observer.start()
        log.info("Zone I watcher started  →  monitoring: %s", ZONE_I_INPUT)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()
        log.info("Zone I watcher stopped.")

    @property
    def is_alive(self) -> bool:
        return self._observer.is_alive()
