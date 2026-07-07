"""
core/engine.py
──────────────
MalTracerEngine — the live monitor orchestrator.
"""

import threading
import signal
import time
import logging

from core.event_bus import EventBus
from core.incident_manager import IncidentManager
from detection_engine.engine import DetectionEngine

logger = logging.getLogger(__name__)


class MalTracerEngine:

    def __init__(self):
        self._bus              = EventBus()
        self._incident_manager = IncidentManager()
        self._detection_engine = DetectionEngine()
        self._threads: list[threading.Thread] = []
        self._monitor_objects  = []
        self._running          = False
        self._stop_event       = threading.Event()

    def start(self, block: bool = True) -> None:
        logger.info("[Engine] Starting MalTracer live monitor …")

        loaded = self._incident_manager.load_from_disk()
        logger.info(f"[Engine] Loaded {loaded} incidents from disk")

        self._bus.subscribe(self._on_event)
        self._bus.start()

        self._start_process_monitor()
        self._start_network_monitor()
        self._start_file_monitor()

        self._running = True
        logger.info("[Engine] All monitors running.  Press Ctrl+C to stop.")

        if block:
            self._block_until_stop()

    def stop(self) -> None:
        if not self._running:
            return

        logger.info("[Engine] Shutting down …")
        self._running = False
        self._stop_event.set()

        for obj in self._monitor_objects:
            try:
                obj.stop()
                obj.join(timeout=3)
            except Exception as exc:
                logger.warning(f"[Engine] Monitor stop error: {exc}")

        self._bus.stop()

        logger.info("[Engine] Shutdown complete.")
        stats = self._bus.stats()
        logger.info(
            f"[Engine] Bus stats — published={stats['published']} "
            f"dispatched={stats['dispatched']} dropped={stats['dropped']} "
            f"errors={stats['errors']}"
        )

    def _on_event(self, event: dict) -> None:
        try:
            if not event.get("incident_id"):
                event["incident_id"] = IncidentManager.new_incident_id()

            self._incident_manager.open(event)
            self._detection_engine.process_event(event)

        except Exception as exc:
            logger.error(f"[Engine] _on_event error: {exc}", exc_info=True)

    def _start_process_monitor(self) -> None:
        from monitoring.process_monitor import monitor_processes

        def _run():
            try:
                monitor_processes(callback=self._bus.publish)
            except Exception as exc:
                logger.error(f"[Engine] ProcessMonitor crashed: {exc}", exc_info=True)

        t = threading.Thread(target=_run, name="ProcessMonitor", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("[Engine] ProcessMonitor thread started")

    def _start_network_monitor(self) -> None:
        from monitoring.network_monitor import monitor_connections

        def _run():
            try:
                monitor_connections(callback=self._bus.publish)
            except Exception as exc:
                logger.error(f"[Engine] NetworkMonitor crashed: {exc}", exc_info=True)

        t = threading.Thread(target=_run, name="NetworkMonitor", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("[Engine] NetworkMonitor thread started")

    def _start_file_monitor(self) -> None:
        from monitoring.file_monitor import start_file_monitor

        def _run():
            try:
                observer = start_file_monitor(callback=self._bus.publish)
                self._monitor_objects.append(observer)
                while self._running and observer.is_alive():
                    time.sleep(1)
            except Exception as exc:
                logger.error(f"[Engine] FileMonitor crashed: {exc}", exc_info=True)

        t = threading.Thread(target=_run, name="FileMonitor", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("[Engine] FileMonitor thread started")

    def _block_until_stop(self) -> None:
        original_sigint  = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _handler(signum, frame):
            print()
            logger.info(f"[Engine] Signal {signum} received — stopping …")
            self.stop()

        try:
            signal.signal(signal.SIGINT,  _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (OSError, ValueError):
            pass

        try:
            while self._running:
                self._stop_event.wait(timeout=1)
        finally:
            try:
                signal.signal(signal.SIGINT,  original_sigint)
                signal.signal(signal.SIGTERM, original_sigterm)
            except (OSError, ValueError):
                pass