"""
core/event_bus.py
─────────────────
Thread-safe publish/subscribe event bus for MalTracer.

Design:
  • Monitors call EventBus.publish(event) from their own threads.
  • The detection engine subscribes via EventBus.subscribe(handler).
  • Internally a queue.Queue buffers events; a dedicated dispatcher thread
    drains the queue and calls each registered handler in order.
  • Handlers are called synchronously inside the dispatcher thread, so they
    must return quickly.  Long work (containment) must be offloaded inside
    the handler (ContainmentEngine already does this via daemon threads).

Concurrency guarantees:
  • publish() is safe to call from any thread.
  • subscribe() / unsubscribe() are safe to call from any thread.
  • No handler is ever called concurrently with itself (single dispatcher).
  • A slow handler delays other handlers — keep handlers fast.

Usage:
    bus = EventBus()
    bus.subscribe(my_handler)          # my_handler(event: dict) → None
    bus.start()                        # starts the dispatcher thread
    bus.publish({"source": "test"})    # enqueue an event
    bus.stop()                         # flush queue and stop dispatcher
"""

import queue
import threading
import logging
from datetime import datetime, timezone
from typing import Callable

from logging_system.logger import get_logger
from utils.constants import EVENT_BUS_MAXSIZE

logger = get_logger(__name__)

# Sentinel object: placing this on the queue tells the dispatcher to stop.
_STOP_SENTINEL = object()


class EventBus:
    """
    Central publish/subscribe hub.

    Single instance is created by core/engine.py and shared with all monitors.
    """

    def __init__(self, maxsize: int = EVENT_BUS_MAXSIZE):
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._handlers: list[Callable[[dict], None]] = []
        self._handlers_lock = threading.Lock()
        self._dispatcher: threading.Thread | None = None
        self._running = False

        # Statistics — useful for dashboard and tests
        self._stats = {
            "published":  0,
            "dispatched": 0,
            "dropped":    0,
            "errors":     0,
        }
        self._stats_lock = threading.Lock()

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the dispatcher thread.  Safe to call only once."""
        if self._running:
            logger.warning("[EventBus] start() called but bus is already running.")
            return

        self._running = True
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop,
            name="maltracer-eventbus",
            daemon=True,
        )
        self._dispatcher.start()
        logger.info("[EventBus] Dispatcher started.")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal the dispatcher to stop after draining the queue.
        Blocks until the dispatcher thread exits or timeout elapses.
        """
        if not self._running:
            return

        self._running = False
        self._queue.put(_STOP_SENTINEL)   # wake dispatcher if idle

        if self._dispatcher and self._dispatcher.is_alive():
            self._dispatcher.join(timeout=timeout)

        logger.info(
            f"[EventBus] Stopped. stats={self._stats}"
        )

    @property
    def is_running(self) -> bool:
        return self._running

    # ──────────────────────────────────────────────────────────────────────────
    # Subscription management
    # ──────────────────────────────────────────────────────────────────────────

    def subscribe(self, handler: Callable[[dict], None]) -> None:
        """
        Register a callable to receive every event.
        The callable must accept a single argument: the event dict.
        Can be called before or after start().
        """
        with self._handlers_lock:
            if handler not in self._handlers:
                self._handlers.append(handler)
                logger.debug(f"[EventBus] Handler subscribed: {handler.__qualname__}")

    def unsubscribe(self, handler: Callable[[dict], None]) -> None:
        """Remove a previously registered handler."""
        with self._handlers_lock:
            try:
                self._handlers.remove(handler)
                logger.debug(f"[EventBus] Handler unsubscribed: {handler.__qualname__}")
            except ValueError:
                pass  # not registered — ignore

    @property
    def handler_count(self) -> int:
        with self._handlers_lock:
            return len(self._handlers)

    # ──────────────────────────────────────────────────────────────────────────
    # Publishing
    # ──────────────────────────────────────────────────────────────────────────

    def publish(self, event: dict) -> bool:
        """
        Enqueue an event for dispatch.

        Stamps event["bus_enqueued_at"] with the current UTC time if missing.
        Returns True if the event was enqueued, False if the queue was full
        and the event was dropped (non-blocking to protect the caller).
        """
        if not isinstance(event, dict):
            logger.error(f"[EventBus] publish() received non-dict: {type(event)}")
            return False

        # Stamp enqueue time for latency tracking
        if "bus_enqueued_at" not in event:
            event["bus_enqueued_at"] = datetime.now(timezone.utc).isoformat()

        try:
            self._queue.put_nowait(event)
            with self._stats_lock:
                self._stats["published"] += 1
            return True
        except queue.Full:
            with self._stats_lock:
                self._stats["dropped"] += 1
            logger.error(
                f"[EventBus] Queue full — event DROPPED. "
                f"source={event.get('source', 'unknown')} "
                f"incident={event.get('incident_id', 'none')}"
            )
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Internal dispatcher
    # ──────────────────────────────────────────────────────────────────────────

    def _dispatch_loop(self) -> None:
        """
        Runs in the dispatcher thread.
        Pulls events off the queue and calls each registered handler in order.
        """
        logger.debug("[EventBus] Dispatch loop started.")

        while True:
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                # Check if we were asked to stop while idle
                if not self._running:
                    break
                continue

            # Stop sentinel
            if item is _STOP_SENTINEL:
                logger.debug("[EventBus] Stop sentinel received — draining remaining events.")
                # Drain whatever is left before exiting
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                        if remaining is not _STOP_SENTINEL:
                            self._call_handlers(remaining)
                    except queue.Empty:
                        break
                break

            self._call_handlers(item)
            self._queue.task_done()

        logger.debug("[EventBus] Dispatch loop exited.")

    def _call_handlers(self, event: dict) -> None:
        """Call every registered handler, catching exceptions so one bad
        handler cannot kill the dispatcher thread."""
        with self._handlers_lock:
            handlers = list(self._handlers)   # snapshot — avoid holding lock during calls

        for handler in handlers:
            try:
                handler(event)
                with self._stats_lock:
                    self._stats["dispatched"] += 1
            except Exception as exc:
                with self._stats_lock:
                    self._stats["errors"] += 1
                logger.error(
                    f"[EventBus] Handler {handler.__qualname__} raised exception: {exc}",
                    exc_info=True,
                )

    # ──────────────────────────────────────────────────────────────────────────
    # Diagnostics
    # ──────────────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return a copy of the current statistics dict."""
        with self._stats_lock:
            return dict(self._stats)

    def queue_size(self) -> int:
        """Approximate number of events waiting to be dispatched."""
        return self._queue.qsize()

    def __repr__(self) -> str:
        return (
            f"<EventBus running={self._running} "
            f"handlers={self.handler_count} "
            f"qsize={self.queue_size()} "
            f"stats={self._stats}>"
        )
