"""
tests/test_event_bus.py
───────────────────────
Unit tests for core/event_bus.py

Run from project root:
    python -m pytest tests/test_event_bus.py -v
"""

import time
import threading
import pytest
from core.event_bus import EventBus


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(source: str = "test_monitor", level: str = "LOW") -> dict:
    return {
        "source":       source,
        "threat_level": level,
        "incident_id":  "INC-20260517-testtest",
    }


def _wait_for(condition_fn, timeout: float = 2.0, interval: float = 0.05) -> bool:
    """Spin-wait until condition_fn() is True or timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition_fn():
            return True
        time.sleep(interval)
    return False


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestEventBusLifecycle:

    def test_starts_and_stops_cleanly(self):
        bus = EventBus()
        bus.start()
        assert bus.is_running
        bus.stop()
        assert not bus.is_running

    def test_start_is_idempotent(self):
        """Calling start() twice should not raise or create a second thread."""
        bus = EventBus()
        bus.start()
        bus.start()   # second call — no crash
        bus.stop()

    def test_stop_before_start_is_safe(self):
        bus = EventBus()
        bus.stop()   # should not raise


class TestSubscription:

    def test_subscribe_and_unsubscribe(self):
        bus = EventBus()
        handler = lambda e: None
        bus.subscribe(handler)
        assert bus.handler_count == 1
        bus.unsubscribe(handler)
        assert bus.handler_count == 0

    def test_subscribe_same_handler_twice_is_idempotent(self):
        bus = EventBus()
        handler = lambda e: None
        bus.subscribe(handler)
        bus.subscribe(handler)   # duplicate
        assert bus.handler_count == 1
        bus.stop()

    def test_unsubscribe_unknown_handler_does_not_raise(self):
        bus = EventBus()
        bus.unsubscribe(lambda e: None)   # never registered — no crash

    def test_multiple_handlers(self):
        bus = EventBus()
        received_a, received_b = [], []
        bus.subscribe(lambda e: received_a.append(e))
        bus.subscribe(lambda e: received_b.append(e))
        assert bus.handler_count == 2
        bus.start()
        bus.publish(_make_event())
        assert _wait_for(lambda: len(received_a) == 1)
        assert _wait_for(lambda: len(received_b) == 1)
        bus.stop()


class TestPublishAndDispatch:

    def test_published_event_reaches_handler(self):
        received = []
        bus = EventBus()
        bus.subscribe(received.append)
        bus.start()
        event = _make_event()
        bus.publish(event)
        assert _wait_for(lambda: len(received) == 1)
        assert received[0]["source"] == "test_monitor"
        bus.stop()

    def test_multiple_events_dispatched_in_order(self):
        received = []
        bus = EventBus()
        bus.subscribe(received.append)
        bus.start()
        for i in range(5):
            bus.publish({"seq": i, "source": f"mon_{i}", "threat_level": "LOW"})
        assert _wait_for(lambda: len(received) == 5)
        assert [e["seq"] for e in received] == [0, 1, 2, 3, 4]
        bus.stop()

    def test_publish_stamps_bus_enqueued_at(self):
        received = []
        bus = EventBus()
        bus.subscribe(received.append)
        bus.start()
        bus.publish({"source": "test", "threat_level": "LOW"})
        assert _wait_for(lambda: len(received) == 1)
        assert "bus_enqueued_at" in received[0]
        bus.stop()

    def test_publish_does_not_overwrite_existing_timestamp(self):
        received = []
        bus = EventBus()
        bus.subscribe(received.append)
        bus.start()
        event = {"source": "test", "threat_level": "LOW", "bus_enqueued_at": "PRESERVED"}
        bus.publish(event)
        assert _wait_for(lambda: len(received) == 1)
        assert received[0]["bus_enqueued_at"] == "PRESERVED"
        bus.stop()

    def test_publish_non_dict_returns_false(self):
        bus = EventBus()
        assert bus.publish("not a dict") is False
        assert bus.publish(42) is False
        assert bus.publish(None) is False

    def test_publish_returns_false_on_full_queue(self):
        bus = EventBus(maxsize=1)
        # Don't start the dispatcher so the queue fills immediately
        bus.publish({"source": "a", "threat_level": "LOW"})   # fills the 1-slot queue
        result = bus.publish({"source": "b", "threat_level": "LOW"})
        assert result is False
        stats = bus.stats()
        assert stats["dropped"] >= 1
        bus.stop()

    def test_publish_from_multiple_threads(self):
        """Events published concurrently from multiple threads all arrive."""
        received = []
        lock = threading.Lock()
        bus = EventBus()

        def safe_append(e):
            with lock:
                received.append(e)

        bus.subscribe(safe_append)
        bus.start()

        threads = [
            threading.Thread(
                target=bus.publish,
                args=({"source": f"t{i}", "threat_level": "LOW"},)
            )
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert _wait_for(lambda: len(received) == 20, timeout=3.0)
        bus.stop()


class TestFaultIsolation:

    def test_crashing_handler_does_not_kill_dispatcher(self):
        """A handler that raises must not stop other handlers from receiving events."""
        received = []
        bus = EventBus()

        def bad_handler(e):
            raise RuntimeError("intentional crash")

        bus.subscribe(bad_handler)
        bus.subscribe(received.append)
        bus.start()

        bus.publish(_make_event())
        assert _wait_for(lambda: len(received) == 1)
        assert bus.stats()["errors"] >= 1
        bus.stop()


class TestStats:

    def test_stats_track_published_and_dispatched(self):
        received = []
        bus = EventBus()
        bus.subscribe(received.append)
        bus.start()
        bus.publish(_make_event())
        assert _wait_for(lambda: len(received) == 1)
        stats = bus.stats()
        assert stats["published"] >= 1
        assert stats["dispatched"] >= 1
        bus.stop()

    def test_queue_size_decreases_after_dispatch(self):
        bus = EventBus()
        bus.start()
        for _ in range(3):
            bus.publish(_make_event())
        assert _wait_for(lambda: bus.queue_size() == 0, timeout=2.0)
        bus.stop()
