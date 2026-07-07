import threading

_live_events: list = []
_live_lock = threading.Lock()