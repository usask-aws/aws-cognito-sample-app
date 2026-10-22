import time
from datetime import date
from threading import Lock


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float, clock=time.monotonic):
        self._max = max_requests
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if now - t < self._window]
            if len(recent) >= self._max:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            return True


class DailyTokenBrake:
    def __init__(self, cap: int, today=date.today):
        self._cap = cap
        self._today = today
        self._date = None
        self._used = 0
        self._lock = Lock()

    def _roll_if_new_day(self) -> None:
        current = self._today()
        if self._date is None or current != self._date:
            self._date = current
            self._used = 0

    def exceeded(self) -> bool:
        with self._lock:
            self._roll_if_new_day()
            return self._used >= self._cap

    def record(self, tokens: int) -> None:
        with self._lock:
            self._roll_if_new_day()
            self._used += tokens
