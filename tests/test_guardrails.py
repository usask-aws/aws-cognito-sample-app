from app.guardrails import DailyTokenBrake, RateLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_rate_limiter_allows_up_to_max_then_blocks():
    clock = FakeClock()
    rl = RateLimiter(max_requests=2, window_seconds=60, clock=clock)
    assert rl.allow("sid-1") is True
    assert rl.allow("sid-1") is True
    assert rl.allow("sid-1") is False  # 3rd within window


def test_rate_limiter_window_resets():
    clock = FakeClock()
    rl = RateLimiter(max_requests=2, window_seconds=60, clock=clock)
    rl.allow("sid-1")
    rl.allow("sid-1")
    clock.t = 61
    assert rl.allow("sid-1") is True


def test_rate_limiter_is_per_key():
    rl = RateLimiter(max_requests=2, window_seconds=60, clock=FakeClock())
    assert rl.allow("a") is True
    assert rl.allow("b") is True
    assert rl.allow("a") is True


def test_token_brake_trips_at_cap():
    brake = DailyTokenBrake(cap=100)
    assert brake.exceeded() is False
    brake.record(60)
    assert brake.exceeded() is False
    brake.record(40)
    assert brake.exceeded() is True


def test_token_brake_resets_on_new_day():
    days = ["2026-07-15", "2026-07-15", "2026-07-16"]
    brake = DailyTokenBrake(cap=100, today=lambda: days.pop(0))
    brake.record(100)          # uses day[0]
    assert brake.exceeded()    # uses day[1] -> still 2026-07-15, tripped
    assert brake.exceeded() is False  # uses day[2] -> new day, reset
