# FIX(P2#9): RateLimiter is a pure helper used by login / SMS / dial /
# OTA. A regression here directly weakens the brute-force defence, so
# the unit tests cover the windowed-allow contract.
import time



def test_rate_limiter_allows_up_to_max(backend):
    limiter = backend.RateLimiter(max_calls=3, period=10)
    assert limiter.allow("k") is True
    assert limiter.allow("k") is True
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    assert limiter.allow("k") is False


def test_rate_limiter_keys_are_independent(backend):
    limiter = backend.RateLimiter(max_calls=2, period=10)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    # different key still allowed
    assert limiter.allow("b") is True
    assert limiter.allow("b") is True


def test_rate_limiter_window_expires(backend):
    limiter = backend.RateLimiter(max_calls=1, period=0.2)
    assert limiter.allow("k") is True
    assert limiter.allow("k") is False
    time.sleep(0.25)
    assert limiter.allow("k") is True


def test_rate_limiter_remaining(backend):
    limiter = backend.RateLimiter(max_calls=3, period=10)
    assert limiter.remaining("k") == 3
    limiter.allow("k")
    assert limiter.remaining("k") == 2
    limiter.allow("k")
    limiter.allow("k")
    assert limiter.remaining("k") == 0
