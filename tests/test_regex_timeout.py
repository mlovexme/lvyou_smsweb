# FIX(P2#9): /api/devices/batch/config/{preview,write} runs user-supplied
# regex against the device config blob. Without the timeout patch from
# P1#8 a malicious pattern like (a+)+$ on "aaaa...!" pegs a worker. This
# test asserts that _apply_regex returns None (graceful failure) rather
# than hanging for catastrophic backtracking patterns.
import time

import pytest


def test_apply_regex_returns_none_on_invalid_pattern(backend):
    assert backend._apply_regex("anything", "(", "x", "") is None


def test_apply_regex_substitutes_normal(backend):
    out = backend._apply_regex("hello world", "world", "earth", "")
    assert out == "hello earth"


def test_apply_regex_supports_imsx_flags(backend):
    assert backend._apply_regex("HELLO", "hello", "x", "i") == "x"
    assert backend._apply_regex("a\nb", "^b", "x", "m") == "a\nx"
    assert backend._apply_regex("a\nb", "a.b", "x", "s") == "x"


def test_apply_regex_rejects_unknown_flags(backend):
    assert backend._apply_regex("ab", "a", "x", "z") is None


@pytest.mark.timeout(10)  # if the timeout regression returns we still bail
def test_apply_regex_terminates_on_redos(backend):
    # Classic exponential backtracking pattern. On a fixed library this
    # should return None within ~REGEX_TIMEOUT seconds; on regression it
    # would peg the CPU until pytest-timeout aborts the test.
    pattern = "(a+)+$"
    haystack = "a" * 30 + "!"
    started = time.monotonic()
    result = backend._apply_regex(haystack, pattern, "x", "")
    elapsed = time.monotonic() - started
    # We don't pin the exact result -- depending on the library the
    # timeout helper either returns None or an unmodified string. Both
    # are acceptable; what we care about is that it returned at all.
    assert result is None or isinstance(result, str)
    # The timeout default in main.py is small (1 second). Allow some
    # slack for slow CI runners but fail loudly if it ran > 5 seconds.
    assert elapsed < 5.0, f"_apply_regex took {elapsed:.2f}s, ReDoS guard regressed"
