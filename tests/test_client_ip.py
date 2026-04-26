# FIX(P2#9): _client_ip honours XFF only when BMTRUSTEDPROXYHOPS >= 1.
# A regression here would make the login rate limiter trivially
# bypassable behind any L7 proxy.


class _FakeRequest:
    def __init__(self, xff: str = "", remote_addr: str = "5.6.7.8"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = type("C", (), {"host": remote_addr})()


def test_client_ip_ignores_xff_without_trust(backend, monkeypatch):
    monkeypatch.setattr(backend, "TRUSTED_PROXY_HOPS", 0)
    req = _FakeRequest(xff="9.9.9.9, 1.2.3.4", remote_addr="5.6.7.8")
    assert backend._client_ip(req) == "5.6.7.8"


def test_client_ip_uses_xff_with_one_trusted_hop(backend, monkeypatch):
    # With one trusted proxy hop the helper reaches into XFF and picks
    # parts[len-1] (the right-most), i.e. the entry the trusted proxy
    # appended for our request.
    monkeypatch.setattr(backend, "TRUSTED_PROXY_HOPS", 1)
    req = _FakeRequest(xff="1.2.3.4, 9.9.9.9", remote_addr="5.6.7.8")
    assert backend._client_ip(req) == "9.9.9.9"
    # Empty XFF falls back to the socket peer.
    req_empty = _FakeRequest(xff="", remote_addr="5.6.7.8")
    assert backend._client_ip(req_empty) == "5.6.7.8"


def test_client_ip_handles_missing_client(backend, monkeypatch):
    monkeypatch.setattr(backend, "TRUSTED_PROXY_HOPS", 0)
    # Some test requests may have client=None.
    req = type("R", (), {"headers": {}, "client": None})()
    # Should not raise; fall back to a sentinel like "" or "0.0.0.0".
    assert isinstance(backend._client_ip(req), str)
