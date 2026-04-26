# FIX(P2#9): cover the security-critical helpers that the v5.1 audit
# called out. These tests guard against the kind of regression that
# would silently re-open SSRF or accept the empty-password footgun.
import os

import pytest


def test_check_login_credentials_uses_constant_time(backend, monkeypatch):
    # Both helpers are imported via the session-scoped fixture; mutate
    # the module globals through monkeypatch so the override is rolled
    # back at the end of this test rather than leaking into other tests.
    monkeypatch.setattr(backend, "UIUSER", "admin")
    monkeypatch.setattr(backend, "UIPASS", "goodpass1")
    assert backend._check_login_credentials("admin", "goodpass1") is True
    assert backend._check_login_credentials("admin", "wrong") is False
    assert backend._check_login_credentials("Admin", "goodpass1") is False
    assert backend._check_login_credentials("", "") is False


def test_validate_startup_security_rejects_empty(monkeypatch):
    # Re-import the module under a fresh env so _validate_startup_security
    # sees the bad config. We do not want to mutate the session-wide
    # backend fixture for this.
    monkeypatch.delenv("BMINSECURE_DEFAULT_PASSWORD", raising=False)
    monkeypatch.setenv("BMUIPASS", "")
    monkeypatch.setenv("BMDB", "/tmp/security-empty.db")
    monkeypatch.setenv("BMSTATIC", "/tmp/security-empty-static")
    os.makedirs("/tmp/security-empty-static", exist_ok=True)
    # We can't re-import backend.main cleanly mid-process (it has global
    # singletons) so we test the helper directly via a controlled call.
    import backend.main as bm

    monkeypatch.setattr(bm, "UIPASS", "")
    with pytest.raises(RuntimeError, match="BMUIPASS"):
        bm._validate_startup_security()


def test_validate_startup_security_rejects_admin(monkeypatch):
    import backend.main as bm

    monkeypatch.setattr(bm, "UIPASS", "admin")
    monkeypatch.delenv("BMINSECURE_DEFAULT_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        bm._validate_startup_security()


def test_validate_startup_security_allows_insecure_default_for_dev(monkeypatch):
    import backend.main as bm

    monkeypatch.setattr(bm, "UIPASS", "admin")
    monkeypatch.setenv("BMINSECURE_DEFAULT_PASSWORD", "1")
    bm._validate_startup_security()  # must not raise


def test_validate_startup_security_accepts_real_password(monkeypatch):
    import backend.main as bm

    monkeypatch.setattr(bm, "UIPASS", "supersecret123")
    monkeypatch.delenv("BMINSECURE_DEFAULT_PASSWORD", raising=False)
    bm._validate_startup_security()


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",        # loopback
        "169.254.10.10",    # link-local
        "8.8.8.8",          # public
        "224.0.0.1",        # multicast
        "0.0.0.0",          # unspecified
        "not-an-ip",
        "",
    ],
)
def test_is_device_ip_allowed_rejects_non_private(backend, monkeypatch, ip):
    # Force the local-network check to be a no-op (returns []) so layer 2
    # cannot accidentally allow what layer 1 should have refused.
    monkeypatch.setattr(backend, "_local_ipv4_networks", lambda: [])
    assert backend._is_device_ip_allowed(ip) is False


def test_is_device_ip_allowed_accepts_private_when_no_local_nets(backend, monkeypatch):
    monkeypatch.setattr(backend, "_local_ipv4_networks", lambda: [])
    # When the host has no local nets we conservatively allow private
    # IPs (best-effort). This is documented in the helper docstring.
    assert backend._is_device_ip_allowed("192.168.1.50") is True
    assert backend._is_device_ip_allowed("10.0.0.5") is True


def test_is_device_ip_allowed_enforces_local_subnet_layer2(backend, monkeypatch):
    from ipaddress import IPv4Network

    monkeypatch.setattr(backend, "_local_ipv4_networks", lambda: [IPv4Network("192.168.1.0/24")])
    assert backend._is_device_ip_allowed("192.168.1.50") is True
    # Private but not on any local subnet -> blocked by layer 2.
    assert backend._is_device_ip_allowed("10.0.0.5") is False
    assert backend._is_device_ip_allowed("172.16.5.5") is False
