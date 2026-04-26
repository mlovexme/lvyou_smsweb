# FIX(P2#9): pytest fixtures for the backend unit tests.
#
# We import backend.main lazily because the module performs side-effecty
# work at import time (engine creation, session factory, scan poller
# bootstrap). Setting BMINSECURE_DEFAULT_PASSWORD + an isolated SQLite
# DB per test directory keeps that import cheap and reproducible.
import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _backend_env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("backend-tests")
    os.environ.setdefault("BMINSECURE_DEFAULT_PASSWORD", "1")
    os.environ.setdefault("BMDB", str(tmp / "test.db"))
    os.environ.setdefault("BMSTATIC", str(tmp / "static"))
    os.environ.setdefault("BMUIPASS", "")  # let validate_startup_security pass via BMINSECURE_DEFAULT_PASSWORD
    os.makedirs(os.environ["BMSTATIC"], exist_ok=True)
    yield


@pytest.fixture(scope="session")
def backend():
    """Imports backend.main once per session and returns the module."""
    import importlib

    return importlib.import_module("backend.main")
