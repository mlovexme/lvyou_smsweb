import time
from threading import Lock
from typing import Any, Dict, List, Optional

from .config import SCAN_TTL


class ScanState:
    def __init__(self):
        self.status    = "pending"
        self.progress  = ""
        self.results: List[Dict[str, Any]] = []
        self.found     = 0
        self.scanned   = 0
        self.total_ips = 0
        self.cidr      = ""
        self.finished_at: float = 0.0
        self._lock     = Lock()

    def set_status(self, status: str, progress: Optional[str] = None) -> None:
        with self._lock:
            self.status = status
            if progress is not None:
                self.progress = progress

    def set_progress(self, progress: str) -> None:
        with self._lock:
            self.progress = progress

    def set_counts(self, *, scanned: Optional[int] = None, found: Optional[int] = None, total_ips: Optional[int] = None) -> None:
        with self._lock:
            if scanned is not None:
                self.scanned = scanned
            if found is not None:
                self.found = found
            if total_ips is not None:
                self.total_ips = total_ips

    def set_results(self, results: List[Dict[str, Any]]) -> None:
        with self._lock:
            self.results = results
            self.found = len(results)

    def set_cidr(self, cidr: str) -> None:
        with self._lock:
            self.cidr = cidr

    def mark_done(self) -> None:
        with self._lock:
            self.finished_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status":    self.status,
                "progress":  self.progress,
                "found":     self.found,
                "scanned":   self.scanned,
                "total_ips": self.total_ips,
                "cidr":      self.cidr,
                "devices":   [{"ip": r["ip"], "devId": r.get("devId", "")} for r in self.results],
            }


active_scans: Dict[str, ScanState] = {}
active_scans_lock = Lock()


def cleanup_old_scans() -> None:
    now = time.time()
    with active_scans_lock:
        expired = [sid for sid, st in active_scans.items()
                   if st.finished_at > 0 and now - st.finished_at > SCAN_TTL]
        for sid in expired:
            active_scans.pop(sid, None)
