"""Wires the detector to its outputs: console, JSONL log, optional block command."""
from __future__ import annotations

import ipaddress
import json
import shlex
import subprocess
import sys
import threading
import time
from typing import IO, Optional

from .detector import ScanAlert, ScanDetector, normalize_ip


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class Sentry:
    """Thread-safe front door: feed it hits from any source."""

    def __init__(
        self,
        detector: ScanDetector,
        log_file: Optional[str] = None,
        block_cmd: Optional[str] = None,
        block_level: int = 2,
        verbose: bool = False,
        quiet: bool = False,
        out: IO[str] = sys.stdout,
    ) -> None:
        self.detector = detector
        self.block_cmd = block_cmd
        self.block_level = block_level
        self.verbose = verbose
        self.quiet = quiet
        self.out = out
        self._lock = threading.Lock()
        self._log = open(log_file, "a", buffering=1, encoding="utf-8") if log_file else None

    def hit(self, ts: float, src_ip: str, port: int, source: str) -> Optional[ScanAlert]:
        try:
            ip = normalize_ip(src_ip)
        except ValueError:
            return None
        with self._lock:
            alert = self.detector.observe(ts, ip, port)
            self._write({"type": "hit", "time": _stamp(ts), "src": ip, "port": port, "source": source})
            if self.verbose and not self.quiet:
                print(f"[{_stamp(ts)}] hit   {ip} -> port {port} ({source})", file=self.out, flush=True)
            if alert:
                self._alert(alert, source)
            return alert

    def tick(self, now: float) -> None:
        with self._lock:
            self.detector.gc(now)

    def close(self) -> None:
        if self._log:
            self._log.close()

    # -- internals -------------------------------------------------------

    def _alert(self, alert: ScanAlert, source: str) -> None:
        ports = ", ".join(str(p) for p in alert.ports)
        blocked = False
        if self.block_cmd and alert.level >= self.block_level:
            blocked = self._block(alert.src_ip)
        self._write({
            "type": "alert",
            "time": _stamp(alert.last_seen),
            "src": alert.src_ip,
            "level": alert.label,
            "ports": list(alert.ports),
            "source": source,
            "blocked": blocked,
        })
        if not self.quiet:
            tail = "  [blocked]" if blocked else ""
            print(
                f"[{_stamp(alert.last_seen)}] ALERT {alert.label} from {alert.src_ip} "
                f"- {len(alert.ports)} ports: {ports} ({source}){tail}",
                file=self.out,
                flush=True,
            )

    def _block(self, ip: str) -> bool:
        """Run the user-supplied command with {ip} substituted. Never for loopback."""
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return False
        args = [part.replace("{ip}", ip) for part in shlex.split(self.block_cmd or "")]
        if not args:
            return False
        try:
            subprocess.run(args, check=False, timeout=10, capture_output=True)  # no shell
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"portsentry: block command failed: {exc}", file=sys.stderr)
            return False

    def _write(self, record: dict) -> None:
        if self._log:
            self._log.write(json.dumps(record) + "\n")
