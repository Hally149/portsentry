"""Sliding-window port scan detection.

Pure logic with no sockets or I/O, so it can be unit tested with explicit
timestamps. A source is flagged when it touches enough *distinct* ports inside
a time window.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Optional, Tuple

LEVEL_NAMES = {1: "scan", 2: "aggressive scan"}


def normalize_ip(raw: str) -> str:
    """Return a canonical IP string; unwraps IPv4-mapped IPv6 and zone ids."""
    addr = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


@dataclass(frozen=True)
class ScanAlert:
    src_ip: str
    level: int                 # 1 = scan, 2 = aggressive scan
    ports: Tuple[int, ...]     # distinct ports seen inside the window
    first_seen: float
    last_seen: float

    @property
    def label(self) -> str:
        return LEVEL_NAMES[self.level]


class _SourceState:
    __slots__ = ("hits", "level", "last_alert")

    def __init__(self) -> None:
        self.hits: Deque[Tuple[float, int]] = deque()
        self.level = 0
        self.last_alert = 0.0


class ScanDetector:
    """Flags sources that hit `threshold` distinct ports within `window` seconds.

    Alerts escalate once: level 1 at `threshold` distinct ports, level 2 at
    three times that. After `cooldown` seconds without a new alert, a source
    can be alerted on again.
    """

    def __init__(
        self,
        threshold: int = 3,
        window: float = 10.0,
        cooldown: float = 60.0,
        allowlist: Iterable[str] = (),
        aggressive_factor: int = 3,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window <= 0 or cooldown < 0:
            raise ValueError("window must be > 0 and cooldown >= 0")
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.aggressive_threshold = max(threshold * aggressive_factor, threshold + 1)
        self._allow = [ipaddress.ip_network(n, strict=False) for n in allowlist]
        self._state: Dict[str, _SourceState] = {}

    def is_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._allow if net.version == addr.version)

    def observe(self, ts: float, src_ip: str, port: int) -> Optional[ScanAlert]:
        """Record one connection attempt; return an alert if a new level is reached."""
        ip = normalize_ip(src_ip)
        if self.is_allowed(ip):
            return None

        st = self._state.setdefault(ip, _SourceState())
        if st.level and ts - st.last_alert > self.cooldown:
            st.level = 0
        st.hits.append((ts, port))
        self._prune(st, ts)

        ports = tuple(sorted({p for _, p in st.hits}))
        if len(ports) >= self.aggressive_threshold:
            new_level = 2
        elif len(ports) >= self.threshold:
            new_level = 1
        else:
            new_level = 0

        if new_level > st.level:
            st.level = new_level
            st.last_alert = ts
            return ScanAlert(ip, new_level, ports, st.hits[0][0], ts)
        return None

    def gc(self, now: float) -> None:
        """Forget sources that have gone quiet, so memory stays bounded."""
        for ip in list(self._state):
            st = self._state[ip]
            self._prune(st, now)
            if not st.hits and (st.level == 0 or now - st.last_alert > self.cooldown):
                del self._state[ip]

    def tracked_sources(self) -> int:
        return len(self._state)

    def _prune(self, st: _SourceState, now: float) -> None:
        cutoff = now - self.window
        while st.hits and st.hits[0][0] < cutoff:
            st.hits.popleft()
