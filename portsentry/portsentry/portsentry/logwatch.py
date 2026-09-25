"""Follow a firewall log (iptables / ufw / nftables style) for dropped packets.

The tripwire listener only sees completed TCP handshakes. Stealth SYN scans
never complete one, but a firewall that logs dropped packets still records
them, so tailing that log covers the gap.
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Callable, Optional, Tuple

HitCallback = Callable[[float, str, int], None]

_LINE = re.compile(
    r"SRC=(?P<src>[0-9A-Fa-f:.]+)\s.*?PROTO=(?P<proto>TCP|UDP)\s.*?DPT=(?P<dpt>\d+)"
)


def parse_line(line: str) -> Optional[Tuple[str, int]]:
    """Extract (src_ip, dst_port) from a kernel firewall log line, else None."""
    m = _LINE.search(line)
    if not m:
        return None
    port = int(m.group("dpt"))
    if not 0 < port < 65536:
        return None
    return m.group("src"), port


def follow(path: str, on_hit: HitCallback, stop: threading.Event, tick: float = 0.5) -> None:
    """Tail `path` from its current end, surviving log rotation."""
    f = open(path, "r", encoding="utf-8", errors="replace")
    try:
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        while not stop.is_set():
            line = f.readline()
            if line:
                parsed = parse_line(line)
                if parsed:
                    on_hit(time.time(), parsed[0], parsed[1])
                continue
            try:  # no new data: check whether the file was rotated or truncated
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = open(path, "r", encoding="utf-8", errors="replace")
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
            stop.wait(tick)
    finally:
        f.close()
