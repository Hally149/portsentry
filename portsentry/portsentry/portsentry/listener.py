"""Tripwire listener: opens decoy TCP ports and reports who connects to them.

Nothing legitimate should ever talk to these ports, so every connection is a
signal. Connections are accepted and closed immediately; no data is read or
sent.
"""
from __future__ import annotations

import os
import selectors
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence

HitCallback = Callable[[float, str, int], None]   # (timestamp, src_ip, dst_port)
TickCallback = Callable[[float], None]


class Listener:
    def __init__(self, ports: Sequence[int], bind: str = "0.0.0.0", backlog: int = 64) -> None:
        self.ports = list(ports)
        self.bind = bind
        self.backlog = backlog
        self.bound: List[int] = []
        self.failed: Dict[int, str] = {}
        self._sel = selectors.DefaultSelector()

    def open(self) -> List[int]:
        """Bind every port we can. Failures are recorded, not fatal."""
        family = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        for port in self.ports:
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                if os.name != "nt":  # on Windows SO_REUSEADDR allows port hijacking
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.bind, port))
                sock.listen(self.backlog)
                sock.setblocking(False)
            except OSError as exc:
                sock.close()
                self.failed[port] = exc.strerror or str(exc)
                continue
            self._sel.register(sock, selectors.EVENT_READ, data=port)
            self.bound.append(port)
        return self.bound

    def run(
        self,
        on_hit: HitCallback,
        on_tick: Optional[TickCallback] = None,
        stop: Optional[threading.Event] = None,
        tick: float = 1.0,
    ) -> None:
        """Block until `stop` is set, calling on_hit per connection and on_tick periodically."""
        stop = stop or threading.Event()
        while not stop.is_set():
            for key, _ in self._sel.select(timeout=tick):
                try:
                    conn, addr = key.fileobj.accept()
                except OSError:  # includes BlockingIOError; connection vanished
                    continue
                conn.close()
                on_hit(time.time(), addr[0], key.data)
            if on_tick:
                on_tick(time.time())

    def close(self) -> None:
        for key in list(self._sel.get_map().values()):
            self._sel.unregister(key.fileobj)
            key.fileobj.close()
        self._sel.close()
