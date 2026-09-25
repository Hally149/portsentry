"""Command-line interface for portsentry."""
from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
import time
from typing import List, Optional

from . import __version__
from .detector import ScanDetector
from .listener import Listener
from .logwatch import follow
from .sentry import Sentry

DEFAULT_PORTS = "2121,2323,3307,5901,8081,8888,9090,9999"


def parse_ports(spec: str) -> List[int]:
    """Parse '21,23,5900-5905' into a sorted, de-duplicated list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            start, end = int(lo), int(hi or lo)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port spec: {part!r}")
        if not (1 <= start <= end <= 65535):
            raise argparse.ArgumentTypeError(f"port out of range: {part!r}")
        ports.update(range(start, end + 1))
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portsentry",
        description="Detect port scans against this machine using tripwire ports "
                    "and (optionally) firewall logs.",
    )
    p.add_argument("--ports", type=parse_ports, default=parse_ports(DEFAULT_PORTS),
                   help=f"tripwire ports, e.g. 21,23,5900-5905 (default: {DEFAULT_PORTS}). "
                        "Ports below 1024 need root/admin.")
    p.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: 0.0.0.0; use :: for IPv6)")
    p.add_argument("--threshold", type=int, default=3,
                   help="distinct ports within the window that count as a scan (default: 3)")
    p.add_argument("--window", type=float, default=10.0, help="window in seconds (default: 10)")
    p.add_argument("--cooldown", type=float, default=60.0,
                   help="seconds of quiet before the same source can alert again (default: 60)")
    p.add_argument("--allow", action="append", default=[], metavar="CIDR",
                   help="ignore this address or network, e.g. 192.168.1.10 or 10.0.0.0/8 (repeatable)")
    p.add_argument("--log-file", help="append hits and alerts to this file as JSON lines")
    p.add_argument("--tail-log", metavar="FILE",
                   help="also watch a firewall log (iptables/ufw) for dropped packets; catches SYN scans")
    p.add_argument("--no-listen", action="store_true", help="skip tripwire ports; only watch --tail-log")
    p.add_argument("--block-cmd", metavar="CMD",
                   help="command to run when a source hits --block-level; {ip} is replaced. "
                        "Example: 'iptables -A INPUT -s {ip} -j DROP'. Off by default; never runs for loopback.")
    p.add_argument("--block-level", type=int, choices=(1, 2), default=2,
                   help="1 = scan, 2 = aggressive scan (default: 2)")
    p.add_argument("-v", "--verbose", action="store_true", help="print every hit, not just alerts")
    p.add_argument("-q", "--quiet", action="store_true", help="no console output (use with --log-file)")
    p.add_argument("--demo", action="store_true",
                   help="run a self-contained demo: simulate a scan against loopback and show the alert")
    p.add_argument("--version", action="version", version=f"portsentry {__version__}")
    return p


def _free_ports(n: int) -> List[int]:
    socks = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return sorted(s.getsockname()[1] for s in socks)
    finally:
        for s in socks:
            s.close()


def run_demo() -> int:
    """Start a listener on loopback, connect to several of its ports, show the alert."""
    ports = _free_ports(6)
    sentry = Sentry(ScanDetector(threshold=3, window=10, cooldown=60), verbose=True)
    listener = Listener(ports, "127.0.0.1")
    listener.open()
    stop = threading.Event()
    thread = threading.Thread(
        target=listener.run,
        args=(lambda ts, ip, port: sentry.hit(ts, ip, port, "tripwire"), sentry.tick, stop, 0.1),
    )
    thread.start()
    print(f"demo: tripwires on 127.0.0.1 ports {ports}")
    print("demo: simulating a scan from 127.0.0.1 (loopback only)...\n")
    try:
        for port in ports:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            time.sleep(0.05)
        time.sleep(0.4)
    finally:
        stop.set()
        thread.join()
        listener.close()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.demo:
        return run_demo()

    if args.no_listen and not args.tail_log:
        print("portsentry: --no-listen needs --tail-log, otherwise there is nothing to watch", file=sys.stderr)
        return 2
    if args.tail_log and not os.access(args.tail_log, os.R_OK):
        print(f"portsentry: cannot read {args.tail_log} (missing, or need elevated permissions)", file=sys.stderr)
        return 2
    try:
        detector = ScanDetector(args.threshold, args.window, args.cooldown, args.allow)
    except ValueError as exc:
        print(f"portsentry: {exc}", file=sys.stderr)
        return 2

    sentry = Sentry(detector, args.log_file, args.block_cmd, args.block_level, args.verbose, args.quiet)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    listener = None
    if not args.no_listen:
        listener = Listener(args.ports, args.bind)
        bound = listener.open()
        for port, why in listener.failed.items():
            print(f"portsentry: skipped port {port}: {why}", file=sys.stderr)
        if not bound and not args.tail_log:
            print("portsentry: could not bind any tripwire port", file=sys.stderr)
            return 2
        if bound:
            print(f"portsentry: tripwires on {args.bind} ports {bound}")

    threads = []
    if args.tail_log:
        print(f"portsentry: watching firewall log {args.tail_log}")
        t = threading.Thread(
            target=follow,
            args=(args.tail_log, lambda ts, ip, port: sentry.hit(ts, ip, port, "firewall-log"), stop),
            daemon=True,
        )
        t.start()
        threads.append(t)

    print(f"portsentry: alert at {args.threshold}+ distinct ports within {args.window:g}s. Ctrl+C to stop.")
    try:
        if listener and listener.bound:
            listener.run(lambda ts, ip, port: sentry.hit(ts, ip, port, "tripwire"), sentry.tick, stop)
        else:
            while not stop.wait(1.0):
                sentry.tick(time.time())
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2)
        if listener:
            listener.close()
        sentry.close()
    print("portsentry: stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
