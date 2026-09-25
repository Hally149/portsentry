import unittest

from portsentry.detector import ScanDetector, normalize_ip
from portsentry.logwatch import parse_line


class DetectorTests(unittest.TestCase):
    def make(self, **kw):
        return ScanDetector(threshold=3, window=10, cooldown=60, **kw)

    def test_below_threshold_no_alert(self):
        d = self.make()
        self.assertIsNone(d.observe(0, "203.0.113.9", 1000))
        self.assertIsNone(d.observe(1, "203.0.113.9", 1001))

    def test_threshold_alerts_once(self):
        d = self.make()
        alerts = [d.observe(i, "203.0.113.9", 1000 + i) for i in range(4)]
        self.assertIsNone(alerts[0])
        self.assertIsNone(alerts[1])
        self.assertEqual(alerts[2].level, 1)
        self.assertEqual(alerts[2].ports, (1000, 1001, 1002))
        self.assertIsNone(alerts[3])  # still level 1, no repeat

    def test_same_port_repeatedly_is_not_a_scan(self):
        d = self.make()
        for i in range(20):
            self.assertIsNone(d.observe(i * 0.1, "203.0.113.9", 2121))

    def test_hits_outside_window_do_not_count(self):
        d = self.make()
        d.observe(0, "203.0.113.9", 1)
        d.observe(1, "203.0.113.9", 2)
        self.assertIsNone(d.observe(20, "203.0.113.9", 3))  # first two expired

    def test_escalates_to_aggressive(self):
        d = self.make()
        levels = [getattr(d.observe(i * 0.1, "203.0.113.9", 100 + i), "level", None) for i in range(9)]
        self.assertEqual([x for x in levels if x], [1, 2])

    def test_alerts_again_after_cooldown(self):
        d = self.make()
        for i in range(3):
            d.observe(i, "203.0.113.9", 10 + i)
        alert = None
        for i in range(3):
            alert = d.observe(200 + i, "203.0.113.9", 10 + i) or alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert.level, 1)

    def test_sources_are_independent(self):
        d = self.make()
        d.observe(0, "203.0.113.9", 1)
        d.observe(0, "198.51.100.7", 2)
        self.assertIsNone(d.observe(0, "203.0.113.9", 3))

    def test_allowlist(self):
        d = self.make(allowlist=["10.0.0.0/8", "192.168.1.5"])
        for i in range(10):
            self.assertIsNone(d.observe(i * 0.1, "10.2.3.4", 100 + i))
            self.assertIsNone(d.observe(i * 0.1, "192.168.1.5", 100 + i))

    def test_ipv4_mapped_ipv6_is_normalized(self):
        self.assertEqual(normalize_ip("::ffff:203.0.113.9"), "203.0.113.9")
        d = self.make()
        d.observe(0, "::ffff:203.0.113.9", 1)
        d.observe(1, "203.0.113.9", 2)
        self.assertIsNotNone(d.observe(2, "::ffff:203.0.113.9", 3))

    def test_gc_drops_quiet_sources(self):
        d = self.make()
        d.observe(0, "203.0.113.9", 1)
        self.assertEqual(d.tracked_sources(), 1)
        d.gc(100)
        self.assertEqual(d.tracked_sources(), 0)

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            ScanDetector(threshold=0)
        with self.assertRaises(ValueError):
            ScanDetector(window=0)


class LogParseTests(unittest.TestCase):
    def test_ufw_line(self):
        line = ("Sep 24 10:00:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.9 "
                "DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=1 PROTO=TCP SPT=44444 DPT=22 "
                "WINDOW=1024 RES=0x00 SYN URGP=0")
        self.assertEqual(parse_line(line), ("203.0.113.9", 22))

    def test_ipv6_line(self):
        line = "kernel: IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 LEN=60 PROTO=TCP SPT=1 DPT=443 WINDOW=1"
        self.assertEqual(parse_line(line), ("2001:db8::1", 443))

    def test_non_matching_lines(self):
        self.assertIsNone(parse_line("Sep 24 sshd[1]: Accepted publickey for user"))
        self.assertIsNone(parse_line("kernel: SRC=1.2.3.4 DST=5.6.7.8 PROTO=ICMP TYPE=8"))


if __name__ == "__main__":
    unittest.main()
