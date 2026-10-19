"""v0.47.3: DHCP watch probes from every local address and never stays blind silently.
10-14: enabled for hours, learned nothing, said nothing — the probe left from
192.168.1.x while the Windows DHCP scope is 192.168.100/23."""
import json
import socket
import unittest

from harness import cleanup, load_monitor, stub_telegram


class _Stop(BaseException):
    pass


class DhcpWatchTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.CONFIG["dhcp_watch"] = {"enabled": True, "interval_minutes": 30, "expected": []}

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_local_addresses_skip_tailscale_and_loopback(self):
        m = self.m
        fake = [(socket.AF_INET, 0, 0, "", (ip, 0)) for ip in
                ("192.168.1.30", "192.168.100.30", "100.64.0.10", "127.0.0.1", "169.254.1.1",
                 "192.168.100.30")]
        real = m.socket.getaddrinfo
        m.socket.getaddrinfo = lambda *a, **k: fake
        m.local_ip = lambda: "192.168.1.30"
        try:
            self.assertEqual(m.local_ipv4s(), ["192.168.1.30", "192.168.100.30"])
        finally:
            m.socket.getaddrinfo = real

    def test_probe_tries_every_address(self):
        m = self.m
        m.local_ipv4s = lambda: ["192.168.1.30", "192.168.100.30", "192.168.101.30"]
        tried = []

        def probe_from(me, wait):
            tried.append(me)
            return ({"192.168.100.4": "192.168.100.77"} if me == "192.168.100.30" else {}), None
        m._dhcp_probe_from = probe_from
        found, err = m.dhcp_probe()
        self.assertEqual(tried, ["192.168.1.30", "192.168.100.30", "192.168.101.30"])
        self.assertEqual((found, err), ({"192.168.100.4": "192.168.100.77"}, None))
        self.assertEqual(m.DHCP_LAST["found"], found)

    def run_rounds(self, n, found):
        m = self.m
        m.dhcp_probe = lambda: (found, None) if not m.DHCP_LAST.update(tried=["192.168.1.30"]) else None
        clock = [1_790_000_000.0]   # real epoch: the first probe runs at once
        real_time, real_sleep = m.time.time, m.time.sleep
        m.time.time = lambda: clock[0]
        sleeps = []

        def sleep(sec):
            sleeps.append(sec)
            clock[0] += 1800
            if len(sleeps) >= n:
                raise _Stop()
        m.time.sleep = sleep
        try:
            with self.assertRaises(_Stop):
                m.dhcp_watch_loop()
        finally:
            m.time.time, m.time.sleep = real_time, real_sleep

    def test_blind_watch_says_so_once(self):
        self.run_rounds(5, {})
        blind = [t for t in self.texts() if "не слышит ответов" in t]
        self.assertEqual(len(blind), 1, "after the 3rd silent probe, once")

    def test_dead_known_server_is_reported(self):
        self.m.CONFIG["dhcp_watch"]["expected"] = ["192.168.100.4"]
        self.run_rounds(4, {})
        self.assertEqual(len([t for t in self.texts() if "не отвечает 3 пробы" in t]), 1,
                         "was silent: the 'missing' check needed some other answer")

    def test_learning_still_works(self):
        self.run_rounds(1, {"192.168.100.4": "192.168.100.77"})
        self.assertEqual(self.m.CONFIG["dhcp_watch"]["expected"], ["192.168.100.4"])
        self.assertIn("запомнил штатные серверы", self.texts()[0])


if __name__ == "__main__":
    unittest.main()
