"""v0.45.1: DHCP reassignment and privacy MACs are not spoofing or conflicts."""
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram


class MacVerdictTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_mac_is_random(self):
        r = self.m.mac_is_random
        self.assertTrue(r("b6:72:2e:00:d0:76"))       # the 08:25 case
        self.assertTrue(r("DA-A1-19-00-00-01"))
        self.assertFalse(r("e4:c3:2a:00:01:5e"))      # TP-Link, real
        self.assertFalse(r(""))
        self.assertFalse(r(None))

    def test_verdicts(self):
        v = self.m.mac_change_verdict
        alive = {"192.168.100.106": "70:85:c2:aa:bb:cc", "192.168.100.50": "70:85:c2:00:00:01"}
        reassign = {"ip": "192.168.100.106", "old_mac": "a4:c9:39:11:22:33",
                    "mac": "70:85:c2:aa:bb:cc"}
        self.assertEqual(v(reassign, alive, set()), "reassigned", "buh-alina took the phone's IP")
        self.assertEqual(v(reassign, alive, {"192.168.100.106"}), "monitored")
        spoof = dict(reassign, mac="70:85:c2:00:00:01")
        self.assertEqual(v(spoof, alive, set()), "spoof", "same MAC answers for another IP")
        rand = dict(reassign, mac="b6:72:2e:00:d0:76")
        self.assertEqual(v(rand, {"192.168.100.106": rand["mac"]}, set()), "random")


class NetdiffAlertTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.quiet_now = lambda: False
        self.m.CONFIG["hosts"] = [{"id": "s", "name": "1C", "host": "192.168.1.20", "type": "host"}]

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def scan(self, alive):
        app, gone, changed = self.m.network_diff(alive)
        self.m.alert_network_changes(app, changed)

    def test_reassignment_quiet_spoof_loud(self):
        self.scan({"192.168.100.106": "a4:c9:39:11:22:33", "192.168.1.20": "00:15:5d:00:00:01",
                   "192.168.100.50": "70:85:c2:00:00:01"})
        self.calls.clear()
        self.scan({"192.168.100.106": "70:85:c2:aa:bb:cc", "192.168.1.20": "00:15:5d:00:00:01",
                   "192.168.100.50": "70:85:c2:00:00:01"})
        self.assertEqual(self.texts(), [], "DHCP handed the phone's IP to a PC")
        self.scan({"192.168.100.106": "70:85:c2:00:00:01", "192.168.1.20": "00:15:5d:00:00:01",
                   "192.168.100.50": "70:85:c2:00:00:01"})
        self.assertEqual(len(self.texts()), 1)
        self.assertIn("отвечает и за другой адрес", self.texts()[0])
        self.scan({"192.168.100.106": "70:85:c2:00:00:01", "192.168.1.20": "00:15:5d:00:00:99",
                   "192.168.100.50": "70:85:c2:00:00:01"})
        self.assertIn("адрес хоста из мониторинга", self.texts()[-1])


class ConflictRandomTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m._arp_entry_relevant = lambda ip, mac: True

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def flip(self, ip, a, b, n=4):
        for i in range(n):
            self.m.watch_arp_conflicts({ip: a if i % 2 == 0 else b})

    def sent(self):
        return [c for c in self.calls if c[0] == "sendMessage"]

    def test_phone_real_and_privacy_mac_is_not_a_conflict(self):
        self.flip("192.168.100.137", "e8:68:e7:11:22:33", "b6:72:2e:00:d0:76")
        self.assertEqual(self.sent(), [])

    def test_two_real_devices_still_alert(self):
        self.flip("192.168.100.140", "e8:68:e7:11:22:33", "70:85:c2:aa:bb:cc")
        self.assertEqual(len(self.sent()), 1)
        self.assertIn("КОНФЛИКТ IP", self.sent()[0][1]["text"])


if __name__ == "__main__":
    unittest.main()
