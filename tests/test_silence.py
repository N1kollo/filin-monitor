"""v0.50: «why is this host silent», the silence strip, host management API,
and 0.0.0.0 is not a new device."""
import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from harness import cleanup, load_monitor, stub_telegram


class AudibilityTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["hosts"] = [
            {"id": "s23", "name": "S23", "host": "10.10.1.23", "type": "host"},
            {"id": "1c", "name": "1С Торговля", "host": "10.10.1.20", "type": "host", "parent": "s23",
             "priority": "critical"},
            {"id": "pc", "name": "PC", "host": "10.10.1.50", "type": "host"},
        ]
        m.CONFIG["quiet"] = {"enabled": False, "from": "22:00", "to": "08:00"}
        m.reconcile_state()
        with m.STATE_LOCK:
            for k in m.STATE:
                m.STATE[k]["status"] = "up"
        self.h = {h["id"]: h for h in m.CONFIG["hosts"]}

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def why(self, hid):
        return self.m.alert_audibility(self.h[hid])

    def test_rings_by_default(self):
        a = self.why("pc")
        self.assertEqual((a["rings"], a["why"]), (True, []))
        self.assertIn("дольше 90 с", a["notes"][0], "hold-down explained, not a blocker")
        self.assertEqual(self.why("1c")["notes"], [], "critical skips the hold-down")

    def test_each_reason(self):
        m = self.m
        m.set_mute("muted_hosts", "pc", 3600)
        self.assertIn("заглушён до", self.why("pc")["why"][0])
        m.set_mute("muted_hosts", "pc", None)
        m.set_maint("*", 1800)
        self.assertIn("(вся сеть)", self.why("pc")["why"][0])
        m.set_maint("*", None)
        m.CONFIG["maintenance"] = [{"name": "регламент", "from": "00:00", "to": "23:59", "days": [],
                                    "hosts": ["pc"], "enabled": True}]
        self.assertIn("окно обслуживания «регламент»", self.why("pc")["why"][0])
        m.CONFIG["maintenance"] = []
        with m.STATE_LOCK:
            m.STATE["s23"]["status"] = "down"
        self.assertIn("родитель «S23» лежит", self.why("1c")["why"][0])
        with m.STATE_LOCK:
            m.STATE["s23"]["status"] = "up"
        m.CONFIG["quiet"].update(enabled=True, **{"from": "00:00", "to": "23:59"})
        self.assertIn("тихие часы", self.why("pc")["why"][0])
        self.assertTrue(self.why("1c")["rings"], "critical rings through quiet hours")
        self.h["pc"]["priority"] = "watch"
        self.assertTrue(any("только журнал" in w for w in self.why("pc")["why"]))

    def test_silence_strip(self):
        m = self.m
        self.assertEqual(m.silence_view()["muted_hosts"], [])
        m.set_mute("muted_hosts", "pc", 3600)
        m.set_mute("muted_kinds", "wifi", 0)
        m.set_maint("*", 1800)
        m.CONFIG.setdefault("unifi", {})["ap_quiet"] = {"from": "18:55", "to": "07:55"}
        m.outbox_put({"chat_id": "42", "text": "x"}, "down", "502")
        v = m.silence_view()
        self.assertEqual([x["name"] for x in v["muted_hosts"]], ["PC"])
        self.assertEqual([(x["kind"], x["until"]) for x in v["muted_kinds"]], [("wifi", 0)])
        self.assertEqual(v["maint"][0]["name"], "вся сеть")
        self.assertEqual(v["ap_quiet"]["from"], "18:55")
        self.assertEqual(v["outbox"], 1)


class HostApiTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [{"id": "pc", "name": "PC", "host": "10.10.1.50", "type": "host"}]
        m.reconcile_state()
        self.srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_mute_maint_kind_roundtrip(self):
        m = self.m
        self.assertEqual(self.call("/api/hosts/mute", {"id": "pc", "seconds": 3600})[0], 200)
        self.assertTrue(m.is_muted("pc"))
        self.assertEqual(self.call("/api/hosts/maint", {"id": "*", "seconds": 1800})[0], 200)
        self.assertTrue(m.maint_until("*"))
        self.assertEqual(self.call("/api/alerts/kind", {"kind": "wifi", "seconds": 0})[0], 200)
        self.assertTrue(m.kind_muted("wifi"))
        _, v = self.call("/api/silence")
        self.assertEqual(len(v["muted_hosts"]) + len(v["maint"]) + len(v["muted_kinds"]), 3)
        for path, body in (("/api/hosts/mute", {"id": "pc", "seconds": None}),
                           ("/api/hosts/maint", {"id": "*", "seconds": None}),
                           ("/api/alerts/kind", {"kind": "wifi", "seconds": None})):
            self.assertEqual(self.call(path, body)[0], 200)
        self.assertFalse(m.is_muted("pc") or m.maint_until("*") or m.kind_muted("wifi"))

    def test_bad_input(self):
        self.assertEqual(self.call("/api/alerts/kind", {"kind": "down", "seconds": 60})[0], 400,
                         "host downs are not kind-mutable — not from the dashboard either")
        self.assertEqual(self.call("/api/hosts/mute", {"seconds": 60})[0], 400)

    def test_detail_carries_audibility(self):
        _, d = self.call("/api/host?id=pc&hours=1")
        self.assertTrue(d["audible"]["rings"])
        self.assertEqual((d["priority"], d["parent"], d["muted"], d["maint"]), ("normal", "", False, False))


class PassiveZeroTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.arp_table = lambda: {}

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_not_a_device(self):
        d = self.m.is_device_ip
        for ip in ("0.0.0.0", "127.0.0.1", "169.254.3.4", "224.0.0.251", "255.255.255.255", "x", "::1"):
            self.assertFalse(d(ip), ip)
        self.assertTrue(d("192.168.100.137"))

    def test_zero_address_not_announced(self):
        """10-14 16:41 «Новое устройство в эфире: 0.0.0.0 — 34c9b92f-…»"""
        self.m._passive_note("0.0.0.0", "34c9b92f-d51a-4fc5", "", "mDNS")
        self.assertEqual([c for c in self.calls if c[0] == "sendMessage"], [])
        self.m._passive_note("10.10.1.77", "printer", "", "mDNS")
        self.assertEqual(len([c for c in self.calls if c[0] == "sendMessage"]), 1, "real devices still announced")


if __name__ == "__main__":
    unittest.main()
