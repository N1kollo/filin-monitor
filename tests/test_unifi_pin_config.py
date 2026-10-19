"""v0.44.1: UniFi certificate pinning (TOFU), config.json.bak."""
import json
import os
import ssl
import unittest

from harness import cleanup, load_monitor, stub_telegram


class FakeClient:
    """Stands in for UnifiClient: login 'connects' with the given cert."""
    cert = b"controller-cert-A"
    logins = []

    def __init__(self, base, site, pin=None):
        self.pin = MON.UnifiPin(pin)

    def login(self, user, pwd):
        self.pin.check(FakeClient.cert)          # raises before credentials leave
        FakeClient.logins.append(user)

    def stat(self, tail):
        return []


class UnifiPinTest(unittest.TestCase):
    def setUp(self):
        global MON
        self.m, self.tmp = load_monitor()
        MON = self.m
        self.calls = stub_telegram(self.m)
        self.m.UnifiClient = FakeClient
        self.m.unifi_creds = lambda: ("viewer", "secret")
        self.m.CONFIG["unifi"] = {"enabled": True, "url": "https://10.0.0.5:8443"}
        FakeClient.cert, FakeClient.logins = b"controller-cert-A", []

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def sends(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_pin_check(self):
        p = self.m.UnifiPin(None)
        p.check(b"x")
        self.assertEqual(len(p.seen), 64)
        p2 = self.m.UnifiPin(p.seen.upper())
        p2.check(b"x")                            # case-insensitive, no raise
        with self.assertRaises(ssl.SSLError):
            p2.check(b"y")
        self.assertTrue(p2.mismatch)

    def test_first_use_pins_then_mismatch_blocks_login(self):
        m = self.m
        m.unifi_evaluate()
        pin = m.CONFIG["unifi"]["cert_sha256"]
        self.assertEqual(FakeClient.logins, ["viewer"])
        with open(m.CONFIG_PATH, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["unifi"]["cert_sha256"], pin, "pin persisted")

        FakeClient.cert = b"mitm-cert"
        m.unifi_evaluate()
        self.assertEqual(FakeClient.logins, ["viewer"], "no login with a foreign cert")
        self.assertFalse(m._UNIFI["ok"])
        self.assertIn("логин не отправлен", m._UNIFI["error"])
        self.assertEqual(m.CONFIG["unifi"]["cert_sha256"], pin, "pin not overwritten")
        alerts = [t for t in self.sends() if "Сертификат контроллера" in t]
        self.assertEqual(len(alerts), 1)
        self.assertNotIn("reply_markup", [c for c in self.calls if c[0] == "sendMessage"][-1][1],
                         "security alert has no 'mute such' button")
        m.unifi_evaluate()
        self.assertEqual(len([t for t in self.sends() if "Сертификат" in t]), 1, "alerted once")

        m.CONFIG["unifi"].pop("cert_sha256")       # what «Сбросить отпечаток» does
        m.unifi_evaluate()
        self.assertEqual(FakeClient.logins, ["viewer", "viewer"])
        self.assertNotEqual(m.CONFIG["unifi"]["cert_sha256"], pin, "re-pinned to the new cert")

    def test_connection_closes_on_mismatch(self):
        m = self.m
        pin = m.UnifiPin("00" * 32)

        class Sock:
            closed = False
            def getpeercert(self, binary_form=False):
                return b"other"
            def close(self):
                Sock.closed = True
        conn = m._PinnedHTTPSConnection("10.0.0.5", 8443, pin=pin)
        orig = m.http.client.HTTPSConnection.connect
        m.http.client.HTTPSConnection.connect = lambda self: setattr(self, "sock", Sock())
        try:
            with self.assertRaises(ssl.SSLError):
                conn.connect()
        finally:
            m.http.client.HTTPSConnection.connect = orig
        self.assertTrue(Sock.closed)

    def test_view_exposes_alert_rogue(self):
        self.m.CONFIG["unifi"]["alert_rogue"] = True
        self.assertTrue(self.m.unifi_view()["config"]["alert_rogue"],
                        "the checkbox used to load unchecked and saving turned it off")


class ConfigBackupTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_bak_holds_previous_version(self):
        m = self.m
        m.CONFIG["app_name"] = "first"
        m.save_config()
        m.CONFIG["app_name"] = "second"
        m.save_config()
        with open(m.CONFIG_PATH + ".bak", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["app_name"], "first")
        with open(m.CONFIG_PATH, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["app_name"], "second")
        self.assertFalse(os.path.exists(m.CONFIG_PATH + ".tmp"))


MON = None

if __name__ == "__main__":
    unittest.main()
