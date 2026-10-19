"""v0.53: Dahua NVR read-only probe. The two rules that protect the office:
one authenticated attempt (Dahua locks after ~5), and camera passwords never leave."""
import io
import json
import os
import unittest
import urllib.error

from harness import cleanup, load_monitor

REMOTE = """table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_0.Address=192.168.2.57
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_0.Enable=true
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_0.Password=CamSecret1
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_0.UserName=admin
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_1.Address=192.168.2.58
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_1.Enable=true
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_1.Password=CamSecret2
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_2.Address=192.168.0.0
table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_2.Enable=false
"""
TITLES = "table.ChannelTitle[0].Name=Вход\ntable.ChannelTitle[1].Name=Склад\n"
STATE = ("states[0].channel=0\nstates[0].connectionState=Connected\n"
         "states[1].channel=1\nstates[1].connectionState=Disconnected\n")
DISKS = ("list.info[0].Name=/dev/sda\nlist.info[0].State=Success\n"
         "list.info[0].Detail[0].TotalBytes=4000000000000.000000\n"
         "list.info[0].Detail[0].UsedBytes=3900000000000.000000\nlist.info[0].Detail[0].IsError=false\n")
BODY = {"getDeviceType": "type=DHI-NVR4216-16P-4KS2\n", "RemoteDevice": REMOTE, "ChannelTitle": TITLES,
        "getCameraState": STATE, "getDeviceAllInfo": DISKS}
WWW = 'Digest realm="Login to 4L01B2EPAZ00000", qop="auth", nonce="1234567890", opaque="abcdef"'


class FakeNVR:
    """urlopen stand-in: 401+challenge without auth; 200 or 401 with it."""
    def __init__(self, good_password="right"):
        self.good, self.calls = good_password, []

    def __call__(self, req, timeout=None):
        auth = req.headers.get("Authorization", "")
        self.calls.append((req.full_url, bool(auth)))
        if not auth:
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {"WWW-Authenticate": WWW}, io.BytesIO(b""))
        if not self.expect(auth, req.full_url):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {"WWW-Authenticate": WWW}, io.BytesIO(b""))
        key = next(k for k in BODY if k in req.full_url)

        class R(io.BytesIO):
            status = 200
            def __enter__(s):
                return s
            def __exit__(s, *a):
                return False
        return R(BODY[key].encode("utf-8"))

    def expect(self, auth, url):
        return 'username="viewer"' in auth and self.good == "right" and self._pw_ok

    _pw_ok = True


class NvrTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real = self.m.urlrequest.urlopen
        self.fake = FakeNVR()
        self.m.urlrequest.urlopen = self.fake
        self.write({"default": {"user": "viewer", "password": "pw"},
                    "nvrs": {"192.168.2.11": {"name": "Объект 1"}}})

    def tearDown(self):
        self.m.urlrequest.urlopen = self.real
        cleanup(self.m, self.tmp)

    def write(self, d):
        p = os.path.join(self.tmp, "nvr.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        st = os.stat(p)
        os.utime(p, (st.st_atime, st.st_mtime + len(self.fake.calls) + 1))   # distinct mtime per write

    def test_probe_parses_everything(self):
        d = self.m.nvr_probe("192.168.2.11")
        self.assertTrue(d["ok"], d)
        self.assertEqual(d["model"], "DHI-NVR4216-16P-4KS2")
        self.assertEqual(d["cameras"], [
            {"channel": 1, "name": "Вход", "ip": "192.168.2.57", "enabled": True, "state": "Connected", "analog": False},
            {"channel": 2, "name": "Склад", "ip": "192.168.2.58", "enabled": True, "state": "Disconnected", "analog": False},
        ], "empty channel (192.168.0.0) skipped")
        self.assertEqual(d["disks"][0]["State"], "Success")
        self.assertAlmostEqual(d["disks"][0]["UsedBytes"] / d["disks"][0]["TotalBytes"], 0.975)

    def test_camera_passwords_never_leave(self):
        d = self.m.nvr_probe("192.168.2.11")
        dump = json.dumps(d, ensure_ascii=False)
        self.assertNotIn("CamSecret", dump)
        self.assertIn("***", dump, "redacted, visibly")

    def test_one_attempt_on_wrong_password(self):
        FakeNVR._pw_ok = False
        try:
            d = self.m.nvr_probe("192.168.2.11")
            authed = [c for c in self.fake.calls if c[1]]
            self.assertFalse(d["ok"])
            self.assertEqual(len(authed), 1, "exactly ONE login attempt — Dahua locks after ~5")
            n = len(self.fake.calls)
            d2 = self.m.nvr_probe("192.168.2.11")
            self.assertIn("исправь nvr.json", d2["error"])
            self.assertEqual(len(self.fake.calls), n, "parked: not a single packet until the file changes")
            self.write({"default": {"user": "viewer", "password": "pw2"}, "nvrs": {"192.168.2.11": {}}})
            self.m.nvr_probe("192.168.2.11")
            self.assertGreater(len(self.fake.calls), n, "edited file -> one new try")
        finally:
            FakeNVR._pw_ok = True

    def test_basic_auth_old_firmware(self):
        """10-15 .135: Basic challenge was read as «refused» without sending a password."""
        sent = []

        class R(io.BytesIO):
            status = 200
            def __enter__(s):
                return s
            def __exit__(s, *a):
                return False

        def basic(req, timeout=None):
            auth = req.headers.get("Authorization", "")
            sent.append(bool(auth))
            if auth != "Basic dmlld2VyOnB3":           # viewer:pw
                raise urllib.error.HTTPError(req.full_url, 401, "U", {"WWW-Authenticate": 'Basic realm="NVR"'}, io.BytesIO(b""))
            return R(BODY[next(k for k in BODY if k in req.full_url)].encode("utf-8"))
        self.m.urlrequest.urlopen = basic
        d = self.m.nvr_probe("192.168.2.11")
        self.assertTrue(d["ok"], d)
        self.assertEqual(len(d["cameras"]), 2)
        self.assertEqual(sent.count(True), len(self.m.NVR_ENDPOINTS), "one authed request per endpoint")

    def test_unknown_scheme_does_not_park(self):
        def weird(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 401, "U", {"WWW-Authenticate": "Negotiate"}, io.BytesIO(b""))
        self.m.urlrequest.urlopen = weird
        d = self.m.nvr_probe("192.168.2.11")
        self.assertIn("пароль не отправлял", d["error"])
        self.assertNotIn("192.168.2.11", self.m.NVR_AUTH_FAIL, "nothing sent -> nothing to park")

    def test_digest_header(self):
        h = self.m._digest_header(WWW, "viewer", "pw", "GET", "/cgi-bin/x")
        self.assertIn('qop=auth', h)
        self.assertIn('opaque="abcdef"', h)
        self.assertIn('realm="Login to 4L01B2EPAZ00000"', h)

    def test_notepad_encodings_and_check(self):
        """10-15: the filled file read as «empty» — Notepad's ANSI/BOM vs strict utf-8."""
        p = os.path.join(self.tmp, "nvr.json")
        body = json.dumps({"default": {"user": "viewer", "password": "pw"},
                           "nvrs": {"192.168.2.11": {"name": "Объект 1"}}}, ensure_ascii=False)
        for raw in (body.encode("cp1251"), b"\xef\xbb\xbf" + body.encode("utf-8")):
            with open(p, "wb") as f:
                f.write(raw)
            conf, _ = self.m.nvr_config()
            self.assertEqual(conf["192.168.2.11"]["user"], "viewer")
            self.assertEqual(conf["192.168.2.11"]["name"], "Объект 1")
        chk = self.m.nvr_config_check()[0]
        self.assertTrue(chk["exists"])
        self.assertEqual(chk["nvrs"]["192.168.2.11"], {"user": True, "password": True})
        # not the whole dump: the random temp path may itself contain "pw" (flaked once, 10-15)
        self.assertNotIn("pw", json.dumps({k: v for k, v in chk.items() if k != "path"}), "booleans only, never the values")

    def test_empty_creds_say_where_and_what(self):
        self.write({"nvrs": {"192.168.2.11": {"name": "Объект 1", "user": "viewer", "password": ""}}})
        d = self.m.nvr_probe("192.168.2.11")
        self.assertIn("пусто: password", d["error"])
        self.assertIn("nvr.json", d["error"])
        self.assertEqual(self.fake.calls, [], "nothing sent with half the creds")

    def test_silent_recorder_is_not_empty(self):
        """10-15: segment powered off -> every request timed out -> «ok, 0 cameras»."""
        def dead(req, timeout=None):
            raise OSError("timed out")
        self.m.urlrequest.urlopen = dead
        d = self.m.nvr_probe("192.168.2.11")
        self.assertFalse(d["ok"])
        self.assertIn("не отвечает", d["error"])
        self.assertNotIn("192.168.2.11", self.m.NVR_AUTH_FAIL, "a timeout is not a refused login")

    def test_missing_config(self):
        os.remove(os.path.join(self.tmp, "nvr.json"))
        self.assertIn("нет в nvr.json", self.m.nvr_probe("192.168.2.11")["error"])
        self.assertEqual(self.fake.calls, [], "no creds -> no traffic")


class WifiAckTileTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_acked_ap_keeps_tile_green(self):
        m = self.m
        m.ap_quiet_now = lambda lt=None: False
        m._UNIFI.update(ok=True, aps=[{"name": n, "online": n != "3-1"} for n in ("1-1", "2-1", "3-1")])
        svc = {"id": "wifi", "name": "Wi-Fi", "unifi": True}
        self.assertEqual(m.service_status(svc)["status"], "warn")
        m.ack_issue("ap:3-1")
        st = m.service_status(svc)
        self.assertEqual((st["status"], st["detail"]), ("ok", "точек на связи 2 из 3 (3-1 — принято)"))
        m._UNIFI.update(aps=[{"name": n, "online": n == "1-1"} for n in ("1-1", "2-1", "3-1")])
        self.assertEqual(m.service_status(svc)["status"], "down", "a NEW dead AP counts again (2 of 3 dead = down)")


if __name__ == "__main__":
    unittest.main()
