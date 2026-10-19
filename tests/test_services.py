"""v0.52: services — «1С 8 не работает», not «S08 не отвечает».
Office layout: 1С 8 on VM S08 behind Hyper-V S09; 1С 7.7 on VM SERVER behind S23."""
import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from harness import cleanup, load_monitor, stub_telegram

HOSTS = [
    {"id": "s23", "name": "S23 (Hyper-V)", "host": "10.10.1.23", "type": "host"},
    {"id": "s09", "name": "S09 (Hyper-V)", "host": "10.10.1.27", "type": "host"},
    {"id": "srv", "name": "1С Торговля", "host": "10.10.1.20", "type": "host", "parent": "s23"},
    {"id": "s08", "name": "S08", "host": "10.10.1.24", "type": "host", "parent": "s09"},
    {"id": "px", "name": "Прокси", "host": "10.10.1.4", "type": "host"},
]
SERVICES = [
    {"id": "1c77", "name": "1С 7.7", "hosts": ["srv"]},
    {"id": "1c8", "name": "1С 8", "hosts": ["s08"]},
    {"id": "inet", "name": "Интернет", "wan": True},
    {"id": "wifi", "name": "Wi-Fi", "unifi": True},
    {"id": "cams", "name": "Камеры", "group": {"cidr": "10.10.2.0/24", "min_pct": 90}},
]


class ServicesTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["hosts"] = [dict(h) for h in HOSTS]
        m.CONFIG["services"] = [dict(x) for x in SERVICES]
        m.reconcile_state()
        self.set(**{h["id"]: "up" for h in HOSTS})

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def set(self, **st):
        with self.m.STATE_LOCK:
            for k, v in st.items():
                self.m.STATE[k]["status"] = v

    def svc(self, sid):
        return next(x for x in self.m.services_view() if x["id"] == sid)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_vm_down(self):
        self.set(s08="down")
        s = self.svc("1c8")
        self.assertEqual((s["status"], s["cause"]), ("down", "S08"))
        self.assertEqual(self.svc("1c77")["status"], "ok")

    def test_hyperv_host_is_the_cause(self):
        """Power cut on S09: the VM is down too, but the CAUSE is the host."""
        self.set(s09="down", s08="down")
        s = self.svc("1c8")
        self.assertEqual(s["cause"], "S09 (Hyper-V)")
        self.assertEqual(s["detail"], "лежит S09 (Hyper-V) → S08")

    def test_affected_line_in_alert(self):
        m = self.m
        text = m._down_text({"host": HOSTS[1], "error": "timeout"})
        self.assertIn("Затронуто: <b>1С 8</b>", text, "a Hyper-V host down names the service on it")
        self.assertNotIn("Затронуто", m._down_text({"host": HOSTS[4], "error": "x"}),
                         "a host in no service gets no extra line")
        storm = m._storm_text([{"host": HOSTS[0]}, {"host": HOSTS[1]}], "down")
        self.assertIn("1С 7.7, 1С 8", storm)

    def test_wan_and_wifi(self):
        m = self.m
        self.assertEqual(self.svc("inet")["status"], "unknown", "no data yet")
        m.WAN_STATE.update(gw={"up": True}, inet={"up": False}, dns={"up": False})
        self.assertEqual(self.svc("inet")["detail"], "не работает: канал, DNS")
        m._UNIFI.update(ok=True, aps=[{"name": str(i), "online": i != 3} for i in range(10)])
        m.ap_quiet_now = lambda lt=None: False
        self.assertEqual((self.svc("wifi")["status"], self.svc("wifi")["detail"]), ("warn", "точек на связи 9 из 10"))
        m.ap_quiet_now = lambda lt=None: True
        self.assertEqual(self.svc("wifi")["status"], "ok", "planned night outage is not a problem")
        m.ap_quiet_now = lambda lt=None: False
        m._UNIFI.update(ok=False)
        m.UNIFI_CTRL["announced"] = True
        self.assertEqual(self.svc("wifi")["detail"], "контроллер UniFi не отвечает")

    def test_camera_group(self):
        m = self.m
        svc = m.CONFIG["services"][4]
        ips = [f"10.10.2.{i}" for i in range(10, 83)]          # 73 cameras
        t = time.time()
        st = m.group_sweep(svc, now=t, scan=lambda c, timeout: list(ips))
        self.assertEqual((st["status"], st["detail"]), ("ok", "на связи 73 из 73 обычных"))
        st = m.group_sweep(svc, now=t + 300, scan=lambda c, timeout: ips[:70])
        self.assertEqual(st["status"], "ok", "70/73 = 96% — within 90%")
        self.assertEqual(self.texts(), [])
        st = m.group_sweep(svc, now=t + 600, scan=lambda c, timeout: ips[:61])
        self.assertEqual(st["status"], "warn")
        self.assertEqual(len(self.texts()), 1)
        self.assertIn("на связи 61 из 73 обычных", self.texts()[0])
        self.assertIn("10.10.2.71", self.texts()[0], "the missing ones are named")
        m.group_sweep(svc, now=t + 900, scan=lambda c, timeout: ips[:60])
        self.assertEqual(len(self.texts()), 1, "told once")
        m.group_sweep(svc, now=t + 1200, scan=lambda c, timeout: list(ips))
        self.assertIn("снова на связи 73", self.texts()[-1])

    def test_group_expected_is_7_day_max(self):
        m = self.m
        svc = m.CONFIG["services"][4]
        day = 86400
        t = time.time() - 10 * day
        m.group_sweep(svc, now=t, scan=lambda c, timeout: [f"10.10.2.{i}" for i in range(80)])
        for d in range(1, 9):
            m.group_sweep(svc, now=t + d * day, scan=lambda c, timeout: [f"10.10.2.{i}" for i in range(70)])
        self.assertEqual(m.GROUPS["cams"]["expected"], 70, "an 80 from 9 days ago has aged out")

    def test_status_message_has_services(self):
        self.set(s08="down")
        txt = self.m.format_status_message()
        self.assertIn("🔴 1С 8", txt)
        self.assertIn("✅ 1С 7.7", txt)


class ServicesApiTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [dict(h) for h in HOSTS]
        m.reconcile_state()
        m.scan_subnet = lambda cidr, timeout=1.0: ["10.10.2.10", "10.10.2.11"]
        m.arp_table = lambda: {"10.10.2.10": "bc:ad:28:00:00:01"}
        self.srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_configure_and_read(self):
        self.assertEqual(self.call("/api/services", {"services": SERVICES})[0], 200)
        _, d = self.call("/api/services")
        self.assertEqual([x["name"] for x in d["services"]], ["1С 7.7", "1С 8", "Интернет", "Wi-Fi", "Камеры"])
        self.assertEqual(self.call("/api/services", {"services": [{"id": "x"}]})[0], 400)
        self.assertEqual(self.call("/api/services", {"services": [{"id": "x", "name": "X", "group": {"cidr": "zzz"}}]})[0], 400)

    def test_one_off_scan_is_read_only(self):
        code, d = self.call("/api/scan?cidr=10.10.2.0/24")
        self.assertEqual((code, d["count"]), (200, 2))
        self.assertEqual(d["alive"][0]["mac"], "bc:ad:28:00:00:01")
        self.assertEqual(self.m._db.execute("SELECT COUNT(*) FROM arp_seen").fetchone()[0], 0, "nothing stored")
        self.assertEqual(self.call("/api/scan?cidr=10.0.0.0/16")[0], 400, "no /16 sweeps")


if __name__ == "__main__":
    unittest.main()
