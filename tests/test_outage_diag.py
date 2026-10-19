"""v0.57: when a camera group comes back, say WHEN — first device, 90 %, all —
so «night power plan or failure?» is answered by data (10-15: 9 of 97 at
19:11). And /api/diag: what the monitor itself sees on the wire."""
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram

SVC = {"id": "cams", "name": "Камеры", "group": {"cidr": "10.10.2.0/24", "min_pct": 90}}
IPS = [f"10.10.2.{i}" for i in range(10, 30)]          # 20 cameras


class OutageTimelineTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.CONFIG["services"] = [dict(SVC)]
        self.t0 = time.mktime((2026, 10, 15, 19, 10, 0, 0, 0, -1))

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def sweep(self, minutes, alive):
        return self.m.group_sweep(self.m.CONFIG["services"][0], now=self.t0 + minutes * 60,
                                  scan=lambda c, timeout: list(alive))

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_night_and_morning(self):
        m = self.m
        self.sweep(0, IPS)
        self.sweep(5, IPS[:2])                                   # 19:15 — gone
        self.assertIn("на связи 2 из 20", self.texts()[-1])
        o = m.services_view()[0]["outage"]
        self.assertEqual((o["n"], o["back"]), (18, 0))
        m.group_note_seen(IPS[5], self.t0 + 12.5 * 3600, "SSDP")   # 07:40 exact, between sweeps
        self.sweep(12.5 * 60 + 5, IPS[:2] + IPS[5:12])           # 07:45 — 7 back by ping
        self.sweep(12.5 * 60 + 10, IPS[:19])                     # 07:50 — 17 of 18 = 94 %
        msg = self.texts()[-1]
        self.assertIn("снова", msg)
        self.assertIn("пропали 19:15", msg)
        self.assertIn("первая вернулась 16.10 07:40", msg, "next day — the date is said")
        self.assertIn("SSDP", msg, "the exact passive time beats the sweep")
        self.assertIn("90 % — 16.10 07:50", msg, "told at 90 % — the service is ok again")
        self.assertIn("вернулось 17 из 18", msg)
        hist = m.services_view()[0]["outages"]
        self.assertEqual(len(hist), 1)
        self.assertIsNone(hist[0]["all"])
        self.sweep(12.5 * 60 + 20, IPS)                          # 08:00 — the last one
        hist = m.services_view()[0]["outages"]
        self.assertEqual(hist[0]["all"], self.t0 + (12.5 * 60 + 20) * 60, "history gets «all back» later")
        self.assertEqual(len(self.texts()), 2, "no extra message for the stragglers")
        self.assertIsNone(m.services_view()[0]["outage"], "outage closed")

    def test_partial_return_is_said_so(self):
        m = self.m
        self.sweep(0, IPS)
        self.sweep(5, IPS[:2])
        self.sweep(600, IPS[:19])                                # 17 of 18 back, ok by threshold
        self.assertIn("вернулось 17 из 18", self.texts()[-1], "one never came back — not «все»")

    def test_upgrade_mid_outage_says_before(self):
        m = self.m
        self.sweep(0, IPS)
        m.GROUPS["cams"].update(told=True)                        # told by a build without tracking
        self.sweep(5, IPS[:2])
        self.sweep(600, IPS)
        self.assertIn("пропали до 19:15", self.texts()[-1])

    def test_passive_hook_from_listener(self):
        m = self.m
        self.sweep(0, IPS)
        self.sweep(5, IPS[:2])
        m._passive_note(IPS[3], "IPC", "", "mDNS")
        back = m.GROUPS["cams"]["outage"]["back"]
        self.assertEqual(back[IPS[3]][1], "mDNS")

    def test_outage_survives_restart(self):
        m = self.m
        self.sweep(0, IPS)
        self.sweep(5, IPS[:2])
        self.assertIn("groups", m._runtime_registry(), "GROUPS (with the open outage) is snapshotted")


class DiagTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_diagnose_shape(self):
        ran = []
        d = self.m.diagnose("127.0.0.1", run=lambda c: (ran.append(c[0]), "out:" + c[0])[1])
        self.assertEqual(d["source_ip"], "127.0.0.1")
        self.assertIn("ping", ran)
        self.assertTrue(all(o["text"].startswith("out:") for o in d["outputs"]))
        self.assertIn("ok", d["tcp80"])


if __name__ == "__main__":
    unittest.main()
