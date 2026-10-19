"""v0.47: AP offline/online — grouped, quiet-aware, learns the nightly pattern.
Replays the real 10-13/10-14 office case: 9 APs drop at 19:25, return at 07:23."""
import json
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram

NINE = ["1-1", "1-2", "1-3", "1-4", "2-1", "2-2", "2-3", "2-4", "3-2"]


def at(day, hh, mm):
    """Local timestamp: 2026-10-13 + day, hh:mm."""
    return time.mktime((2026, 10, 13 + day, hh, mm, 0, 0, 0, -1))


class UnifiApTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.CONFIG["quiet"] = {"enabled": True, "from": "22:00", "to": "08:00", "digest": True}
        self.m._UNIFI_DOWN.add("3-1")        # down for days, already announced
        self.m._UNIFI_AP_TOLD.add("3-1")

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def sent(self):
        return [c[1] for c in self.calls if c[0] == "sendMessage"]

    def poll(self, down, ts):
        self.m.unifi_ap_alerts(set(down), now=ts, lt=time.localtime(ts))

    def test_real_two_nights(self):
        m = self.m
        # night 1 — no history yet
        self.poll(["3-1"] + NINE, at(0, 19, 25))
        self.assertEqual(len(self.sent()), 1, "9 APs = 1 message, 3-1 not repeated")
        self.assertIn("отвалились 9 точек", self.sent()[0]["text"])
        self.assertNotIn("ap:q:", self.sent()[0].get("reply_markup", ""), "no history -> no window offer")
        self.poll(["3-1"], at(1, 7, 23))                 # back inside quiet hours
        self.assertEqual(len(self.sent()), 1, "silent at 07:23")
        self.poll(["3-1"], at(1, 8, 1))                  # quiet over
        self.assertEqual(len(self.sent()), 2)
        self.assertIn("Снова на связи 9 точек", self.sent()[1]["text"])

        # night 2 — same APs, same time: suggest the window
        self.poll(["3-1"] + NINE, at(1, 19, 26))
        msg = self.sent()[2]
        self.assertIn("Вчера в это же время", msg["text"])
        kb = json.loads(msg["reply_markup"])
        data = kb["inline_keyboard"][0][0]["callback_data"]
        self.assertEqual(data, "ap:q:1855:0755", "30 min before the drop .. 30 min after recovery")

        # tap it
        m.handle_update({"update_id": 1, "callback_query": {"id": "c", "data": data,
                         "message": {"chat": {"id": 42}, "message_id": 1}}})
        self.assertEqual(m.CONFIG["unifi"]["ap_quiet"], {"from": "18:55", "to": "07:55"})
        n = len(self.sent())
        self.poll(["3-1"], at(2, 7, 23))
        self.poll(["3-1"], at(2, 8, 0))                  # night 2's drop was told -> recovery told
        self.assertEqual(len(self.sent()), n + 1)

        # night 3 — fully silent
        n = len(self.sent())
        self.poll(["3-1"] + NINE, at(2, 19, 25))
        self.poll(["3-1"], at(3, 7, 23))
        self.poll(["3-1"], at(3, 8, 0))
        self.assertEqual(len(self.sent()), n, "planned nightly power-down: zero messages")

    def test_still_down_after_window_is_announced_once(self):
        self.m.CONFIG["unifi"] = {"ap_quiet": {"from": "18:55", "to": "07:55"}}
        self.poll(["3-1", "2-2"], at(0, 23, 0))
        self.assertEqual(self.sent(), [])
        self.poll(["3-1", "2-2"], at(1, 8, 0))
        self.assertEqual(len(self.sent()), 1)
        self.assertIn("«2-2» отвалилась", self.sent()[0]["text"])
        self.poll(["3-1", "2-2"], at(1, 9, 0))
        self.assertEqual(len(self.sent()), 1)

    def test_window_off_button_and_filter_line(self):
        m = self.m
        m.CONFIG["unifi"] = {"ap_quiet": {"from": "18:55", "to": "07:55"}}
        text, kb = m.filter_view()
        self.assertIn("не сообщаю 18:55–07:55", text)
        self.assertIn("ap:x", kb)
        m.handle_update({"update_id": 1, "callback_query": {"id": "c", "data": "ap:x",
                         "message": {"chat": {"id": 42}, "message_id": 1}}})
        self.assertNotIn("ap_quiet", m.CONFIG["unifi"])

    def test_ledger_survives_restart(self):
        m = self.m
        self.poll(["3-1", "1-1", "1-2"], at(0, 19, 25))
        m.runtime_save()
        m._UNIFI_AP_TOLD.clear()
        m.UNIFI_AP_LOG.clear()
        restored = m.runtime_restore()
        self.assertTrue({"unifi_ap_told", "unifi_ap_log"} <= restored)
        self.assertEqual(m._UNIFI_AP_TOLD, {"3-1", "1-1", "1-2"})
        self.assertTrue(m.UNIFI_AP_LOG)


class ApiRoutesTest(unittest.TestCase):
    """Drive the real Handler POST routes over a loopback server."""

    def setUp(self):
        import threading
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [{"id": "h1", "name": "1.21 физ", "host": "192.168.1.21", "type": "host"}]
        m.CONFIG["unifi"] = {"enabled": True}
        self.srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def post(self, path, body):
        import urllib.error
        import urllib.request
        url = f"http://127.0.0.1:{self.srv.server_address[1]}{path}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_rename(self):
        self.assertEqual(self.post("/api/hosts/rename", {"id": "h1", "name": "APP_SRV (VM)"})[0], 200)
        self.assertEqual(self.m.CONFIG["hosts"][0]["name"], "APP_SRV (VM)")
        self.assertEqual(self.post("/api/hosts/rename", {"id": "h1", "name": "  "})[0], 400)

    def test_ap_quiet(self):
        m = self.m
        self.assertEqual(self.post("/api/unifi/config", {"ap_quiet": {"from": "18:55", "to": "07:55"}})[0], 200)
        self.assertEqual(m.CONFIG["unifi"]["ap_quiet"], {"from": "18:55", "to": "07:55"})
        self.assertEqual(m.unifi_view()["config"]["ap_quiet"]["from"], "18:55")
        self.assertEqual(self.post("/api/unifi/config", {"ap_quiet": {"from": "25:00", "to": "x"}})[0], 400)
        self.assertEqual(m.CONFIG["unifi"]["ap_quiet"]["from"], "18:55", "bad input changes nothing")
        self.post("/api/unifi/config", {"ap_quiet": None})
        self.assertNotIn("ap_quiet", m.CONFIG["unifi"])
        self.assertTrue(m.CONFIG["unifi"]["enabled"], "other UniFi settings untouched")


if __name__ == "__main__":
    unittest.main()
