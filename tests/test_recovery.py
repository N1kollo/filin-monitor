"""v0.49: one-tap recovery after a power cut — Hyper-V hosts first, VMs come up
with them, re-check, then the rest. Replays the shape of the real outage."""
import json
import threading
import unittest

from harness import cleanup, load_monitor, stub_telegram

HOSTS = [
    {"id": "s09", "name": "S09", "host": "10.10.1.27", "type": "host", "mac": "10:78:d2:00:00:09"},
    {"id": "s08", "name": "S08", "host": "10.10.1.24", "type": "host", "mac": "00:15:5d:00:1b:01", "parent": "s09"},
    {"id": "im", "name": "APP_SRV", "host": "10.10.1.21", "type": "ping", "mac": "00:15:5d:00:21:09"},
    {"id": "pc", "name": "Бухгалтерия", "host": "10.10.1.50", "type": "host", "mac": "aa:bb:cc:00:00:01", "parent": "sw"},
    {"id": "sw", "name": "Коммутатор", "host": "10.10.1.2", "type": "ping", "mac": "aa:bb:cc:00:00:02"},
    {"id": "cam", "name": "Камера", "host": "10.10.2.64", "type": "ping"},
    {"id": "ok", "name": "Живой", "host": "10.10.1.9", "type": "ping", "mac": "aa:bb:cc:00:00:09"},
]


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["hosts"] = [dict(h) for h in HOSTS]
        m.reconcile_state()
        with m.STATE_LOCK:
            for h in HOSTS:
                m.STATE[h["id"]]["status"] = "up" if h["id"] == "ok" else "down"
        self.woken = []
        m.send_wol = lambda mac, bc=None: self.woken.append(mac)
        self.alive = set()
        m.run_check = lambda h, t: (h["id"] in self.alive, 1.0, None)
        m.time.sleep = self.on_wait          # each wave's wait = the moment things boot
        self.waits = 0

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def on_wait(self, sec):
        self.waits += 1
        if self.waits == 1:          # after wave 1: S09 is up, its VM S08 autostarted, switch up
            self.alive |= {"s09", "s08", "sw"}
        elif self.waits == 2:        # after wave 2: the PC behind the switch is up
            self.alive |= {"pc"}

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_plan_order(self):
        plan = {x["id"]: (x["action"], x["wave"]) for x in self.m.recovery_plan()}
        self.assertEqual(plan["s09"], ("wol", 1), "Hyper-V host first")
        self.assertEqual(plan["s08"], ("wait_parent", 2), "VM rides on its host — no WoL")
        self.assertEqual(plan["im"], ("vm_manual", 0), "a VM with a live (or no) host can't be WoL'd")
        self.assertEqual(plan["sw"], ("wol", 1))
        self.assertEqual(plan["pc"], ("wol", 2), "behind a dead parent: second wave")
        self.assertEqual(plan["cam"], ("no_mac", 0))
        self.assertNotIn("ok", plan, "live hosts are not in the plan")
        order = [x["id"] for x in self.m.recovery_plan()]
        self.assertLess(order.index("s09"), order.index("pc"))

    def test_power_cut_run(self):
        m = self.m
        self.assertTrue(m.recovery_run(by="тест", wait=1))
        self.assertEqual(self.woken[:2], ["10:78:d2:00:00:09", "aa:bb:cc:00:00:02"], "wave 1: S09 + switch")
        self.assertEqual(self.woken[2:], ["aa:bb:cc:00:00:01"], "wave 2: the PC, after its switch rose")
        self.assertNotIn("00:15:5d:00:1b:01", self.woken, "never WoL a VM")
        res = {x["id"]: x["result"] for x in m.RECOVERY["steps"]}
        self.assertEqual(res, {"s09": "up", "sw": "up", "s08": "up", "pc": "up",
                               "im": "skip", "cam": "skip"})
        report = self.texts()[-1]
        self.assertIn("Встали: S09", report)
        self.assertIn("запусти в «Диспетчере Hyper-V»: APP_SRV", report)
        self.assertIn("Без MAC, будить нечем: Камера", report)
        self.assertIn("Поднимаю упавшие", self.texts()[0])
        self.assertFalse(m.RECOVERY["running"])

    def test_host_that_stays_dark(self):
        self.on_wait = lambda sec: None
        self.m.time.sleep = self.on_wait
        self.m.recovery_run(wait=1)
        self.assertIn("Не встали после WoL: S09, Коммутатор, Бухгалтерия", self.texts()[-1], "plan order: wave 1 first")
        self.assertIn("S08", self.texts()[-1], "its host never rose -> the VM is listed for Hyper-V")

    def test_only_one_run_at_a_time(self):
        m = self.m
        m.RECOVERY["running"] = True
        self.assertFalse(m.recovery_run(wait=1))
        self.assertFalse(m.recovery_start("x"))
        self.assertEqual(self.woken, [])

    def test_nothing_down(self):
        with self.m.STATE_LOCK:
            for h in HOSTS:
                self.m.STATE[h["id"]]["status"] = "up"
        self.assertEqual(self.m.recovery_plan(), [])
        text, kb = self.m.recovery_view()
        self.assertIn("поднимать нечего", text)

    def test_bot_screen_and_start(self):
        m = self.m
        started = []
        m.recovery_start = lambda by="": started.append(by) or True
        text, kb = m.recovery_view()
        self.assertIn("S09 — ⏻ разбужу (волна 1)", text)
        self.assertIn("m:rg", kb)
        m.handle_update({"update_id": 1, "callback_query": {"id": "c", "data": "m:rg",
                         "message": {"chat": {"id": 42}, "message_id": 1}}})
        self.assertEqual(started, ["Telegram"])

    def test_storm_digest_offers_recovery(self):
        m = self.m
        m.CONFIG["alerts"]["storm_threshold"] = 3
        m.maybe_trace = lambda downs, storm=False: None
        roots = [h for h in HOSTS if not h.get("parent") and h["id"] != "ok"]     # nothing suppressed
        m.dispatch_alerts([{"type": "down", "host": h, "error": "timeout"} for h in roots])
        msg = [c[1] for c in self.calls if c[0] == "sendMessage"][-1]
        self.assertIn("m:rv:n", msg["reply_markup"], "mass outage -> one-tap recovery")

    def test_api(self):
        m = self.m
        srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            import urllib.request
            import urllib.error
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            with urllib.request.urlopen(base + "/api/recovery", timeout=5) as r:
                d = json.load(r)
            self.assertEqual(d["actionable"], 4)
            m.recovery_start = lambda by="": False
            req = urllib.request.Request(base + "/api/recovery/start", data=b"{}", method="POST",
                                         headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(req, timeout=5)
            with e.exception:
                self.assertEqual(e.exception.code, 409)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
