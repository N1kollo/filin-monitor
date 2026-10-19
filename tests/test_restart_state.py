"""v0.44: nothing lost on a dead link, nothing replayed or forgotten on restart."""
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram


class _Stop(BaseException):
    pass


class OutboxTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.link = [True]  # True = Telegram unreachable (502)
        self.calls = stub_telegram(self.m, lambda meth, p: self.link[0])

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def rows(self):
        return self.m._db.execute("SELECT id, kind, attempts FROM tg_outbox ORDER BY id").fetchall()

    def test_retryable(self):
        r = self.m.tg_retryable
        self.assertTrue(r("timed out"))
        self.assertTrue(r("Telegram API 502: Bad Gateway"))
        self.assertTrue(r("Telegram API 429: Too Many Requests"))
        self.assertFalse(r("Telegram API 400: can't parse entities"))
        self.assertFalse(r("Telegram API 403: bot was blocked"))

    def test_dead_link_then_recovery(self):
        m = self.m
        ok, detail = m.emit("down", "🔴 kassa down")
        self.assertTrue(ok)
        self.assertTrue(detail.startswith("в очереди"))
        m.emit("down", "🔴 second")
        self.assertEqual([r[1] for r in self.rows()], ["down"] * 2)

        far = time.time() + 3600
        self.assertEqual(m.outbox_flush(far), (0, 0), "link still down: nothing sent")
        self.assertEqual(len(self.rows()), 2, "kept for later")
        self.assertEqual(self.rows()[0][2], 2, "first attempt counted, stopped there (order)")

        self.link[0] = False
        self.assertEqual(m.outbox_flush(far + 3600), (2, 0))
        self.assertEqual(self.rows(), [])
        texts = [c[1]["text"] for c in self.calls if c[0] == "sendMessage"][-2:]
        self.assertTrue(texts[0].startswith("⏳ <i>с задержкой") and texts[0].endswith("kassa down"))
        self.assertTrue(texts[1].endswith("second"), "delivered in original order")
        kinds = {k["kind"] for k in m.db_tg_sent_stats(1)["by_kind"]}
        self.assertEqual(kinds, {"down"}, "resend keeps the original kind")

    def test_rejected_on_retry_and_expired_are_dropped(self):
        m = self.m
        m.tg_send("a")
        self.link[0] = 400
        self.assertEqual(m.outbox_flush(time.time() + 3600), (0, 0))
        self.assertEqual(self.rows(), [], "permanent refusal is not retried forever")
        self.link[0] = True
        m.tg_send("b")
        self.assertEqual(m.outbox_flush(time.time() + m.OUTBOX_MAX_AGE + 60), (0, 1))
        self.assertEqual(self.rows(), [])

    def test_no_queue_for_settings_test_button(self):
        ok, detail = self.m.tg_send("test", queue=False)
        self.assertFalse(ok, "the test button must report the real result")
        self.assertEqual(self.rows(), [])


class RestartTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [
            {"id": "h1", "name": "kassa", "host": "10.0.0.2", "type": "ping", "priority": "critical"},
            {"id": "h2", "name": "pc", "host": "10.0.0.3", "type": "ping"},
            {"id": "h3", "name": "new", "host": "10.0.0.4", "type": "ping"},
        ]
        self.t_down = time.time() - 3600
        m.db_event("h1", self.t_down, "down", "timeout")
        m.db_event("h2", self.t_down - 60, "down", "timeout")
        m.db_event("h2", self.t_down, "up", None, 60)
        m.db_event("h2", self.t_down + 5, "diag", "x")

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_state_seeded_from_event_log(self):
        m = self.m
        m.reconcile_state()
        self.assertEqual(m.STATE["h1"]["status"], "down")
        self.assertEqual(m.STATE["h1"]["since"], self.t_down)
        self.assertEqual(m.STATE["h2"]["status"], "pending", "last transition was up")
        self.assertEqual(m.STATE["h3"]["status"], "pending")

        h1 = m.CONFIG["hosts"][0]
        self.assertIsNone(m.process_result(h1, False, None, "timeout"), "no second 'упал'")
        ev = m.process_result(h1, True, 1.0, None)
        self.assertEqual(ev["type"], "up", "recovery during downtime is reported")
        self.assertAlmostEqual(ev["downtime"], 3600, delta=5, msg="real downtime, not since restart")

    def test_escalation_clock_from_outage_not_restart(self):
        m = self.m
        m.reconcile_state()
        m.seed_escalations()
        self.assertEqual(m.ESCALATE, {"h1": {"since": self.t_down, "done": False}})
        m.ESCALATE.clear()
        m.ESCALATE["h1"] = {"since": self.t_down, "done": True}
        m.seed_escalations()
        self.assertTrue(m.ESCALATE["h1"]["done"], "snapshot (already escalated) wins")

    def test_runtime_snapshot_roundtrip(self):
        m = self.m
        m.ESCALATE["h1"] = {"since": 5.0, "done": True}
        m.ACKED.add("h1")
        m._UNIFI_DOWN.add("3-1")
        m._DHCP_ALERTED["10.0.0.9"] = 7.0
        m._DIGEST_FIRED["2026-10-13"] = True
        m.runtime_save()
        m._db.close()
        m2, _ = load_monitor(self.tmp, name=f"m_{time.time_ns()}")
        self.m = m2
        acked, unifi = m2.ACKED, m2._UNIFI_DOWN
        m2.runtime_restore()
        self.assertEqual(m2.ESCALATE, {"h1": {"since": 5.0, "done": True}})
        self.assertEqual((m2.ACKED, m2._UNIFI_DOWN), ({"h1"}, {"3-1"}))
        self.assertIs(m2.ACKED, acked, "restored in place: references stay valid")
        self.assertIs(m2._UNIFI_DOWN, unifi)
        self.assertEqual(m2._DHCP_ALERTED, {"10.0.0.9": 7.0})
        self.assertIn("2026-10-13", m2._DIGEST_FIRED)


class WanTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.sent = []
        m.emit = lambda kind, t, **kw: self.sent.append(t) or (True, "ok")
        m.quiet_now = lambda: False
        m.time.sleep = lambda s: None
        self.next = {}
        m.wan_cycle = lambda state, wan, thr: dict(self.next)

    def tearDown(self):
        cleanup(self.m, self.tmp)   # restores the real time.sleep

    def test_seed(self):
        m = self.m
        self.assertEqual(m.wan_seed(), ({"gw": True, "inet": True, "dns": True}, {}))
        ts = time.time() - 600
        m.db_event("_wan_inet", ts, "down", "timeout")
        prev, since = m.wan_seed()
        self.assertEqual((prev["inet"], since), (False, {"inet": ts}))

    def test_link_down_at_boot_is_announced_once(self):
        m = self.m
        prev, since = m.wan_seed()
        self.next = {"gw": True, "inet": None, "dns": True}  # first miss, not settled
        prev = m._wan_step(prev, since)
        self.assertEqual(self.sent, [], "settling is not a flip")
        self.next = {"gw": True, "inet": False, "dns": False}
        prev = m._wan_step(prev, since)
        self.assertEqual(len(self.sent), 1, "down at boot -> announced (was: never)")
        prev = m._wan_step(prev, since)
        self.assertEqual(len(self.sent), 1, "standing outage is not repeated")

    def test_known_outage_not_repeated_after_restart(self):
        m = self.m
        for leg in ("_wan_inet", "_wan_dns"):
            m.db_event(leg, time.time() - 600, "down", "timeout")
        prev, since = m.wan_seed()
        self.next = {"gw": True, "inet": False, "dns": False}
        m._wan_step(prev, since)
        self.assertEqual(self.sent, [])
        self.next = {"gw": True, "inet": True, "dns": True}
        m._wan_step(dict(self.next, inet=False, dns=False), since)
        self.assertEqual(self.sent, ["🌐 Интернет вернулся.", "🌐 DNS снова резолвит."],
                         "recovery still reported")


class DigestTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["quiet"] = {"enabled": True, "from": "22:00", "to": "08:00", "digest": True}
        self.sent = []
        m.emit = lambda kind, t, **kw: self.sent.append(t) or (True, "ok")
        m.build_night_digest = lambda ev, still, span: "night digest"

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def run_at(self, hh, mm):
        m = self.m
        real_lt, real_sleep = m.time.localtime, m.time.sleep
        m.time.localtime = lambda *a: time.struct_time((2026, 10, 13, hh, mm, 0, 0, 286, 0))

        def stop(_):
            raise _Stop()
        m.time.sleep = stop
        try:
            with self.assertRaises(_Stop):
                m.quiet_digest_loop()
        finally:
            m.time.localtime, m.time.sleep = real_lt, real_sleep

    def test_catch_up_window(self):
        self.run_at(7, 59)
        self.assertEqual(self.sent, [])
        self.run_at(8, 37)
        self.assertEqual(self.sent, ["night digest"], "late start still delivers")
        self.run_at(8, 50)
        self.assertEqual(len(self.sent), 1, "once per day")

    def test_window_closes(self):
        self.run_at(10, 1)
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
