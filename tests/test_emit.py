"""v0.45: one alert door (emit), recovery only for announced outages,
escalation context, cycle atomicity, housekeeping."""
import os
import re
import time
import unittest

from harness import REAL_SLEEP, ROOT, cleanup, load_monitor, stub_telegram


class ProducerContractTest(unittest.TestCase):
    """Static: every alert in the ssd package names a kind the gates know about."""

    def test_every_emit_has_a_known_kind(self):
        m, tmp = load_monitor()
        try:
            known = set(m.ALERT_KINDS) | m.HOST_KINDS | m.NOTICE_KINDS
        finally:
            cleanup(m, tmp)
        pkg = os.path.join(ROOT, "ssd")
        src = ""
        for name in sorted(os.listdir(pkg)):
            if name.endswith(".py"):
                with open(os.path.join(pkg, name), encoding="utf-8") as f:
                    src += f.read() + chr(10)
        kinds = re.findall(r'\bemit\(\s*"([a-z_]+)"', src)
        self.assertGreaterEqual(len(kinds), 25, "all producers go through emit")
        self.assertEqual(set(kinds) - known, set(), "typo'd kind would bypass mute")
        sends = re.findall(r"^(?!def ).*\btg_send\(", src, re.M)
        self.assertEqual(len(sends), 1, "only the settings test button uses tg_send")
        self.assertNotIn("tg_send_markup", src)


class EmitGateTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.h = {"id": "h1", "name": "srv", "host": "10.0.0.2", "type": "ping"}
        self.m.CONFIG["hosts"] = [self.h]

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def sends(self):
        return [c for c in self.calls if c[0] == "sendMessage"]

    def test_host_mute_and_maintenance(self):
        m = self.m
        m.set_mute("muted_hosts", "h1", 3600)
        self.assertEqual(m.emit("degradation", "x", host=self.h), (True, "muted"))
        m.set_mute("muted_hosts", "h1", None)
        m.CONFIG["maintenance"] = [{"id": "w", "from": "00:00", "to": "23:59", "days": [],
                                    "hosts": [], "enabled": True}]
        self.assertEqual(m.emit("trace", "x", host=self.h), (True, "maintenance"))
        self.assertEqual(m.emit("wifi", "x")[1], "ok", "non-host kinds ignore host windows")
        self.assertEqual(len(self.sends()), 1)
        self.assertEqual(m.db_tg_sent_stats(1)["muted"], 2, "host mute + maintenance window")

    def test_wan_mute_works_again(self):
        m = self.m
        m.set_mute("muted_kinds", "wan", 3600)
        m.CONFIG["wan"] = {"enabled": True}
        m.quiet_now = lambda: False
        m.time.sleep = lambda s: None
        m.wan_cycle = lambda st, w, t: {"gw": True, "inet": False, "dns": False}
        try:
            m._wan_step({"gw": True, "inet": True, "dns": True}, {})
        finally:
            m.time.sleep = REAL_SLEEP
        self.assertEqual(self.sends(), [], "0.43-0.44 regression: WAN mute keyed on wan_loop")


class AnnouncedRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["hosts"] = [
            {"id": "gw", "name": "gw", "host": "10.0.0.1", "type": "ping"},
            {"id": "c1", "name": "child", "host": "10.0.0.5", "type": "ping", "parent": "gw"},
            {"id": "n1", "name": "nightly", "host": "10.0.0.6", "type": "ping"},
        ]
        m.maybe_trace = lambda downs, storm=False: None
        m.reconcile_state()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def ev(self, hid, typ):
        h = next(x for x in self.m.CONFIG["hosts"] if x["id"] == hid)
        return {"type": typ, "host": h, "error": "timeout", "downtime": 60}

    def test_suppressed_child_recovers_silently(self):
        m = self.m
        with m.STATE_LOCK:
            m.STATE["gw"]["status"] = "down"
        m.dispatch_alerts([self.ev("gw", "down"), self.ev("c1", "down")])
        self.assertEqual(len(self.texts()), 1, "child suppressed by its dead parent")
        m.dispatch_alerts([self.ev("gw", "up"), self.ev("c1", "up")])
        ups = [t for t in self.texts()[1:]]
        self.assertEqual(len(ups), 1, "only the announced parent gets 'восстановлен'")
        self.assertIn("gw", ups[0])
        self.assertEqual(m.ANNOUNCED, set())

    def test_quiet_hours_down_then_digest_then_recovery(self):
        m = self.m
        m.quiet_now = lambda: True
        m.dispatch_alerts([self.ev("n1", "down")])
        self.assertEqual(self.texts(), [], "normal host held at night")
        m.quiet_now = lambda: False
        m.dispatch_alerts([self.ev("n1", "up")])
        self.assertEqual(self.texts(), [], "no recovery for an outage nobody heard about")

        m.ANNOUNCED.add("n1")          # what the morning digest does for still-down hosts
        m.dispatch_alerts([self.ev("n1", "up")])
        self.assertEqual(len(self.texts()), 1)

    def test_storm_announces_everyone(self):
        m = self.m
        m.CONFIG["alerts"]["storm_threshold"] = 2
        m.dispatch_alerts([self.ev("gw", "down"), self.ev("n1", "down")])
        self.assertEqual(m.ANNOUNCED, {"gw", "n1"})

    def test_announced_survives_restart(self):
        m = self.m
        m.ANNOUNCED.add("gw")
        m.runtime_save()
        m.ANNOUNCED.clear()
        self.assertIn("announced", m.runtime_restore())
        self.assertEqual(m.ANNOUNCED, {"gw"})


class EscalationContextTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["alerts"]["escalate_after_minutes"] = 5
        m.CONFIG["hosts"] = [
            {"id": "gw", "name": "gw", "host": "10.0.0.1", "type": "ping"},
            {"id": "k", "name": "kassa", "host": "10.0.0.2", "type": "ping",
             "priority": "critical", "parent": "gw"},
        ]
        with m.STATE_LOCK:
            m.STATE["gw"] = {"status": "up"}
            m.STATE["k"] = {"status": "down"}
        m.ESCALATE["k"] = {"since": time.time() - 600, "done": False}

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_held_under_dead_parent_then_fires(self):
        m = self.m
        with m.STATE_LOCK:
            m.STATE["gw"]["status"] = "down"
        self.assertEqual(m.check_escalations(), [])
        self.assertFalse(m.ESCALATE["k"]["done"], "held, not consumed")
        with m.STATE_LOCK:
            m.STATE["gw"]["status"] = "up"
        self.assertEqual(m.check_escalations(), ["k"])

    def test_held_during_maintenance(self):
        m = self.m
        m.CONFIG["maintenance"] = [{"id": "w", "from": "00:00", "to": "23:59", "days": [],
                                    "hosts": ["k"], "enabled": True}]
        self.assertEqual(m.check_escalations(), [])
        self.assertFalse(m.ESCALATE["k"]["done"])


class CycleAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [{"id": f"h{i}", "name": f"h{i}", "host": f"10.0.0.{i}",
                              "type": "ping"} for i in range(3)]
        m.run_check = lambda h, t: (False, None, "timeout")
        m.watch_arp_conflicts = lambda: None
        self.dispatched = []
        m.dispatch_alerts = lambda evs: self.dispatched.extend(evs)
        m.CONFIG["fail_threshold"] = 1
        m.CONFIG["alerts"]["hold_down_seconds"] = 0

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_one_bad_host_does_not_drop_the_others(self):
        m = self.m
        real = m.process_result

        def flaky(h, up, lat, err):
            if h["id"] == "h1":
                raise RuntimeError("database is locked")
            return real(h, up, lat, err)
        m.process_result = flaky
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(4) as pool:
            m.monitor_cycle(pool)
        self.assertEqual(sorted(e["host"]["id"] for e in self.dispatched), ["h0", "h2"])


class HousekeepingTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_prune(self):
        m = self.m
        now = time.time()
        old, fresh = now - 20 * 86400, now - 3600
        m.db_event("h", now - 500 * 86400, "down")
        m.db_event("h", fresh, "down")
        with m._db_lock:
            for bssid, seen in (("old", old), ("new", fresh)):
                m._db.execute("INSERT INTO wifi_seen VALUES (?,?,?,0,0,'','',?,?,1)",
                              (bssid, "unifi:1", "s", seen, seen))
            m._db.execute("INSERT INTO wifi_sensors VALUES ('dead', ?)", (old,))
            m._db.commit()
        m.db_prune()
        q = lambda sql: m._db.execute(sql).fetchone()[0]
        self.assertEqual(q("SELECT COUNT(*) FROM events"), 1)
        self.assertEqual(q("SELECT GROUP_CONCAT(bssid) FROM wifi_seen"), "new")
        self.assertEqual(q("SELECT COUNT(*) FROM wifi_sensors"), 0)


if __name__ == "__main__":
    unittest.main()
