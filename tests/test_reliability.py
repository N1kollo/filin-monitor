"""v0.43: the monitor must not go blind silently."""
import logging
import os
import sys
import threading
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram


class _Stop(BaseException):
    """Breaks a `while True` loop out of a patched time.sleep. BaseException so
    the loops' own `except Exception` guards don't swallow it."""


def sleeps_then_stop(m, allowed):
    log = []

    def fake(sec):
        log.append(sec)
        if len(log) > allowed:
            raise _Stop()
    m.time.sleep = fake
    return log


class ReliabilityTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real_sleep = self.m.time.sleep

    def tearDown(self):
        self.m.time.sleep = self.real_sleep
        cleanup(self.m, self.tmp)

    # --- heartbeat vouches only for a live check cycle
    def test_cycle_stale(self):
        m = self.m
        m.CONFIG["check_interval_seconds"] = 30
        now = time.time()
        m.LAST_CYCLE["ts"] = now - 60
        self.assertEqual(m.cycle_stale(now), 0)
        m.LAST_CYCLE["ts"] = now - 600
        self.assertAlmostEqual(m.cycle_stale(now), 600, delta=1)
        m.LAST_CYCLE["ts"] = 0.0
        m.STARTED_AT = now - 30
        self.assertEqual(m.cycle_stale(now), 0, "fresh start gets a grace period")
        m.STARTED_AT = now - 900
        self.assertGreater(m.cycle_stale(now), 0, "never completed a cycle = stuck")

    def _run_heartbeat_once(self):
        m = self.m
        m.CONFIG["heartbeat"] = {"enabled": True, "url": "http://hc.test/x", "interval_minutes": 5}
        pings = []
        m.ping_heartbeat = lambda url: pings.append(url) or (True, "ok")
        sleeps_then_stop(m, 0)
        with self.assertRaises(_Stop):
            m.heartbeat_loop()
        return pings

    def test_heartbeat_held_when_cycle_stuck(self):
        self.m.LAST_CYCLE["ts"] = time.time() - 3600
        self.assertEqual(self._run_heartbeat_once(), [])
        self.assertFalse(self.m.HEARTBEAT_STATE["ok"])
        self.assertIn("пинг придержан", self.m.HEARTBEAT_STATE["detail"])

    def test_heartbeat_pings_when_cycle_alive(self):
        self.m.LAST_CYCLE["ts"] = time.time()
        self.assertEqual(self._run_heartbeat_once(), ["http://hc.test/x"])

    # --- escalation is not marked done unless a message left
    def _escalation_setup(self, fail):
        m = self.m
        calls = stub_telegram(m, lambda meth, p: fail[0])
        m.CONFIG["alerts"]["escalate_after_minutes"] = 5
        m.CONFIG["hosts"] = [{"id": "h1", "name": "kassa", "host": "10.0.0.2",
                              "type": "ping", "priority": "critical"}]
        with m.STATE_LOCK:
            m.STATE["h1"] = {"status": "down"}
        m.ESCALATE["h1"] = {"since": time.time() - 600, "done": False}
        return calls

    def test_escalation_retries_after_rejected_send(self):
        fail = [400]
        calls = self._escalation_setup(fail)
        self.assertEqual(self.m.check_escalations(), [])
        self.assertFalse(self.m.ESCALATE["h1"]["done"], "rejected send must not count")
        fail[0] = 0
        self.assertEqual(self.m.check_escalations(), ["h1"])
        self.assertTrue(self.m.ESCALATE["h1"]["done"])
        self.assertEqual(self.m.check_escalations(), [], "sent once, not every cycle")
        self.assertEqual(sum(1 for c in calls if c[0] == "sendMessage"), 2)

    def test_escalation_queued_on_dead_link(self):
        fail = [True]
        self._escalation_setup(fail)
        self.assertEqual(self.m.check_escalations(), ["h1"],
                         "in the outbox = will be delivered; re-sending would duplicate")
        self.assertEqual(self.m._db.execute("SELECT COUNT(*) FROM tg_outbox").fetchone()[0], 1)

    def test_escalation_second_chat_counts(self):
        m = self.m
        self._escalation_setup([False])
        m.CONFIG["alerts"]["escalate_chat_id"] = "777"
        m._tg_call = lambda meth, p, t: ((None, "502") if p.get("chat_id") == "42"
                                         else ({"ok": True}, None))
        self.assertEqual(m.check_escalations(), ["h1"],
                         "the backup human got it — that is a delivered escalation")

    # --- one exception must not end WAN alerting
    def test_wan_loop_survives_exception(self):
        m = self.m
        steps = []

        def step(prev, down_since):
            steps.append(1)
            if len(steps) == 1:
                raise RuntimeError("database is locked")
            raise _Stop()
        m._wan_step = step
        log = sleeps_then_stop(m, 5)
        with self.assertRaises(_Stop):
            m.wan_loop()
        self.assertEqual(len(steps), 2, "loop kept going after the error")
        self.assertEqual(log, [20, 60], "startup settle, then back-off after error")

    def test_wifi_loop_waits_before_judging(self):
        m = self.m
        evals = []
        m.wifi_evaluate = lambda: evals.append(1)
        m.CONFIG["wifi"] = {"enabled": True}
        log = sleeps_then_stop(m, 0)
        with self.assertRaises(_Stop):
            m.wifi_loop()
        self.assertEqual((log, evals), ([90], []), "no evaluate before the grace sleep")

    # --- print() and dead threads land in a rotating log file
    def test_logging(self):
        m = self.m
        saved = sys.stdout, sys.stderr, threading.excepthook
        path = os.path.join(self.tmp, "logs", "monitor.log")
        try:
            log = m.setup_logging(path)
            print("[wifi] eval error: boom")
            sys.stdout.write("partial ")
            sys.stdout.write("line\n")
            t = threading.Thread(target=lambda: 1 / 0, name="wan_loop")
            t.start(); t.join()
            for h in log.handlers:
                h.flush()
        finally:
            sys.stdout, sys.stderr, threading.excepthook = saved
            for h in logging.getLogger("ssd").handlers:
                h.close()
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("INFO [wifi] eval error: boom", text)
        self.assertIn("INFO partial line", text)
        self.assertIn("поток wan_loop умер", text)
        self.assertIn("ZeroDivisionError", text)


if __name__ == "__main__":
    unittest.main()
