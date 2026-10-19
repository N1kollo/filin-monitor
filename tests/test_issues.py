"""v0.51.1: standing problems on the Overview, «принято», and browser hang-ups
are not errors in the log."""
import io
import sys
import time
import unittest

from harness import cleanup, load_monitor


class IssuesTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [
            {"id": "old", "name": "Старый", "host": "10.10.1.5", "type": "ping"},
            {"id": "new", "name": "Свежий", "host": "10.10.1.6", "type": "ping"},
            {"id": "off", "name": "Касса", "host": "10.10.1.2", "type": "ping", "enabled": False},
        ]
        m.reconcile_state()
        now = time.time()
        with m.STATE_LOCK:
            m.STATE["old"].update(status="down", since=now - 3 * 3600)
            m.STATE["new"].update(status="down", since=now - 300)
        m.CONFIG["unifi"] = {"ap_quiet": {"from": "18:55", "to": "07:55"}}
        m._UNIFI_DOWN.add("3-1")
        m.UNIFI_AP_LOG[str(int(now - 2 * 86400))] = {"kind": "down", "names": ["3-1"]}
        m._WIFI_ALERTED["rdn:e4:c3:2a:00:01:5e"] = now - 86400
        with m._db_lock:
            m._db.execute("INSERT INTO wifi_seen VALUES ('e4:c3:2a:00:01:5e','unifi:1-1','mesh-2',50,1,'','',?,?,1)",
                          (now - 9e5, now - 9e4))
            m._db.commit()
        m.ap_quiet_now = lambda lt=None: False

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def keys(self):
        return [i["key"] for i in self.m.standing_issues()]

    def test_what_counts(self):
        issues = {i["key"]: i for i in self.m.standing_issues()}
        self.assertIn("host:old", issues, "down 3 h")
        self.assertNotIn("host:new", issues, "down 5 min is an event, not a standing problem")
        self.assertNotIn("host:off", issues, "disabled check (the cash register) is not a problem")
        self.assertEqual(issues["ap:3-1"]["title"], "точка UniFi «3-1» не на связи")
        self.assertIn("mesh-2", issues["node:e4:c3:2a:00:01:5e"]["title"])

    def test_night_window_hides_aps(self):
        self.m.ap_quiet_now = lambda lt=None: True
        self.assertNotIn("ap:3-1", self.keys(), "9 APs dark at night are planned, not a problem")

    def test_ack_and_auto_forget(self):
        m = self.m
        m.ack_issue("host:old")
        old = next(i for i in m.standing_issues() if i["key"] == "host:old")
        self.assertTrue(old["acked"])
        self.assertEqual(m.standing_issues()[-1]["key"], "host:old", "acked go to the end")
        with m.STATE_LOCK:
            m.STATE["old"]["status"] = "up"          # fixed
        m.standing_issues()
        self.assertNotIn("host:old", m.CONFIG.get("acked_issues", {}),
                         "the ack dies with the problem — a new outage shows up un-acked")
        m.ack_issue("ap:3-1")
        m.ack_issue("ap:3-1", on=False)
        self.assertFalse(next(i for i in m.standing_issues() if i["key"] == "ap:3-1")["acked"])


class HangupTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def handle(self, exc):
        srv = self.m.MonitorHTTPServer(("127.0.0.1", 0), self.m.Handler)
        buf, real = io.StringIO(), sys.stderr
        sys.stderr = buf
        try:
            try:
                raise exc
            except Exception:
                srv.handle_error(None, ("127.0.0.1", 1))
        finally:
            sys.stderr = real
            srv.server_close()
        return buf.getvalue()

    def test_browser_hangup_is_silent(self):
        """10-14 17:30: a closed tab = 13 ERROR lines, the only «error» in the office log."""
        self.assertEqual(self.handle(ConnectionAbortedError(10053, "aborted")), "")
        self.assertEqual(self.handle(ConnectionResetError(10054, "reset")), "")
        self.assertEqual(self.handle(BrokenPipeError()), "")

    def test_real_error_still_logged(self):
        self.assertIn("ValueError", self.handle(ValueError("real bug")))


if __name__ == "__main__":
    unittest.main()
