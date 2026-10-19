"""v0.42.1: Wi-Fi dedup survives restart; vanished nodes are one message."""
import time
import unittest

from harness import cleanup, load_monitor


def gone(bssid, sensor, ssid):
    return {"type": "radiogone", "key": f"rd:{bssid}:{sensor}", "bssid": bssid,
            "sensor": sensor, "ssid": ssid, "detail": "d"}


ALERTS = [gone("aa", "unifi:1-3", "mesh-5"), gone("aa", "unifi:2-4", "mesh-5"),
          gone("aa", "unifi:3-2", "mesh-5"), gone("bb", "unifi:2-4", "mesh-2"),
          gone("bb", "unifi:1-3", "mesh-2"),
          {"type": "eviltwin", "key": "et:cc", "bssid": "cc", "sensor": "netsh-1", "detail": "evil"}]


class WifiAlertsTest(unittest.TestCase):
    def boot(self, tmp=None):
        m, tmp = load_monitor(tmp, name=f"m_{time.time_ns()}")
        sent = []
        m.emit = lambda kind, t, **kw: sent.append(t) or (True, "ok")
        now = time.time()
        with m._db_lock:
            m._db.execute("INSERT OR REPLACE INTO wifi_seen VALUES "
                          "('x','unifi:1',NULL,0,0,'','',?,?,1)", (now - 1e6, now))
            # a sensor reporting "far into the future" stays fresh for any test clock
            m._db.execute("INSERT OR REPLACE INTO wifi_sensors VALUES ('unifi:1', ?)", (now + 1e6,))
            m._db.commit()
        return m, tmp, sent

    def setUp(self):
        self.m, self.tmp, self.sent = self.boot()
        self.m.wifi_detect = lambda *a: list(ALERTS)

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_grouping(self):
        self.m.wifi_evaluate()
        self.assertEqual(len(self.sent), 2, "5 radiogone -> 1 message, + evil twin")
        g = [t for t in self.sent if "пропали" in t][0]
        self.assertIn("2 нод", g)
        self.assertEqual(g.count("•"), 2)
        self.assertIn("unifi:1-3, unifi:2-4, unifi:3-2", g)
        self.m.wifi_evaluate()
        self.assertEqual(len(self.sent), 2, "standing conditions stay silent")

    def test_restart_is_silent_and_rearm_works(self):
        self.m.wifi_evaluate()
        self.m._db.close()
        m2, _, sent2 = self.boot(self.tmp)
        self.m = m2
        m2.wifi_detect = lambda *a: list(ALERTS)
        m2.wifi_evaluate()
        self.assertEqual(sent2, [], "restart must not replay standing alerts")

        t = time.time()
        self.seen(m2, "aa", t + m2.WIFI_REARM_SECONDS)   # the node is really back in the air
        m2.wifi_detect = lambda *a: [a for a in ALERTS if a["bssid"] != "aa"]
        m2.wifi_evaluate(t)
        m2.wifi_evaluate(t + m2.WIFI_REARM_SECONDS)
        keys = {r[0] for r in m2._db.execute("SELECT key FROM wifi_alerted")}
        self.assertNotIn("rdn:aa", keys)
        m2.wifi_detect = lambda *a: list(ALERTS)
        m2.wifi_evaluate(t + 700)
        self.assertEqual(len(sent2), 1)
        self.assertIn("1 нода", sent2[0])
        self.assertNotIn("bb", sent2[0])

        for b in ("aa", "bb", "cc"):
            self.seen(m2, b, t + 800 + m2.WIFI_REARM_SECONDS)
        m2.wifi_detect = lambda *a: []
        m2.wifi_evaluate(t + 800)
        m2.wifi_evaluate(t + 800 + m2.WIFI_REARM_SECONDS)
        self.assertEqual(m2._db.execute("SELECT COUNT(*) FROM wifi_alerted").fetchone()[0], 0)

    def seen(self, m, bssid, ts):
        with m._db_lock:
            m._db.execute("INSERT OR REPLACE INTO wifi_seen VALUES (?, 'unifi:1-1', 'imp', 50, 1, '', '', ?, ?, 1)",
                          (bssid, ts - 1e5, ts))
            m._db.commit()

    def test_sensors_dark_overnight_no_morning_repeat(self):
        """10-15 07:23: APs (= sensors) off at night -> "gone" unobservable ->
        counted as fixed -> the same mesh-2/mesh-5 re-announced every morning."""
        m, t = self.m, time.time()
        m.wifi_evaluate(t)
        n = len(self.sent)
        with m._db_lock:                                    # night: APs off, sensors go stale
            m._db.execute("UPDATE wifi_sensors SET last_report=?", (t,))
            m._db.commit()
        m.wifi_detect = lambda *a: []                       # nothing observable
        m.wifi_evaluate(t + 3600)
        m.wifi_evaluate(t + 9 * 3600)
        with m._db_lock:                                    # 07:23: APs back
            m._db.execute("UPDATE wifi_sensors SET last_report=?", (t + 12 * 3600,))
            m._db.commit()
        m.wifi_detect = lambda *a: list(ALERTS)             # nodes (and the twin) still there
        m.wifi_evaluate(t + 12 * 3600)
        self.assertEqual(len(self.sent), n, "same dead nodes are not news")

    def test_ap_returning_later_is_not_a_new_alert(self):
        """10-15 09:33: AP 1-3 rejoined later and re-announced mesh-2 «— unifi:1-3»."""
        m, t = self.m, time.time()
        m.wifi_evaluate(t)
        n = len(self.sent)
        m.wifi_detect = lambda *a: list(ALERTS) + [gone("aa", "unifi:1-9", "mesh-5")]
        m.wifi_evaluate(t + 7200)
        self.assertEqual(len(self.sent), n)

    def test_old_per_sensor_keys_migrate_silently(self):
        m = self.m
        with m._db_lock:
            m._db.executemany("INSERT INTO wifi_alerted (key, ts) VALUES (?, ?)",
                              [("rd:aa:unifi:1-3", 1.0), ("rd:bb:unifi:2-4", 1.0)])
            m._db.commit()
        # ALERTS use short fake bssids; real ones have 6 colon parts — test the parser too
        self.assertEqual(m._node_key("rd:e4:c3:2a:00:01:5e:unifi:1-1"), "rdn:e4:c3:2a:00:01:5e")
        self.assertEqual(m._node_key("sensor:x"), "sensor:x")

    def test_flapping_node_alerts_once(self):
        m, t = self.m, time.time()
        m.wifi_evaluate(t)
        n = len(self.sent)
        for i in range(1, 6):                     # flickers back for one pass each time
            m.wifi_detect = lambda *a: [a for a in ALERTS if a["bssid"] != "aa"]
            m.wifi_evaluate(t + i * 120)
            m.wifi_detect = lambda *a: list(ALERTS)
            m.wifi_evaluate(t + i * 120 + 60)
        self.assertEqual(len(self.sent), n, "mesh-2 case: 2 alerts in 2 min -> none")

    def test_escape(self):
        self.assertIn("&lt;x&gt;", self.m.fmt_radiogone([gone("dd", "unifi:1", "<x>")]))


if __name__ == "__main__":
    unittest.main()
