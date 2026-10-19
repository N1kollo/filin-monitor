"""v0.47.2: degradation must recover. 10-13/14: four hosts got a short night
spike (median ~15 ms vs 2 ms) and stayed 🐢 for 14+ hours at 1 ms — the
"below the floor, don't judge" check ran before the recovery branch."""
import time
import unittest

from harness import cleanup, load_monitor


class DegradationTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.CONFIG["hosts"] = [{"id": "s08", "name": "S08", "host": "192.168.1.24", "type": "host"}]
        m.reconcile_state()
        with m.STATE_LOCK:
            m.STATE["s08"]["status"] = "up"
        self.cur = [15.0]
        m.get_baseline = lambda hid, hours, until: (2.0, 500)
        m.db_median_latency = lambda hid, since, until=None: (self.cur[0], 20)
        m.CONFIG["degradation"]["confirm_passes"] = 3     # short for the scenarios below

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def passes(self, n):
        out = []
        for _ in range(n):
            out.append(self.m.evaluate_degradation())
        return out

    def test_spike_then_recovery(self):
        m = self.m
        res = self.passes(3)
        self.assertEqual([r[0] for r in res[:2]], [[], []], "not on the first passes")
        self.assertEqual([e["host"]["id"] for e in res[2][0]], ["s08"], "15 ms vs 2 ms, held -> degraded")
        self.cur[0] = 1.3                       # the spike is over
        newly, rec = m.evaluate_degradation()
        self.assertEqual([e["host"]["id"] for e in rec], ["s08"], "was stuck here forever")
        self.assertNotIn("s08", m.DEGRADED)

    def test_one_minute_spike_is_silent(self):
        """10-14 15:41/15:42: «ДЕГРАДАЦИЯ 1.26» then «НОРМА» a minute later."""
        m = self.m
        m.evaluate_degradation()                # spike seen once
        self.cur[0] = 1.6
        newly, rec = m.evaluate_degradation()   # gone next pass
        self.cur[0] = 15.0
        m.evaluate_degradation()                # another single blip: counter restarted
        self.assertEqual(m.DEGRADED, {}, "never announced, nothing to recover from")

    def test_hysteresis_kept_above_floor(self):
        m = self.m
        self.passes(3)
        self.cur[0] = 14.0                      # still 7x, just under the 15 ms entry floor
        newly, rec = m.evaluate_degradation()
        self.assertEqual(rec, [], "near the threshold it does not flap out")
        self.cur[0] = 4.0                       # 2x — well below 0.8 x 3
        newly, rec = m.evaluate_degradation()
        self.assertEqual(len(rec), 1)

    def test_default_needs_ten_minutes(self):
        """10-15 10:31 ДЕГРАДАЦИЯ S08 -> 10:33 НОРМА: 3 passes let a 5-min spike through."""
        m = self.m
        m.CONFIG["degradation"].pop("confirm_passes")
        res = self.passes(9)
        self.assertTrue(all(r[0] == [] for r in res), "9 minutes of spike: still silent")
        self.assertEqual(len(m.evaluate_degradation()[0]), 1, "10th pass: announced")

    def test_floor_still_guards_entry(self):
        m = self.m
        self.cur[0] = 8.0                       # 4x of 2 ms but under 15 ms: LAN noise
        newly, rec = m.evaluate_degradation()
        self.assertEqual((newly, rec), ([], []))


if __name__ == "__main__":
    unittest.main()
