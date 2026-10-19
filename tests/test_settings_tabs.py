"""v0.51: settings regrouped (Алерты / Автоматика / Система), monitor log in the
dashboard, kind list for the filter. The restructure must not lose a field."""
import os
import re
import unittest

from harness import ROOT, cleanup, load_monitor


class LogTailTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.path = os.path.join(self.tmp, "monitor.log")

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def write(self, lines):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def test_tail_and_errors(self):
        self.write([f"2026-10-15 10:00:{i:02d},000 INFO [netscan] авто-скан: живых {i}" for i in range(50)]
                   + ["2026-10-15 10:01:00,000 INFO [wan] cycle error: database is locked",
                      "2026-10-15 10:01:01,000 ERROR поток wan_loop умер",
                      "2026-10-15 10:01:02,000 INFO [telegram] алерт не отправлен: 502"])
        d = self.m.log_tail(5, path=self.path)
        self.assertEqual(len(d["lines"]), 5)
        self.assertTrue(d["lines"][-1].endswith("502"))
        errs = self.m.log_tail(300, errors_only=True, path=self.path)["lines"]
        self.assertEqual(len(errs), 3, "error, thread death, undelivered alert — not the netscan chatter")

    def test_missing_log(self):
        d = self.m.log_tail(10, path=os.path.join(self.tmp, "nope.log"))
        self.assertEqual(d["lines"], [])
        self.assertIn("не найден", d["note"])

    def test_big_log_reads_only_the_tail(self):
        self.write(["x" * 200] * 6000 + ["last line"])      # ~1.2 MB
        d = self.m.log_tail(3, path=self.path)
        self.assertEqual(d["lines"][-1], "last line")
        self.assertNotIn("", d["lines"][:1], "first (possibly cut) line is dropped")


class SettingsMarkupTest(unittest.TestCase):
    """Static checks on dashboard.html after the regrouping."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8") as f:
            cls.h = f.read()

    def pane(self, pid):
        i = self.h.index(f'id="pane-{pid}"')
        j = self.h.find('<div class="pane', i + 10)
        return self.h[i:j if j > 0 else None]

    def test_tabs_and_panes_match(self):
        tabs = re.findall(r'data-tab="([a-z]+)" onclick="switchTab', self.h)
        panes = re.findall(r'class="pane[^"]*" id="pane-([a-z]+)"', self.h)
        self.assertEqual(tabs, ["hosts", "subnets", "alerts", "sched", "tg", "gen"])
        self.assertEqual(sorted(tabs), sorted(panes))

    def test_alert_policy_lives_in_one_tab(self):
        a = self.pane("alerts")
        for field in ("q-enabled", "g-hold", "g-storm", "g-esc-min", "dg-enabled", "mw-hosts", "ax-kinds", "ax-ap-from"):
            self.assertIn(f'id="{field}"', a, field)
        self.assertIn('onclick="saveSettings()"', a, "hold/storm/escalation save from here")

    def test_system_tab(self):
        g = self.pane("gen")
        for field in ("g-name", "g-interval", "auth-user", "wan-gw", "hb-url", "log-pre"):
            self.assertIn(f'id="{field}"', g, field)
        self.assertIn('onclick="saveSettings()"', g, "general settings got their own save button")
        self.assertNotIn('id="g-hold"', g, "hold-down moved to Алерты")

    def test_automation_tab(self):
        s = self.pane("sched")
        self.assertIn('id="rb-enabled"', s)
        self.assertNotIn('id="mw-hosts"', s, "maintenance windows moved to Алерты")

    def test_every_field_once(self):
        ids = re.findall(r'id="([^"]+)"', self.h)
        self.assertEqual(len(ids), len(set(ids)), "duplicate element ids after the move")


class SilenceKindsTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_kinds_listed(self):
        kinds = self.m.silence_view()["kinds"]
        self.assertIn("wifi", kinds)
        self.assertNotIn("down", kinds, "host downs are not kind-mutable")


if __name__ == "__main__":
    unittest.main()
