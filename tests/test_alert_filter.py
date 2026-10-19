"""tg_sent journal, explicit alert kinds (emit), kind filter and /mute."""
import json
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram


class AlertFilterTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m, lambda meth, p: 400 if "fail" in p.get("text", "") else 0)
        self.m.CONFIG["hosts"] = [{"id": "ab12cd34", "name": "srv-a"}]

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_journal_records_kind(self):
        m = self.m
        m.emit("down", "storm digest")
        m.emit("escalation", "esc", markup="{}")
        m.tg_send_to(1, "status")          # bot reply: attributed to its caller
        m.tg_api("getUpdates", {})
        kinds = {k["kind"] for k in m.db_tg_sent_stats(1)["by_kind"]}
        self.assertTrue({"down", "escalation"} <= kinds)
        self.assertEqual(m.db_tg_sent_stats(1)["total"], 3, "getUpdates is not a send")

    def test_failed_send_recorded(self):
        ok, _ = self.m.emit("dhcp", "fail rogue")
        self.assertFalse(ok)
        st = self.m.db_tg_sent_stats(1)
        self.assertEqual((st["failed"], st["muted"]), (1, 0))

    def test_kind_mute_cycle(self):
        m = self.m
        m.emit("dhcp", "rogue dhcp")
        kb = json.loads(self.calls[-1][1]["reply_markup"])
        self.assertEqual(kb["inline_keyboard"][0][0]["callback_data"], "flt:q:dhcp")
        m.emit("down", "down")
        self.assertNotIn("reply_markup", self.calls[-1][1], "host down is never kind-muted")
        m.emit("system", "startup")
        self.assertNotIn("reply_markup", self.calls[-1][1])

        m.handle_filter_callback({"id": "c"}, "42", {"message_id": 7}, "flt:q:dhcp")
        self.assertEqual(self.calls[-1][0], "answerCallbackQuery")
        self.assertFalse(any(c[0] == "editMessageText" for c in self.calls), "alert text kept")
        n = len(self.calls)
        self.assertEqual(m.emit("dhcp", "rogue dhcp"), (True, "muted"))
        self.assertEqual(len(self.calls), n)
        m.emit("wifi", "wifi")
        self.assertEqual(len(self.calls), n + 1)
        with open(m.CONFIG_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertIn("dhcp", saved["alerts"]["muted_kinds"], "mute survives restart")
        self.assertEqual(m.db_tg_sent_stats(1)["muted"], 1)

        m.CONFIG["alerts"]["muted_kinds"]["dhcp"] = time.time() - 1
        self.assertFalse(m.kind_muted("dhcp"), "expired mute lifts")

    def test_menu(self):
        m = self.m
        m.handle_filter_callback({"id": "c"}, "42", {"message_id": 9}, "flt:s:wifi:0")
        self.assertEqual(m.CONFIG["alerts"]["muted_kinds"]["wifi"], 0)
        self.assertIn("Wi-Fi — 🔕 пока не включишь", self.calls[-2][1]["text"])
        m.handle_filter_callback({"id": "c"}, "42", {"message_id": 9}, "flt:s:wifi:-1")
        self.assertFalse(m.kind_muted("wifi"))

        m.set_mute("muted_hosts", "ab12cd34", 3600)
        text, kb = m.filter_view()
        self.assertIn("srv-a", text)
        self.assertIn("flt:uh:ab12cd34", kb)
        m.set_mute("muted_kinds", "wan", 60)
        m.handle_filter_callback({"id": "c"}, "42", {"message_id": 9}, "flt:all")
        self.assertFalse(m.kind_muted("wan") or m.is_muted("ab12cd34"))

    def test_callback_data_limits(self):
        m = self.m
        m.set_mute("muted_kinds", "netdiff", 60)
        views = [m.filter_view()] + [m.filter_kind_view(k) for k in m.ALERT_KINDS]
        sizes = [len(b["callback_data"].encode()) for _, kb in views
                 for row in json.loads(kb)["inline_keyboard"] for b in row]
        self.assertLessEqual(max(sizes), 64, "Telegram rejects callback_data > 64 bytes")


if __name__ == "__main__":
    unittest.main()
