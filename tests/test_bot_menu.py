"""v0.46: button-driven bot — menu, host cards, maintenance, noise, /who."""
import json
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram

OWNER = "42"


class BotMenuTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        m.CONFIG["hosts"] = [
            {"id": "h1", "name": "1С Торговля", "host": "192.168.1.20", "type": "host",
             "priority": "critical", "mac": "00:15:5d:00:02:03"},
            {"id": "h2", "name": "Прокси <proxy>", "host": "192.168.1.4", "type": "host"},
        ]
        m.reconcile_state()
        with m.STATE_LOCK:
            m.STATE["h1"].update(status="up", latency=1.3)
            m.STATE["h2"].update(status="down", error="timeout")
        m.db_event("h2", time.time() - 600, "down", "timeout")
        m.run_check = lambda h, t: (True, 2.0, None)
        m.send_wol = lambda *a: None

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def tap(self, data, text=""):
        n = len(self.calls)
        self.m.handle_update({"update_id": 1, "callback_query": {
            "id": "c", "data": data, "message": {"chat": {"id": int(OWNER)}, "message_id": 5, "text": text}}})
        return self.calls[n:]

    def say(self, text):
        n = len(self.calls)
        self.m.handle_update({"update_id": 1, "message": {"chat": {"id": int(OWNER)}, "text": text}})
        return self.calls[n:]

    def screen(self, calls):
        c = [c for c in calls if c[0] in ("editMessageText", "sendMessage")]
        self.assertTrue(c, "a screen was rendered")
        return c[-1][1]["text"], json.loads(c[-1][1].get("reply_markup") or '{"inline_keyboard": []}')

    def buttons(self, kb):
        return [b["callback_data"] for row in kb["inline_keyboard"] for b in row]

    # ---------------------------------------------------------------- crawl
    def test_every_button_on_every_screen_works(self):
        m = self.m
        m.set_mute("muted_hosts", "h1", 3600)
        m.set_maint("*", 1800)
        m.set_maint("h2", 1800)
        m.emit("wifi", "x")
        # Navigation screens (m:*) plus the filter screens (flt:l, flt:k:*).
        # m:mg (network maintenance) and m:rg (recovery = real WoL) are actions, not screens
        nav = lambda d: d.startswith(("m:", "flt:l", "flt:k:")) and not d.startswith(("m:mg", "m:rg", "m:ug"))
        seen, todo = set(), ["m:menu"]
        while todo:
            data = todo.pop()
            if data in seen or not nav(data):
                continue
            seen.add(data)
            self.assertLessEqual(len(data.encode()), 64, data)
            out = self.tap(data)
            self.assertTrue(any(c[0] == "answerCallbackQuery" for c in out), data)
            text, kb = self.screen(out)
            btns = self.buttons(kb)
            # 10-14: the filter screen was a dead end on the phone
            self.assertTrue({"m:menu", "m:hl", "flt:l"} & set(btns), f"no way back from {data}")
            for b in btns:
                self.assertLessEqual(len(b.encode()), 64, b)
                todo.append(b)
        for must in ("m:st", "m:dn", "m:hl", "m:h:h1", "m:h:h2", "m:mt", "m:nz", "m:wk", "m:rv",
                     "flt:l", "flt:k:wifi"):
            self.assertIn(must, seen)

    # ---------------------------------------------------------------- screens
    def test_menu_and_start(self):
        text, kb = self.screen(self.say("/start"))
        self.assertIn("🟢 1", text)
        self.assertIn("m:hl", self.buttons(kb))

    def test_host_card(self):
        text, kb = self.screen(self.tap("m:h:h2"))
        self.assertIn("Прокси &lt;proxy&gt;", text, "names are HTML-escaped")
        self.assertIn("лежит", text)
        self.assertIn("🔴 упал", text)
        self.assertNotIn("wake:h2", self.buttons(kb), "no MAC -> no wake button")
        text, kb = self.screen(self.tap("m:h:h1"))
        self.assertIn("🔥 критичный", text)
        self.assertIn("wake:h1", self.buttons(kb))

    def test_card_actions(self):
        m = self.m
        out = self.tap("m:rc:h1")
        note = [c for c in out if c[0] == "answerCallbackQuery"][-1][1]
        self.assertIn("отвечает (2 мс)", note["text"])
        self.tap("m:mu:h1")
        self.assertTrue(m.is_muted("h1"))
        text, kb = self.screen(self.tap("m:h:h1"))
        self.assertIn("m:um:h1", self.buttons(kb))
        self.tap("m:um:h1")
        self.assertFalse(m.is_muted("h1"))
        self.tap("m:mh:h1")
        self.assertTrue(m.in_maintenance(m.CONFIG["hosts"][0]))
        self.tap("m:mxh:h1")
        self.assertFalse(m.in_maintenance(m.CONFIG["hosts"][0]))

    def test_alert_buttons_open_new_message(self):
        kb = json.loads(self.m.down_keyboard(self.m.CONFIG["hosts"][1]))
        datas = self.buttons(kb)
        self.assertIn("m:h:h2:n", datas)
        self.assertIn("m:mh:h2:n", datas)
        out = self.tap("m:h:h2:n")
        self.assertIn("sendMessage", [c[0] for c in out])
        self.assertNotIn("editMessageText", [c[0] for c in out], "the alert text is kept")

    def test_global_maintenance(self):
        m = self.m
        self.tap("m:mg:3600")
        self.assertTrue(m.maint_until("*"))
        h = m.CONFIG["hosts"][1]
        self.assertEqual(m.emit("down", "x", host=h), (True, "maintenance"))
        self.assertEqual(m.emit("wifi", "w")[1], "ok", "network-wide ≠ Wi-Fi/security")
        text, kb = self.screen(self.tap("m:mt"))
        self.assertIn("Вся сеть", text)
        self.tap("m:mx:*")
        self.assertFalse(m.maint_until("*"))

    def test_maintenance_expires(self):
        m = self.m
        m.CONFIG["maint_until"] = {"*": time.time() - 1}
        self.assertFalse(m.in_maintenance(m.CONFIG["hosts"][0]))

    def test_noise(self):
        m = self.m
        for _ in range(3):
            m.emit("wifi", "w")
        m.emit("down", "d")
        text, kb = self.screen(self.tap("m:nz"))
        self.assertIn("отправлено 4", text)
        self.assertIn("📶 Wi-Fi", text)
        self.assertIn("flt:k:wifi", self.buttons(kb))
        self.assertNotIn("flt:k:down", self.buttons(kb), "host downs are not kind-mutable")

    def test_who(self):
        m = self.m
        m.network_diff({"192.168.1.20": "00:15:5d:00:02:03", "192.168.100.137": "b6:72:2e:00:d0:76"})
        text = [c for c in self.say("/who 192.168.1.20") if c[0] == "sendMessage"][-1][1]["text"]
        self.assertIn("в мониторинге как <b>1С Торговля</b>", text)
        text = [c for c in self.say("/who B6-72-2E-00-D0-76") if c[0] == "sendMessage"][-1][1]["text"]
        self.assertIn("192.168.100.137", text)
        self.assertIn("случайный", text)
        text = [c for c in self.say("/who 10.9.9.9") if c[0] == "sendMessage"][-1][1]["text"]
        self.assertIn("ничего не знаю", text)

    def test_stranger_gets_nothing(self):
        n = len(self.calls)
        self.m.handle_update({"update_id": 1, "callback_query": {
            "id": "c", "data": "m:mg:14400", "message": {"chat": {"id": 777}, "message_id": 1}}})
        self.assertFalse(self.m.maint_until("*"), "only the owner can silence the network")
        self.assertEqual([c[0] for c in self.calls[n:]], ["answerCallbackQuery"])

    def test_commands_registered(self):
        self.m.bot_register_commands()
        cmds = json.loads([c for c in self.calls if c[0] == "setMyCommands"][-1][1]["commands"])
        names = {c["command"] for c in cmds}
        self.assertTrue({"menu", "hosts", "maint", "noise", "who", "mute"} <= names)


if __name__ == "__main__":
    unittest.main()
