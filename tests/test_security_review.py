"""v0.58.1: three holes from the security review before publishing the code.
- a hostile SSID broke the Telegram HTML and silenced the alert about itself;
- with the panel password off, any web page open on a LAN PC could drive the API;
- the SYSTEM monitor would smoke-test (= run) an exe any local account dropped in Downloads."""
import http.client
import json
import os
import threading
import time
import unittest

from harness import cleanup, load_monitor


class TelegramPlainFallbackTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = []

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def fake(self, refuse_html):
        def post(method, params, timeout):
            self.calls.append(dict(params))
            if refuse_html and params.get("parse_mode"):
                return None, "Telegram API 400: Bad Request: can't parse entities: Unclosed start tag at byte offset 40"
            return {"ok": True}, None
        self.m._tg_post = post

    def test_bad_markup_goes_again_as_plain_text(self):
        self.fake(refuse_html=True)
        res, err = self.m._tg_call("sendMessage", {"chat_id": "1", "parse_mode": "HTML",
                                                   "text": "📡 <b>Wi-Fi</b>\nНовая точка «<b» &amp; co"}, 5)
        self.assertIsNone(err)
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("parse_mode", self.calls[1])
        self.assertEqual(self.calls[1]["text"], "📡 Wi-Fi\nНовая точка «<b» & co")

    def test_good_markup_is_sent_once(self):
        self.fake(refuse_html=False)
        self.m._tg_call("sendMessage", {"chat_id": "1", "parse_mode": "HTML", "text": "<b>ok</b>"}, 5)
        self.assertEqual(len(self.calls), 1)

    def test_other_errors_are_not_retried_as_plain(self):
        def post(method, params, timeout):
            self.calls.append(params)
            return None, "Telegram API 403: Forbidden: bot was blocked by the user"
        self.m._tg_post = post
        self.assertIsNotNone(self.m._tg_call("sendMessage", {"parse_mode": "HTML", "text": "x"}, 5)[1])
        self.assertEqual(len(self.calls), 1)


class WifiSsidEscapedTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.sent = []
        m.emit = lambda kind, t, **kw: self.sent.append(t) or (True, "ok")
        now = time.time()
        with m._db_lock:
            m._db.execute("INSERT OR REPLACE INTO wifi_seen VALUES "
                          "('x','netsh',NULL,0,0,'','',?,?,1)", (now - 1e6, now))
            m._db.execute("INSERT OR REPLACE INTO wifi_sensors VALUES ('netsh', ?)", (now + 1e6,))
            m._db.commit()
        m.wifi_detect = lambda *a: [{"type": "rogue", "key": "rg:ee", "bssid": "ee", "sensor": "netsh",
                                     "detail": "Новая точка «<b>free</b> & <i»"}]

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_ssid_cannot_inject_markup(self):
        self.m.wifi_evaluate()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("<b>Wi-Fi</b>", self.sent[0], "our own markup stays")
        self.assertIn("«&lt;b&gt;free&lt;/b&gt; &amp; &lt;i»", self.sent[0])


class CrossSiteTest(unittest.TestCase):
    """Password off, like a fresh install."""
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.m.CONFIG.setdefault("auth", {})["enabled"] = False
        self.srv = self.m.MonitorHTTPServer(("127.0.0.1", 0), self.m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def hb_url(self):
        return (self.m.CONFIG.get("heartbeat") or {}).get("url", "")

    def test_cross_site_post_refused(self):
        evil = {"enabled": True, "url": "https://evil.example/ping", "interval_minutes": 5}
        self.assertEqual(self.req("POST", "/api/heartbeat", evil, {"Sec-Fetch-Site": "cross-site"}), 403)
        self.assertEqual(self.req("POST", "/api/heartbeat", evil, {"Sec-Fetch-Site": "same-site"}), 403)
        # an old browser: no Sec-Fetch-*, but a foreign Origin on the POST
        self.assertEqual(self.req("POST", "/api/heartbeat", evil,
                                  {"Origin": "https://evil.example", "Content-Type": "text/plain"}), 403)
        self.assertNotEqual(self.hb_url(), "https://evil.example/ping")

    def test_cross_site_get_refused(self):
        self.assertEqual(self.req("GET", "/api/status", headers={"Sec-Fetch-Site": "cross-site"}), 403)

    def test_own_page_and_tools_pass(self):
        ok = {"enabled": False, "url": "https://hc-ping.com/test", "interval_minutes": 5}
        self.assertEqual(self.req("POST", "/api/heartbeat", ok, {"Sec-Fetch-Site": "same-origin",
                                                                "Origin": f"http://127.0.0.1:{self.port}"}), 200)
        self.assertEqual(self.hb_url(), "https://hc-ping.com/test")
        self.assertEqual(self.req("GET", "/api/status", headers={"Sec-Fetch-Site": "same-origin"}), 200)
        self.assertEqual(self.req("GET", "/api/status", headers={"Sec-Fetch-Site": "none"}), 200, "typed in the address bar")
        self.assertEqual(self.req("GET", "/api/status"), 200, "curl / scripts send no browser headers")
        # behind a tunnel that rewrites Host the browser still says same-origin
        self.assertEqual(self.req("POST", "/api/heartbeat", ok, {"Sec-Fetch-Site": "same-origin",
                                                                "Origin": "https://mon.example.com"}), 200)


class UpdateOwnerTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def run_ps(self, owner, admins, fail=False):
        class R:
            stdout = f"{owner}\n{admins}\n"
        def run(*a, **kw):
            if fail:
                raise OSError("powershell missing")
            self.env = kw.get("env", {})
            return R()
        return run

    def test_admin_owned_file_passes(self):
        ok, _ = self.m.exe_trusted("C:\\x\\ServerSignalDesk-v1.0.0.exe",
                                    run=self.run_ps("S-1-5-21-9-500", "S-1-5-21-9-500,S-1-5-21-9-1001"))
        self.assertTrue(ok)
        self.assertEqual(self.env.get("SSD_CHECK"), "C:\\x\\ServerSignalDesk-v1.0.0.exe", "path via env, not the script")
        self.assertTrue(self.m.exe_trusted("p", run=self.run_ps("S-1-5-32-544", ""))[0], "BUILTIN\\Administrators")
        self.assertTrue(self.m.exe_trusted("p", run=self.run_ps("S-1-5-18", ""))[0], "SYSTEM")

    def test_other_users_file_refused(self):
        ok, msg = self.m.exe_trusted("C:\\Users\\guest\\Downloads\\ServerSignalDesk-v9.9.9.exe",
                                      run=self.run_ps("S-1-5-21-9-1003", "S-1-5-21-9-500"))
        self.assertFalse(ok)
        self.assertIn("не администратор", msg)
        self.assertFalse(self.m.exe_trusted("p", run=self.run_ps("", "S-1-5-21-9-500"))[0], "unknown owner")
        self.assertFalse(self.m.exe_trusted("p", run=self.run_ps("", "", fail=True))[0], "can't check -> no")

    def test_untrusted_candidate_is_never_run(self):
        m = self.m
        dl = os.path.join(self.tmp, "Downloads")
        os.makedirs(dl)
        with open(os.path.join(dl, "ServerSignalDesk-v99.0.0.exe"), "wb") as f:
            f.write(b"MZ")
        paths = {"file": os.path.join(self.tmp, "update.json"), "backup": os.path.join(self.tmp, "backup"),
                 "downloads": dl}
        m.update_paths = lambda: paths
        smoked, spawned = [], []
        ok, msg = m.update_start("update", spawn=lambda *a: spawned.append(a),
                                 smoke=lambda p, v: smoked.append(p) or (True, ""),
                                 exit_after=lambda: None, trust=lambda p: (False, "чужой файл"))
        self.assertEqual((ok, msg), (False, "чужой файл"))
        self.assertEqual((smoked, spawned), ([], []), "not even the smoke test ran it")
        self.assertFalse(os.path.exists(paths["file"]))


if __name__ == "__main__":
    unittest.main()
