"""v0.45.2: controller-down alert, no backlog replay, nothing hangs or dies silently."""
import json
import socket
import time
import unittest

from harness import cleanup, load_monitor, stub_telegram


class _Stop(BaseException):
    pass


class UnifiHealthTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def test_down_after_three_then_recovery(self):
        m, t = self.m, time.time()
        m.unifi_health(False, "timed out", t)
        m.unifi_health(False, "timed out", t + 60)
        self.assertEqual(self.texts(), [], "two blips are not an outage")
        m.unifi_health(False, "timed out", t + 120)
        self.assertEqual(len(self.texts()), 1)
        self.assertIn("Контроллер UniFi не отвечает 2м", self.texts()[0])
        m.unifi_health(False, "timed out", t + 180)
        self.assertEqual(len(self.texts()), 1, "announced once")
        m.unifi_health(True, "", t + 300)
        self.assertIn("снова отвечает (не отвечал 5м", self.texts()[1])

    def test_short_blip_recovers_silently(self):
        m = self.m
        m.unifi_health(False, "x")
        m.unifi_health(True, "")
        self.assertEqual(self.texts(), [])

    def test_state_survives_restart(self):
        m = self.m
        for _ in range(3):
            m.unifi_health(False, "x")
        m.runtime_save()
        m.UNIFI_CTRL.update(fails=0, since=0.0, announced=False)
        m.runtime_restore()
        self.assertTrue(m.UNIFI_CTRL["announced"], "no second 'не отвечает' after restart")

    def test_loop_reports_and_survives_bad_interval(self):
        m = self.m
        m.CONFIG["unifi"] = {"enabled": True, "interval_seconds": "abc"}

        def boom():
            raise OSError("connection refused")
        m.unifi_evaluate = boom
        seen = []
        m.unifi_health = lambda ok, err, now=None: seen.append((ok, err))
        sleeps = []

        def sleep(sec):
            sleeps.append(sec)
            raise _Stop()
        real = m.time.sleep
        m.time.sleep = sleep
        try:
            with self.assertRaises(_Stop):
                m.unifi_loop()
        finally:
            m.time.sleep = real
        self.assertEqual(seen, [(False, "connection refused")])
        self.assertEqual(sleeps, [60], "string interval no longer kills the thread")


class BacklogTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = []

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_backlog_skipped_not_executed(self):
        m = self.m
        m.CONFIG["telegram"].update(bot_token="x", chat_id="42")
        stale = {"update_id": 900, "callback_query": {"id": "c", "data": "wake:h1",
                 "message": {"chat": {"id": 42}}}}

        def fake(method, params, timeout):
            self.calls.append((method, dict(params)))
            if method == "getUpdates" and params.get("offset") == -1:
                return {"ok": True, "result": [stale]}, None
            if method == "setMyCommands":
                return {"ok": True}, None
            raise _Stop()
        m._tg_call = fake
        handled = []
        m.handle_update = lambda u: handled.append(u)
        with self.assertRaises(_Stop):
            m.telegram_bot_loop()
        self.assertEqual(handled, [], "the stale WoL tap is not replayed")
        self.assertIn("setMyCommands", [meth for meth, _ in self.calls], "/ menu registered")
        polls = [p for meth, p in self.calls if meth == "getUpdates"]
        self.assertEqual(polls[1]["offset"], 901, "long poll starts after the backlog")


class CycleDeadlineTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_hung_check_does_not_hold_the_cycle(self):
        m = self.m
        m.CHECK_DEADLINE_MIN = 1
        m.CONFIG["timeout_seconds"] = 0.05
        m.CONFIG["fail_threshold"] = 1
        m.CONFIG["alerts"]["hold_down_seconds"] = 0
        m.CONFIG["hosts"] = [{"id": "dns", "name": "by-name", "host": "srv.local", "type": "ping"},
                             {"id": "ip", "name": "by-ip", "host": "10.0.0.9", "type": "ping"}]

        def check(h, t):
            if h["id"] == "dns":
                time.sleep(5)                 # getaddrinfo on a dead DNS
            return False, None, "timeout"
        m.run_check = check
        m.watch_arp_conflicts = lambda: None
        got = []
        m.dispatch_alerts = lambda evs: got.extend(evs)
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(4)
        t0 = time.monotonic()
        m.monitor_cycle(pool)
        self.assertLess(time.monotonic() - t0, 3, "cycle bounded by the deadline")
        errs = {e["host"]["id"]: e.get("error") for e in got}
        self.assertEqual(errs["dns"], "проверка зависла (DNS?)")
        self.assertEqual(errs["ip"], "timeout")
        pool.shutdown(wait=False)


class PortBusyTest(unittest.TestCase):
    """The real case is the monitor itself running twice — so the first copy
    holds the port with the same server class (SO_REUSEADDR on Windows let a
    plain-socket test pass while two real monitors happily shared 8081)."""

    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.first = self.m.MonitorHTTPServer(("127.0.0.1", 0), self.m.Handler)
        self.sock = self.first.socket

    def tearDown(self):
        self.first.server_close()
        cleanup(self.m, self.tmp)

    def test_second_server_cannot_share_the_port(self):
        with self.assertRaises(OSError):
            self.m.MonitorHTTPServer(self.first.server_address, self.m.Handler)

    def test_exits_before_threads_and_says_why(self):
        m = self.m
        m.CONFIG["web_host"] = "127.0.0.1"
        m.CONFIG["web_port"] = self.sock.getsockname()[1]
        m.CONFIG["telegram"].update(bot_token="x", chat_id="42")
        m.save_config()
        calls = []
        m._tg_call = lambda meth, p, t: calls.append(p) or ({"ok": True}, None)
        m.setup_logging = lambda: None
        started = []
        m.threading.Thread = lambda *a, **k: started.append(k.get("target"))
        with self.assertRaises(SystemExit):
            m.main()                     # harness.cleanup restores Thread
        self.assertEqual(started, [], "no threads, no '🚀 запущен'")
        self.assertEqual(len(calls), 1)
        self.assertIn("не запустился", calls[0]["text"])


class PassiveListenerTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_socket_error_rebuilds_instead_of_dying(self):
        m = self.m

        class S:
            closed = 0
            def close(self):
                S.closed += 1
        m._sock_multicast = lambda g, p: S()
        real_select, real_sleep = m.select.select, m.time.sleep

        def bad_select(*a):
            raise OSError("WinError 10038")
        sleeps = []

        def sleep(sec):
            sleeps.append(sec)
            if len(sleeps) > 1:
                raise _Stop()
        m.select.select, m.time.sleep = bad_select, sleep
        try:
            with self.assertRaises(_Stop):
                m.passive_listen_loop()
        finally:
            m.select.select, m.time.sleep = real_select, real_sleep
        self.assertEqual(S.closed, 2, "both sockets closed for a rebuild")
        self.assertEqual(sleeps, [10, 30])


class HttpBodyCapTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_body(self):
        H = self.m.Handler
        self.assertEqual(H.timeout, 30)

        class Fake:
            MAX_BODY = H.MAX_BODY
            def __init__(self, length, raw=b""):
                self.headers = {"Content-Length": length}
                self.rfile = type("R", (), {"read": lambda _s, n: raw[:n]})()
        body = json.dumps({"a": 1}).encode()
        self.assertEqual(H._body(Fake(str(len(body)), body)), {"a": 1})
        self.assertEqual(H._body(Fake(str(50_000_000))), {}, "oversized body not read")
        self.assertEqual(H._body(Fake("abc")), {})


if __name__ == "__main__":
    unittest.main()
