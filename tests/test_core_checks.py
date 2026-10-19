"""Core checks: ping / tcp / host / http, ARP and traceroute parsing.
System commands are replaced by recorded output (tests/fixtures, see README)."""
import io
import os
import socket
import subprocess
import unittest
import urllib.error

from harness import ROOT, cleanup, load_monitor

FIX = os.path.join(ROOT, "tests", "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


class _Proc:
    def __init__(self, out, rc):
        self.stdout, self.returncode = out, rc


class PingTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real_run = self.m.subprocess.run

    def tearDown(self):
        self.m.subprocess.run = self.real_run
        cleanup(self.m, self.tmp)

    def ping(self, name, rc):
        self.m.subprocess.run = lambda *a, **k: _Proc(fixture(name), rc)
        return self.m.check_ping("10.10.1.20", 1)

    def test_russian_reply_latency_is_parsed_not_process_time(self):
        """10-14: on Russian Windows «время<1мс» never matched the ms-only regex,
        so the latency was the ping PROCESS runtime — APP_SRV «85 ms», gateway «54 ms»."""
        up, lat, err = self.ping("ping_ok_ru.bin", 0)
        self.assertTrue(up)
        self.assertLessEqual(lat, 1.0, "real capture says <1 ms")
        up, lat, err = self.ping("ping_ok_slow_ru.bin", 0)
        self.assertEqual(lat, 14.0)

    def test_english_reply(self):
        up, lat, err = self.ping("ping_ok_en.bin", 0)
        self.assertEqual((up, lat), (True, 3.0))

    def test_ttl_feeds_os_guess(self):
        self.ping("ping_ok_slow_ru.bin", 0)
        self.assertEqual(self.m.os_from_ttl(self.m._TTL_SEEN["10.10.1.20"]), "Linux/Unix")
        self.ping("ping_ok_en.bin", 0)
        self.assertEqual(self.m.os_from_ttl(self.m._TTL_SEEN["10.10.1.20"]), "сетевое устройство")
        self.assertEqual(self.m.os_from_ttl(128), "Windows")
        self.assertEqual(self.m.os_from_ttl(None), "")

    def test_timeout(self):
        self.assertEqual(self.ping("ping_timeout_ru.bin", 1), (False, None, "unreachable"))

    def test_unreachable_with_exit_code_zero(self):
        """Windows returns 0 for «Заданный узел недоступен» — the reply has no TTL."""
        self.assertEqual(self.ping("ping_unreachable_ru.bin", 0), (False, None, "unreachable"))

    def test_ping_missing_or_hung(self):
        def missing(*a, **k):
            raise FileNotFoundError()
        self.m.subprocess.run = missing
        self.assertEqual(self.m.check_ping("x", 1), (False, None, "ping not found"))

        def hung(*a, **k):
            raise subprocess.TimeoutExpired("ping", 4)
        self.m.subprocess.run = hung
        up, lat, err = self.m.check_ping("x", 1)
        self.assertFalse(up)


class SocketChecksTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real = self.m.socket.create_connection
        self.tried = []

    def tearDown(self):
        self.m.socket.create_connection = self.real
        cleanup(self.m, self.tmp)

    def fake(self, outcome_by_port):
        class Conn:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

        def connect(addr, timeout=None):
            self.tried.append(addr[1])
            exc = outcome_by_port.get(addr[1], socket.timeout())
            if exc is True:
                return Conn()
            raise exc
        self.m.socket.create_connection = connect

    def test_tcp(self):
        self.fake({1433: True})
        self.assertTrue(self.m.check_tcp("10.10.1.20", 1433, 1)[0])
        self.fake({1433: ConnectionRefusedError("refused")})
        up, lat, err = self.m.check_tcp("10.10.1.20", 1433, 1)
        self.assertEqual((up, lat), (False, None), "for a tcp check a closed port IS down")

    def test_host_any_open_port(self):
        self.fake({3389: True})
        up, _, _ = self.m.check_host("10.10.1.20", 3)
        self.assertTrue(up)
        self.assertEqual(self.tried, [445, 135, 3389], "stops at the first answer")

    def test_host_refused_means_alive(self):
        """D5: RST/refused is an answer — the machine is there, the port is closed."""
        self.fake({445: ConnectionRefusedError("refused")})
        self.assertTrue(self.m.check_host("10.10.1.20", 3)[0])
        self.fake({445: ConnectionResetError("reset")})
        self.assertTrue(self.m.check_host("10.10.1.20", 3)[0])

    def test_host_all_silent(self):
        self.fake({})
        self.assertEqual(self.m.check_host("10.10.1.20", 3), (False, None, "timeout"))
        self.assertEqual(self.tried, self.m._HOST_PROBE_PORTS, "every port tried")

    def test_host_unreachable_oserror(self):
        self.fake({p: OSError(10065, "No route to host") for p in self.m._HOST_PROBE_PORTS})
        up, _, err = self.m.check_host("10.10.1.20", 3)
        self.assertFalse(up)
        self.assertIn("No route", err)

    def test_host_per_port_timeout_is_bounded(self):
        seen = []

        def connect(addr, timeout=None):
            seen.append(timeout)
            raise socket.timeout()
        self.m.socket.create_connection = connect
        self.m.check_host("10.10.1.20", 30)
        self.assertTrue(all(0.4 <= t <= 0.8 for t in seen), "6 ports x 30 s would stall the cycle")

    def test_run_check_dispatch(self):
        m = self.m
        m.check_ping = lambda h, t: ("ping", h)
        m.check_tcp = lambda h, p, t: ("tcp", h, p)
        m.check_host = lambda h, t: ("host", h)
        m.check_http = lambda u, t, e: ("http", u, e)
        self.assertEqual(m.run_check({"type": "tcp", "host": "a", "port": 22}, 1), ("tcp", "a", 22))
        self.assertEqual(m.run_check({"type": "host", "host": "a"}, 1), ("host", "a"))
        self.assertEqual(m.run_check({"type": "http", "url": "u", "expect": "  ok "}, 1), ("http", "u", "ok"))
        self.assertEqual(m.run_check({"type": "http", "url": "u", "expect": "  "}, 1), ("http", "u", None))
        self.assertEqual(m.run_check({"host": "a"}, 1), ("ping", "a"), "default is ping")


class HttpCheckTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real = self.m.urlrequest.urlopen

    def tearDown(self):
        self.m.urlrequest.urlopen = self.real
        cleanup(self.m, self.tmp)

    def serve(self, status=200, body="", exc=None):
        class R(io.BytesIO):
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

        def urlopen(req, timeout=None, context=None):
            if exc:
                raise exc
            r = R(body.encode("utf-8"))
            r.status = status
            return r
        self.m.urlrequest.urlopen = urlopen

    def test_status(self):
        self.serve(200)
        self.assertTrue(self.m.check_http("http://1c/", 1)[0])
        self.serve(503)
        self.assertEqual(self.m.check_http("http://1c/", 1)[2], "HTTP 503")
        self.serve(exc=urllib.error.HTTPError("http://1c/", 404, "nf", {}, io.BytesIO(b"")))
        self.assertEqual(self.m.check_http("http://1c/", 1)[2], "HTTP 404")
        self.serve(exc=urllib.error.URLError("refused"))
        self.assertFalse(self.m.check_http("http://1c/", 1)[0])

    def test_lying_200(self):
        """v0.19: 1C answers 200 while showing «идёт обновление конфигурации»."""
        self.serve(200, "<h1>Идёт обновление конфигурации</h1>")
        up, _, err = self.m.check_http("http://1c/", 1, expect="Вход в систему")
        self.assertFalse(up)
        self.assertIn("нет ожидаемого текста", err)
        self.serve(200, "<title>Вход в систему</title>")
        self.assertTrue(self.m.check_http("http://1c/", 1, expect="вход в систему")[0])

    def test_expect_literal_before_regex(self):
        self.serve(200, "Прайс: цена (опт) 100")
        self.assertTrue(self.m.check_http("http://x/", 1, expect="цена (опт)")[0],
                        "parentheses are text, not a regex group")
        self.serve(200, "build 2026-10-14 ok")
        self.assertTrue(self.m.check_http("http://x/", 1, expect=r"build \d{4}-\d\d")[0])
        self.serve(200, "x")
        self.assertFalse(self.m.check_http("http://x/", 1, expect="[unclosed")[0], "bad regex = no match")


class ParsersTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.real_run = self.m.subprocess.run

    def tearDown(self):
        self.m.subprocess.run = self.real_run
        cleanup(self.m, self.tmp)

    def test_arp_table_russian(self):
        self.m.subprocess.run = lambda *a, **k: _Proc(fixture("arp_ru.bin"), 0)
        t = self.m.arp_table()
        self.assertEqual(t["10.10.1.20"], "00:15:5d:00:17:02")
        self.assertEqual(t["10.10.1.1"], "00:11:22:33:44:55")
        relevant = {ip for ip, mac in t.items() if self.m._arp_entry_relevant(ip, mac)}
        self.assertEqual(relevant, {"10.10.1.1", "10.10.1.20"}, "broadcast/multicast ignored")

    def test_traceroute_russian_with_silent_hop(self):
        text = fixture("tracert_ru.bin").decode("cp866")
        self.assertEqual(self.m.parse_traceroute(text), ["10.10.1.1", None, "198.51.100.7"])

    def test_traceroute_unix(self):
        text = ("traceroute to 8.8.8.8 (8.8.8.8), 3 hops max\n"
                " 1  10.10.1.1  0.5 ms  0.4 ms  0.4 ms\n 2  * * *\n 3  198.51.100.7  9 ms\n")
        self.assertEqual(self.m.parse_traceroute(text), ["10.10.1.1", None, "198.51.100.7"])


if __name__ == "__main__":
    unittest.main()
