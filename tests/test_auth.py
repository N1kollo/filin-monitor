"""Dashboard gate: sessions, throttle, logout-everywhere, API token, what never
leaks. Since v0.54 the gate also guards 87 camera frames, so it gets its own suite."""
import base64
import http.client
import json
import threading
import time
import unittest

from harness import cleanup, load_monitor

PW = "correct-horse"


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m._PBKDF_ROUNDS = 1000                       # the real 200k is for attackers, not for CI
        m._LOGIN_FAILS.clear()
        m.CONFIG.setdefault("telegram", {})["bot_token"] = "123:TG-SECRET"
        m.CONFIG.setdefault("api", {})["token"] = "API-SECRET-TOKEN"
        m.set_password("admin", PW)
        self.srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def req(self, method, path, body=None, cookie=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = "session=" + cookie
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return r.status, r.getheader("Set-Cookie") or "", payload, r.getheader("Location")

    def login(self, user="admin", pw=PW):
        st, ck, d, _ = self.req("POST", "/api/login", {"username": user, "password": pw})
        tok = ck.split(";")[0].partition("=")[2] if ck else ""
        return st, tok, d, ck

    # --------------------------------------------------------------- the gate
    def test_closed_without_session(self):
        self.assertEqual(self.req("GET", "/api/status")[0], 401)
        self.assertEqual(self.req("GET", "/api/video/snap?nvr=1.2.3.4&ch=1")[0], 401, "camera frames are behind the gate")
        st, _, _, loc = self.req("GET", "/")
        self.assertEqual((st, loc), (302, "/login"))
        self.assertEqual(self.req("GET", "/login")[0], 200, "the login page itself is open")

    def test_login_cookie_flags_and_use(self):
        st, tok, d, raw = self.login()
        self.assertEqual((st, d["ok"]), (200, True))
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=Lax", raw)
        self.assertEqual(self.req("GET", "/api/status", cookie=tok)[0], 200)
        self.assertEqual(self.req("GET", "/login", cookie=tok)[3], "/", "already in -> sent to the dashboard")

    def test_forged_tampered_expired(self):
        m = self.m
        _, tok, _, _ = self.login()
        user, iat, exp, sig = base64.urlsafe_b64decode(tok).decode().rsplit("|", 3)
        forged = base64.urlsafe_b64encode(f"root|{iat}|{exp}|{sig}".encode()).decode()
        self.assertEqual(self.req("GET", "/api/status", cookie=forged)[0], 401, "payload edited, signature kept")
        longer = base64.urlsafe_b64encode(f"{user}|{iat}|{int(exp) + 10**6}|{sig}".encode()).decode()
        self.assertEqual(self.req("GET", "/api/status", cookie=longer)[0], 401, "can't extend own expiry")
        self.assertEqual(self.req("GET", "/api/status", cookie="garbage!!")[0], 401)
        old = m.make_session("admin", days=-1)
        self.assertEqual(self.req("GET", "/api/status", cookie=old)[0], 401, "expired")

    def test_same_error_for_wrong_user_and_wrong_password(self):
        a = self.login(user="nobody")
        b = self.login(pw="wrong")
        self.assertEqual((a[0], a[2]), (b[0], b[2]))
        self.assertEqual(a[0], 401)

    def test_wrong_user_costs_the_same_hash(self):
        """Without it, a wrong username answers ~instantly and a wrong password
        after a full PBKDF2 — the timing tells which half was right."""
        calls = []
        real = self.m.verify_password
        self.m.verify_password = lambda pw: (calls.append(1), real(pw))[1]
        self.login(user="nobody", pw="x")
        self.assertEqual(len(calls), 1)

    def test_throttle(self):
        for _ in range(5):
            self.assertEqual(self.login(pw="wrong")[0], 401)
        st, _, d, _ = self.login()
        self.assertEqual(st, 429, "6th try blocked — even with the right password")
        self.assertIn("подожди", d["error"])
        self.m._LOGIN_FAILS.clear()
        self.assertEqual(self.login()[0], 200)
        for _ in range(4):
            self.login(pw="wrong")
        self.assertEqual(self.login()[0], 200)
        self.assertEqual(self.login(pw="wrong")[0], 401, "a success resets the count")

    def test_logout_everywhere(self):
        _, tok, _, _ = self.login()
        time.sleep(0.01)
        self.assertEqual(self.req("POST", "/api/auth/logout-all", {}, cookie=tok)[0], 200)
        self.assertEqual(self.req("GET", "/api/status", cookie=tok)[0], 401, "every older cookie is dead")
        _, tok2, _, _ = self.login()
        self.assertEqual(self.req("GET", "/api/status", cookie=tok2)[0], 200, "a fresh login still works")

    def test_password_change_keeps_caller_kills_others(self):
        _, mine, _, _ = self.login()
        _, other, _, _ = self.login()
        st, ck, d, _ = self.req("POST", "/api/auth/set", {"current": "nope", "username": "admin",
                                                          "password": "new-password-1", "password2": "new-password-1"}, cookie=mine)
        self.assertEqual(st, 403, "current password required")
        st, ck, d, _ = self.req("POST", "/api/auth/set", {"current": PW, "username": "admin",
                                                          "password": "new-password-1", "password2": "new-password-1"}, cookie=mine)
        self.assertEqual(st, 200)
        fresh = ck.split(";")[0].partition("=")[2]
        self.assertEqual(self.req("GET", "/api/status", cookie=fresh)[0], 200, "caller is not logged out")
        self.assertEqual(self.req("GET", "/api/status", cookie=other)[0], 401, "the other browser is")
        self.assertEqual(self.login()[0], 401, "old password gone")
        self.assertEqual(self.login(pw="new-password-1")[0], 200)

    def test_disable_needs_current_password(self):
        _, tok, _, _ = self.login()
        self.assertEqual(self.req("POST", "/api/auth/disable", {"current": "x"}, cookie=tok)[0], 403)
        self.assertTrue(self.m.auth_enabled())

    def test_mutation_without_session_changes_nothing(self):
        before = json.dumps(self.m.CONFIG.get("hosts", []))
        st = self.req("POST", "/api/hosts/add", {"name": "evil", "host": "10.6.6.6"})[0]
        self.assertEqual(st, 401)
        self.assertEqual(json.dumps(self.m.CONFIG.get("hosts", [])), before)

    # --------------------------------------------------------------- API token
    def test_api_token(self):
        self.assertEqual(self.req("GET", "/api/status", headers={"Authorization": "Bearer API-SECRET-TOKEN"})[0], 200)
        self.assertEqual(self.req("GET", "/api/status", headers={"X-Api-Token": "API-SECRET-TOKEN"})[0], 200)
        self.assertEqual(self.req("GET", "/api/status", headers={"Authorization": "Bearer nope"})[0], 401)
        self.m.CONFIG["api"]["token"] = ""
        self.assertEqual(self.req("GET", "/api/status", headers={"Authorization": "Bearer "})[0], 401,
                         "no token configured -> an empty bearer is not a key")

    # --------------------------------------------------------------- never leaks
    def test_config_never_leaks_secrets(self):
        _, tok, _, _ = self.login()
        _, _, d, _ = self.req("GET", "/api/config", cookie=tok)
        dump = json.dumps(d)
        a = self.m.CONFIG["auth"]
        for secret in ("TG-SECRET", "API-SECRET-TOKEN", a["password_hash"], a["salt"], a["secret"]):
            self.assertNotIn(secret, dump)
        self.assertEqual(d["auth"], {"enabled": True, "username": "admin"})


class AuthOffTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_open_when_disabled(self):
        m = self.m
        m.CONFIG["auth"] = {"enabled": True, "password_hash": ""}
        self.assertFalse(m.auth_enabled(), "enabled without a hash is not a gate (no lock-out by a half-written config)")
        self.assertFalse(m.check_session(m.make_session("admin")), "no secret -> no valid session either")


if __name__ == "__main__":
    unittest.main()
