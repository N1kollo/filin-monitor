"""Web app: HTTP server and the REST API."""

import hmac
import ipaddress
import json
import re
import secrets
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib import parse as urlparse

from . import core, webauth, storage, checks, netinventory, dhcp, passive, pathdiag, wolschedule, services, recovery, telegram, alerting, livestate, policy, degradation, status, netdiag


LOGIN_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Вход · Филин</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'%3E%3Crect x='6' y='6' width='188' height='188' rx='52' fill='%23231c52'/%3E%3Cg fill='none' stroke='%23fff' stroke-width='18' stroke-linecap='round' stroke-linejoin='round' transform='translate(14 0) scale(.86)'%3E%3Ccircle cx='66' cy='128' r='25'/%3E%3Ccircle cx='134' cy='128' r='25'/%3E%3Cpath d='M40 76 L100 112 L160 76' stroke='%23231c52' stroke-width='32'/%3E%3Cpath d='M40 76 L100 112 L160 76'/%3E%3C/g%3E%3Ccircle cx='70.8' cy='111.8' r='9.5' fill='%2338bdf8'/%3E%3Ccircle cx='129.2' cy='111.8' r='9.5' fill='%2338bdf8'/%3E%3C/svg%3E">
<style>
  :root{--bg:#080b11;--panel:#0e131c;--line:#26374b;--text:#dbe4f0;--muted:#6f8098;--cyan:#38bdf8;--down:#ff4d68}
  *{box-sizing:border-box}body{margin:0;height:100vh;display:grid;place-items:center;background:linear-gradient(180deg,#0b1019,var(--bg));
  color:var(--text);font:15px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif}
  .box{width:340px;max-width:90vw;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:28px;box-shadow:0 10px 40px rgba(0,0,0,.5)}
  .logo{position:relative;width:56px;height:56px;display:grid;place-items:center;margin:0 auto 14px}
  .logo::before{content:'';position:absolute;width:42px;height:42px;border-radius:50%;
    background:radial-gradient(circle,rgba(56,189,248,.22) 0%,transparent 70%)}
  .logo svg{position:relative}
  h1{font-size:17px;text-align:center;margin:0 0 4px}.sub{text-align:center;color:var(--muted);font-size:12px;margin-bottom:20px}
  label{display:block;font-size:12px;color:var(--muted);margin:12px 0 5px;font-weight:600}
  input{width:100%;padding:10px 12px;border-radius:9px;background:#121926;border:1px solid var(--line);color:var(--text);font-size:14px}
  input:focus{outline:none;border-color:var(--cyan)}
  button{width:100%;margin-top:18px;padding:11px;border:none;border-radius:9px;background:linear-gradient(140deg,var(--cyan),#2b8fe0);color:#04121f;font-weight:700;font-size:14px;cursor:pointer}
  .err{color:var(--down);font-size:13px;text-align:center;margin-top:12px;min-height:16px}
</style></head><body>
<form class="box" onsubmit="return login(event)">
  <div class="logo"><svg viewBox="0 0 200 200" width="56" height="56" aria-hidden="true"><defs><mask id="k" maskUnits="userSpaceOnUse" x="0" y="0" width="200" height="200"><rect width="200" height="200" fill="#fff"/><path d="M44 78 L100 112 L156 78" fill="none" stroke="#000" stroke-width="24" stroke-linecap="round" stroke-linejoin="round"/></mask></defs><g fill="none" stroke="#dbe4f0" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"><g mask="url(#k)"><circle cx="69" cy="126" r="25"/><circle cx="131" cy="126" r="25"/></g><path d="M44 78 L100 112 L156 78"/></g><circle cx="69" cy="128" r="9" fill="#38bdf8"/><circle cx="131" cy="128" r="9" fill="#38bdf8"/><circle cx="66" cy="125" r="3" fill="#fff" opacity=".85"/><circle cx="128" cy="125" r="3" fill="#fff" opacity=".85"/></svg></div><h1>Филин</h1><div class="sub">Вход в панель мониторинга</div>
  <label>Логин</label><input id="u" autofocus autocomplete="username">
  <label>Пароль</label><input id="p" type="password" autocomplete="current-password">
  <button type="submit">Войти</button>
  <div class="err" id="e"></div>
</form>
<script>
async function login(ev){ev.preventDefault();
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
  const d=await r.json();
  if(d.ok){location.href='/';}else{document.getElementById('e').textContent=d.error||'Ошибка входа';}
  return false;}
</script></body></html>"""


class MonitorHTTPServer(ThreadingHTTPServer):
    """On Windows SO_REUSEADDR (HTTPServer's default) lets a second process bind
    a port that is already listening — two monitors ran on 8081 side by side,
    the second never noticed. Exclusive bind makes the second copy fail."""
    allow_reuse_address = sys.platform != "win32"

    def handle_error(self, request, client_address):
        # A browser closing the tab mid-response printed a 13-line traceback as
        # ERROR (10-14 17:30) — the only "error" in the office log, drowning the
        # real ones. A hang-up is the client's business; anything else is logged.
        if isinstance(sys.exc_info()[1], (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)

    def server_bind(self):
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    # A client that opens a connection and goes quiet used to hold a server
    # thread forever.
    timeout = 30
    MAX_BODY = 1_000_000

    def log_message(self, *a):
        pass  # quiet

    # -- auth helpers ------------------------------------------------------
    def _cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return None

    def _authed(self):
        tok = self._cookie("session")
        if tok and webauth.check_session(tok):
            return True
        # API token path: scripts send "Authorization: Bearer <token>"
        api_tok = ((core.cfg("api", {}) or {}).get("token") or "")
        if api_tok:
            sent = (self.headers.get("Authorization") or "").strip()
            if sent.lower().startswith("bearer "):
                sent = sent[7:].strip()
            else:
                sent = self.headers.get("X-Api-Token") or ""
            if sent and hmac.compare_digest(api_tok, sent):
                return True
        return False

    def _cross_site(self):
        """A browser request that some other site made on the user's behalf.
        With the panel password off (the default) any page open on a LAN PC could
        otherwise change the config or press «Поднять»/«Обновить». Browsers mark
        such requests: Sec-Fetch-Site on every fetch, Origin on every POST.
        Non-browser clients (curl, the API token) send neither and pass.
        Sec-Fetch-Site is the browser's own verdict, so it also holds behind a
        tunnel that rewrites Host; Origin vs Host is the fallback for old browsers."""
        sfs = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if sfs:
            return sfs not in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if origin:
            host = urlparse.urlparse(origin).netloc.lower()
            return host != (self.headers.get("Host") or "").lower()
        return False

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _serve_html(self, html, code=200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return {}
        if not length or length > self.MAX_BODY:
            return {}
        raw = self.rfile.read(length)
        # Browsers always send UTF-8; cp1251 fallback is for stray CLI clients
        # on Windows, so a mis-encoded body doesn't surface as a bogus error.
        for enc in ("utf-8", "cp1251"):
            try:
                return json.loads(raw.decode(enc))
            except (UnicodeDecodeError, ValueError):
                continue
        return {}

    def do_GET(self):
        path = urlparse.urlparse(self.path).path
        if path.startswith("/api/") and self._cross_site():
            return self._send({"error": "cross-site request refused"}, 403)
        if path == "/login":
            if webauth.auth_enabled() and self._authed():
                return self._redirect("/")
            return self._serve_html(LOGIN_HTML)
        if webauth.auth_enabled() and not self._authed():
            if path.startswith("/api/"):
                return self._send({"error": "unauthorized"}, 401)
            return self._redirect("/login")
        if path == "/":
            try:
                html = open(core.resource_path("dashboard.html"), "r", encoding="utf-8").read()
            except Exception as e:
                html = f"<h1>dashboard.html not found</h1><p>{e}</p>"
            self._serve_html(html)
        elif path == "/api/status":
            self._send(status.build_status())
        elif path == "/api/config":
            self._send(status.public_config())
        elif path == "/api/host":
            self._host_detail(urlparse.parse_qs(urlparse.urlparse(self.path).query))
        elif path == "/api/network":
            with storage._db_lock:
                rows = storage._db.execute(
                    "SELECT ip, mac, vendor, first_seen, last_seen, present, hostname "
                    "FROM arp_seen ORDER BY last_seen DESC").fetchall()
            devices = [{
                "ip": r[0], "mac": r[1], "vendor": r[2], "present": bool(r[5]),
                "hostname": r[6] or "",
                "first_human": alerting.fmt_duration(time.time() - r[3]) + " назад" if r[3] else None,
                "last_human": alerting.fmt_duration(time.time() - r[4]) + " назад" if r[4] else None,
            } for r in rows]
            devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split("."))
                         if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", d["ip"]) else (0,))
            self._send({"devices": devices, "total": len(devices)})
        elif path == "/api/wifi":
            self._send(wifi.wifi_view())
        elif path == "/api/unifi":
            self._send(unifi.unifi_view())
        elif path == "/api/recovery":
            self._send(recovery.recovery_view_data())
        elif path == "/api/silence":
            self._send(policy.silence_view())
        elif path == "/api/services":
            self._send({"services": services.services_view(), "config": core.cfg("services", []) or []})
        elif path == "/api/video":
            self._send(video.video_view())
        elif path == "/api/update":
            self._send(update.update_view())
        elif path == "/api/video/snap":
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            nvr = (q.get("nvr") or [""])[0]
            try:
                ch = int((q.get("ch") or ["0"])[0])
            except ValueError:
                ch = 0
            if nvr not in dahua.nvr_config()[0] or not 1 <= ch <= 256:
                return self._send({"ok": False, "error": "регистратор/канал"}, 400)
            body, err = video.nvr_snapshot(nvr, ch)
            if err:
                return self._send({"ok": False, "error": err}, 502)
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/diag":
            ip = (urlparse.parse_qs(urlparse.urlparse(self.path).query).get("ip") or [""])[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._send({"ok": False, "error": "нужен ip"}, 400)
            self._send(netdiag.diagnose(ip))
        elif path == "/api/nvr/check":
            self._send({"files": dahua.nvr_config_check()})
        elif path == "/api/nvr/probe":
            ip = (urlparse.parse_qs(urlparse.urlparse(self.path).query).get("ip") or [""])[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._send({"ok": False, "error": "ip регистратора"}, 400)
            self._send(dahua.nvr_probe(ip))
        elif path == "/api/scan":
            # one-off, read-only sweep: nothing is stored, nothing is alerted
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            try:
                net = ipaddress.ip_network((q.get("cidr") or [""])[0], strict=False)
            except ValueError:
                return self._send({"error": "cidr вида 192.168.2.0/24"}, 400)
            if net.num_addresses > 1024:
                return self._send({"error": "не больше /22"}, 400)
            alive = status.scan_subnet(str(net), timeout=1.0)
            arp = dhcp.arp_table()
            self._send({"cidr": str(net), "count": len(alive), "alive": [
                {"ip": ip, "mac": arp.get(ip, ""), "vendor": netinventory.lookup_vendor(arp.get(ip, ""))} for ip in alive]})
        elif path == "/api/issues":
            self._send({"issues": policy.standing_issues()})
        elif path == "/api/log":
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            try:
                n = int((q.get("lines") or ["300"])[0])
            except ValueError:
                n = 300
            self._send(policy.log_tail(n, (q.get("errors") or ["0"])[0] == "1"))
        elif path == "/api/dhcp":
            self._send({"config": core.cfg("dhcp_watch", {}) or {}, "last": dhcp.DHCP_LAST,
                        "addresses": dhcp.local_ipv4s()})
        elif path == "/api/topology":
            self._send(status.topology_snapshot())
        elif path == "/api/inventory":
            inv = storage.db_inventory_all()
            items = []
            with core.CONFIG_LOCK:
                hosts = [dict(h) for h in core.CONFIG.get("hosts", [])]
            with livestate.STATE_LOCK:
                states = {k: v["status"] for k, v in livestate.STATE.items()}
            for h in hosts:
                rec = inv.get(h["id"], {})
                items.append({
                    "id": h["id"],
                    "name": h.get("name", ""),
                    "target": passive.host_target(h),
                    "ip": h.get("host", ""),
                    "status": states.get(h["id"], "pending"),
                    "mac": rec.get("mac") or h.get("mac", ""),
                    "vendor": rec.get("vendor", ""),
                    "hostname": rec.get("hostname", ""),
                    "os": rec.get("os") or checks.os_from_ttl(checks._TTL_SEEN.get(h.get("host", ""))),
                    "ports": rec.get("ports", []),
                    "updated": rec.get("updated"),
                    "updated_human": (alerting.fmt_duration(time.time() - rec["updated"]) + " назад"
                                      if rec.get("updated") else None),
                })
            items.sort(key=lambda x: x["name"].lower())
            self._send({"items": items, "known": len(inv), "total": len(items)})
        elif path == "/api/report":
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            try:
                days = max(1, min(365, int((q.get("days") or ["30"])[0])))
            except ValueError:
                days = 30
            self._send(storage.db_report(days))
        elif path == "/api/events":
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            try:
                limit = max(1, min(500, int((q.get("limit") or ["100"])[0])))
            except ValueError:
                limit = 100
            events = storage.db_events_all(limit)
            # rollup: total downtime and incident count per host over the window
            roll = {}
            for e in events:
                r = roll.setdefault(e["host_id"], {
                    "host_id": e["host_id"], "name": e["name"],
                    "incidents": 0, "downtime": 0.0,
                })
                if e["type"] == "down":
                    r["incidents"] += 1
                if e["type"] == "up" and e["downtime"]:
                    r["downtime"] += e["downtime"]
            top = sorted(roll.values(), key=lambda x: -x["downtime"])[:10]
            for t in top:
                t["downtime_human"] = alerting.fmt_duration(t["downtime"])
            self._send({"events": events, "top": top, "total": len(events)})
        elif path == "/api/tg_sent":
            q = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            try:
                hours = max(1, min(90 * 24, int((q.get("hours") or ["168"])[0])))
            except ValueError:
                hours = 168
            self._send(telegram.db_tg_sent_stats(hours))
        else:
            self._send({"error": "not found"}, 404)

    def _host_detail(self, q):
        hid = (q.get("id") or [""])[0]
        try:
            hours = max(1, min(720, int((q.get("hours") or ["24"])[0])))
        except ValueError:
            hours = 24
        with core.CONFIG_LOCK:
            h = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == hid), None)
        if not h:
            return self._send({"error": "хост не найден"}, 404)
        with livestate.STATE_LOCK:
            st = dict(livestate.STATE.get(hid, {}))
        parent_name = ""
        if h.get("parent"):
            with core.CONFIG_LOCK:
                p = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == h["parent"]), None)
            parent_name = p.get("name", "") if p else ""
        self._send({
            "id": hid,
            "name": h.get("name", ""),
            "type": h.get("type", "ping"),
            "target": passive.host_target(h),
            "mac": h.get("mac", ""),
            "parent_name": parent_name,
            "status": st.get("status", "pending"),
            "latency": st.get("latency"),
            # NOT "error": that key is reserved for API-level failures. A host's
            # own check error must never be mistaken for a failed request.
            "last_error": st.get("error"),
            "since_human": alerting.fmt_duration(time.time() - st["since"]) if st.get("since") else "",
            "hours": hours,
            "uptime_24h": storage.db_uptime(hid, 24),
            "uptime_7d": storage.db_uptime(hid, 168),
            "series": storage.db_series(hid, hours),
            "events": storage.db_events(hid, 40),
            "priority": policy.alert_class(h),
            "parent": h.get("parent", ""),
            "muted": policy.is_muted(hid),
            "maint": bool(policy.maint_until(hid)),
            "audible": policy.alert_audibility(h),
        })

    def do_POST(self):
        path = urlparse.urlparse(self.path).path
        if self._cross_site():
            return self._send({"error": "cross-site request refused"}, 403)
        data = self._body()
        if path == "/api/login":
            return self._login(data)
        if path == "/api/logout":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            body = json.dumps({"ok": True}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if webauth.auth_enabled() and not self._authed():
            return self._send({"error": "unauthorized"}, 401)
        try:
            self._route_post(path, data)
        except Exception as e:
            self._send({"ok": False, "error": core.short_err(e)}, 400)

    def _login(self, d):
        user = (d.get("username") or "").strip()
        pw = d.get("password") or ""
        a = core.cfg("auth", {}) or {}
        if not webauth.auth_enabled():
            return self._send({"ok": True})  # auth off — nothing to log into
        ip = self.client_address[0]
        left = webauth.login_blocked(ip)
        if left:
            return self._send({"ok": False, "error": f"слишком много попыток, "
                                                     f"подожди {left // 60 + 1} мин"}, 429)
        # hash first, always: a wrong username must cost the same PBKDF2 as a
        # wrong password, or the response time says which half was right
        pw_ok = webauth.verify_password(pw)
        if hmac.compare_digest(user.encode(), (a.get("username") or "").encode()) and pw_ok:
            webauth.login_note_ok(ip)
            tok = webauth.make_session(user)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header(
                "Set-Cookie",
                f"session={tok}; HttpOnly; Path=/; Max-Age={7*86400}; SameSite=Lax",
            )
            body = json.dumps({"ok": True}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            webauth.login_note_fail(ip)
            # Deliberately the same message for a wrong user and a wrong
            # password — no probing which half was right.
            self._send({"ok": False, "error": "неверный логин или пароль"}, 401)

    def _auth_set(self, d):
        """Set / change the dashboard password from the UI.

        Note the ordering: set_password() rotates the signing secret, which
        kills every live session including the caller's own — so we hand the
        caller a fresh cookie in the same response, or they'd log themselves out.
        """
        user = (d.get("username") or "").strip() or "admin"
        pw = d.get("password") or ""
        pw2 = d.get("password2") or ""
        if webauth.auth_enabled() and not webauth.verify_password(d.get("current") or ""):
            return self._send({"ok": False, "error": "неверный текущий пароль"}, 403)
        if len(pw) < 8:
            return self._send({"ok": False, "error": "пароль короче 8 символов"}, 400)
        if pw != pw2:
            return self._send({"ok": False, "error": "пароли не совпадают"}, 400)
        webauth.set_password(user, pw)
        tok = webauth.make_session(user)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header(
            "Set-Cookie",
            f"session={tok}; HttpOnly; Path=/; Max-Age={7*86400}; SameSite=Lax",
        )
        body = json.dumps({"ok": True, "username": user}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route_post(self, path, data):
        if path == "/api/hosts/add":
            self._add_host(data)
        elif path == "/api/hosts/delete":
            self._mutate_hosts(lambda hs: [h for h in hs if h["id"] != data.get("id")])
            self._send({"ok": True})
        elif path == "/api/arp/forget":
            with storage._db_lock:
                storage._db.execute("DELETE FROM arp_seen WHERE ip=?", (data.get("ip"),))
                storage._db.commit()
            self._send({"ok": True})
        elif path == "/api/wifi/report":
            self._send(wifi.wifi_ingest(data))
        elif path == "/api/wifi/config":
            with core.CONFIG_LOCK:
                wc = core.CONFIG.setdefault("wifi", {})
                if "enabled" in data:
                    wc["enabled"] = bool(data["enabled"])
                if "watch_ssids" in data:
                    v = data["watch_ssids"]
                    v = v if isinstance(v, list) else str(v).split(",")
                    wc["watch_ssids"] = [s.strip() for s in v if s.strip()]
                for k in ("learn_hours", "radio_gone_minutes", "rogue_min_signal", "sensor_stale_minutes"):
                    if data.get(k) not in (None, ""):
                        wc[k] = float(data[k])
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/map/layout":
            # {id,x,y} pin a node · {id, clear:true} unpin one · {clear:true} unpin all
            with core.CONFIG_LOCK:
                lay = core.CONFIG.setdefault("map_layout", {})
                nid = str(data.get("id") or "")
                if data.get("clear") and not nid:
                    lay.clear()
                elif nid and data.get("clear"):
                    lay.pop(nid, None)
                elif nid and data.get("x") is not None and data.get("y") is not None:
                    lay[nid] = [round(float(data["x"]), 1), round(float(data["y"]), 1)]
                else:
                    self._send({"ok": False, "error": "нужен id с x/y либо clear"}); return
                core.save_config()
            self._send({"ok": True, "pinned": len(core.CONFIG.get("map_layout", {}))})
        elif path == "/api/unifi/config":
            with core.CONFIG_LOCK:
                uc = core.CONFIG.setdefault("unifi", {})
                for k in ("enabled", "alert_ap_offline", "alert_rogue"):
                    if k in data:
                        uc[k] = bool(data[k])
                for k in ("url", "site"):
                    if data.get(k) not in (None, ""):
                        uc[k] = str(data[k]).strip()
                if data.get("reset_pin"):
                    uc.pop("cert_sha256", None)   # next login pins whatever answers
                if "ap_quiet" in data:
                    w = data["ap_quiet"] or {}
                    if not w:
                        uc.pop("ap_quiet", None)
                    elif policy._hhmm_minutes(w.get("from")) is None or policy._hhmm_minutes(w.get("to")) is None:
                        return self._send({"ok": False, "error": "ap_quiet: время ЧЧ:ММ"}, 400)
                    else:
                        uc["ap_quiet"] = {"from": w["from"], "to": w["to"]}
                if data.get("interval_seconds") not in (None, ""):
                    uc["interval_seconds"] = max(15, int(float(data["interval_seconds"])))
                if "own_other_ssids" in data:
                    v = data["own_other_ssids"]
                    v = v if isinstance(v, list) else str(v).split(",")
                    uc["own_other_ssids"] = [s.strip() for s in v if s.strip()]
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/wifi/trust":
            with storage._db_lock:
                storage._db.execute("UPDATE wifi_seen SET trusted=? WHERE bssid=?",
                            (1 if data.get("trusted") else 0, (data.get("bssid") or "").lower()))
                storage._db.commit()
            self._send({"ok": True})
        elif path == "/api/wifi/forget":
            with storage._db_lock:
                storage._db.execute("DELETE FROM wifi_seen WHERE bssid=?", ((data.get("bssid") or "").lower(),))
                storage._db.commit()
            self._send({"ok": True})
        elif path == "/api/hosts/toggle":
            def tog(hs):
                for h in hs:
                    if h["id"] == data.get("id"):
                        h["enabled"] = not h.get("enabled", True)
                return hs
            self._mutate_hosts(tog)
            self._send({"ok": True})
        elif path == "/api/hosts/wake":
            self._wake_host(data)
        elif path in ("/api/hosts/mute", "/api/hosts/maint"):
            # {id, seconds}: seconds null/0 = lift. maint also takes id "*" (whole network)
            hid = str(data.get("id") or "")
            if not hid:
                return self._send({"ok": False, "error": "нужен id"}, 400)
            try:
                sec = int(data.get("seconds") or 0)
            except (TypeError, ValueError):
                return self._send({"ok": False, "error": "seconds — число"}, 400)
            if path.endswith("mute"):
                policy.set_mute("muted_hosts", hid, sec or None)
            else:
                policy.set_maint(hid, sec or None)
            self._send({"ok": True})
        elif path == "/api/services":
            svcs = data.get("services")
            if not isinstance(svcs, list):
                return self._send({"ok": False, "error": "services — список"}, 400)
            clean = []
            for x in svcs:
                if not isinstance(x, dict) or not x.get("id") or not x.get("name"):
                    return self._send({"ok": False, "error": "у сервиса нужны id и name"}, 400)
                if "group" in x:
                    try:
                        ipaddress.ip_network(x["group"]["cidr"], strict=False)
                    except (KeyError, TypeError, ValueError):
                        return self._send({"ok": False, "error": f"{x['name']}: group.cidr"}, 400)
                clean.append({k: x[k] for k in ("id", "name", "hosts", "wan", "unifi", "group") if k in x})
            with core.CONFIG_LOCK:
                core.CONFIG["services"] = clean
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/issues/ack":
            key = str(data.get("key") or "")
            if not key:
                return self._send({"ok": False, "error": "нужен key"}, 400)
            policy.ack_issue(key, data.get("ack", True) is not False)
            self._send({"ok": True})
        elif path == "/api/alerts/kind":
            # {kind, seconds}: seconds null = unmute, 0 = until switched back on
            kind = data.get("kind")
            if kind not in policy.ALERT_KINDS:
                return self._send({"ok": False, "error": "неизвестный тип"}, 400)
            sec = data.get("seconds")
            policy.set_mute("muted_kinds", kind, None if sec is None else int(sec))
            self._send({"ok": True})
        elif path == "/api/recovery/start":
            started = recovery.recovery_start("дашборд")
            self._send({"ok": started, "error": None if started else "восстановление уже идёт"},
                       200 if started else 409)
        elif path == "/api/hosts/rename":
            hid, name = data.get("id"), (data.get("name") or "").strip()
            if not name:
                return self._send({"ok": False, "error": "нужно имя"}, 400)
            def setn(hs):
                for h in hs:
                    if h["id"] == hid:
                        h["name"] = name[:60]
                return hs
            self._mutate_hosts(setn)
            self._send({"ok": True})
        elif path == "/api/hosts/parent":
            hid, pid = data.get("id"), (data.get("parent") or "").strip()
            if pid == hid:
                return self._send({"ok": False, "error": "хост не может быть родителем сам себе"}, 400)
            def setp(hs):
                for h in hs:
                    if h["id"] == hid:
                        h["parent"] = pid
                return hs
            self._mutate_hosts(setp)
            self._send({"ok": True})
        elif path == "/api/inventory/scan":
            self._inventory_scan(data)
        elif path == "/api/network/scan":
            self._network_scan(data)
        elif path == "/api/subnets/add":
            self._add_subnet(data)
        elif path == "/api/switches/add":
            name = (data.get("name") or "").strip()
            if not name:
                return self._send({"ok": False, "error": "нужно имя свитча"}, 400)
            sw = {"id": uuid.uuid4().hex[:8], "name": name,
                  "parent": (data.get("parent") or "").strip()}
            with core.CONFIG_LOCK:
                core.CONFIG.setdefault("switches", []).append(sw)
                core.save_config()
            self._send({"ok": True, "switch": sw})
        elif path == "/api/switches/delete":
            sid = data.get("id")
            with core.CONFIG_LOCK:
                core.CONFIG["switches"] = [s for s in core.CONFIG.get("switches", [])
                                      if s.get("id") != sid]
                for h in core.CONFIG.get("hosts", []):   # drop dangling parent refs
                    if h.get("parent") == sid:
                        h["parent"] = ""
                for s in core.CONFIG.get("switches", []):
                    if s.get("parent") == sid:
                        s["parent"] = ""
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/switches/update":
            sid = data.get("id")
            with core.CONFIG_LOCK:
                for s in core.CONFIG.get("switches", []):
                    if s.get("id") == sid:
                        nm = (data.get("name") or "").strip()
                        if nm:
                            s["name"] = nm
                        if "parent" in data:
                            p = (data.get("parent") or "").strip()
                            s["parent"] = "" if p == sid else p
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/trace/run":
            threading.Thread(target=pathdiag.run_trace_paths, daemon=True).start()
            self._send({"ok": True})   # runs in background; paths land as they finish
        elif path == "/api/maint/add":
            t_from, t_to = str(data.get("from") or ""), str(data.get("to") or "")
            if policy._hhmm_minutes(t_from) is None or policy._hhmm_minutes(t_to) is None \
                    or policy._hhmm_minutes(t_from) == policy._hhmm_minutes(t_to):
                return self._send({"ok": False, "error": "время в формате ЧЧ:ММ, начало ≠ конец"}, 400)
            win = {
                "id": uuid.uuid4().hex[:8],
                "name": (data.get("name") or "").strip() or f"{t_from}–{t_to}",
                "from": t_from, "to": t_to,
                "days": [int(x) for x in (data.get("days") or []) if 0 <= int(x) <= 6],
                "hosts": [str(x) for x in (data.get("hosts") or [])],
                "enabled": True,
            }
            with core.CONFIG_LOCK:
                core.CONFIG.setdefault("maintenance", []).append(win)
                core.save_config()
            self._send({"ok": True, "window": win})
        elif path == "/api/maint/delete":
            with core.CONFIG_LOCK:
                core.CONFIG["maintenance"] = [w for w in core.CONFIG.get("maintenance", [])
                                         if w["id"] != data.get("id")]
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/maint/toggle":
            with core.CONFIG_LOCK:
                for w in core.CONFIG.get("maintenance", []):
                    if w["id"] == data.get("id"):
                        w["enabled"] = not w.get("enabled", True)
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/dhcp":
            with core.CONFIG_LOCK:
                dw = core.CONFIG.setdefault("dhcp_watch", {})
                if "enabled" in data:
                    dw["enabled"] = bool(data["enabled"])
                if data.get("interval_minutes") is not None:
                    dw["interval_minutes"] = max(5, int(data["interval_minutes"]))
                if data.get("relearn"):
                    dw["expected"] = []   # next probe re-learns the trusted set
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/netscan":
            with core.CONFIG_LOCK:
                ns = core.CONFIG.setdefault("netscan", {})
                if "enabled" in data:
                    ns["enabled"] = bool(data["enabled"])
                if data.get("interval_minutes") is not None:
                    ns["interval_minutes"] = max(5, int(data["interval_minutes"]))
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/hosts/priority":
            hid, pr = data.get("id"), data.get("priority")
            pr = pr if pr in ("critical", "watch") else "normal"
            def setpr(hs):
                for h in hs:
                    if h["id"] == hid:
                        h["priority"] = pr
                return hs
            self._mutate_hosts(setpr)
            self._send({"ok": True})
        elif path == "/api/quiet":
            bad = [k for k in ("from", "to") if data.get(k) is not None
                   and policy._hhmm_minutes(data[k]) is None]
            if bad:
                return self._send({"ok": False, "error": "время в формате ЧЧ:ММ"}, 400)
            with core.CONFIG_LOCK:
                qc = core.CONFIG.setdefault("quiet", {})
                if "enabled" in data:
                    qc["enabled"] = bool(data["enabled"])
                if "digest" in data:
                    qc["digest"] = bool(data["digest"])
                for k in ("from", "to"):
                    if data.get(k) is not None:
                        qc[k] = str(data[k])
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/wan":
            with core.CONFIG_LOCK:
                w = core.CONFIG.setdefault("wan", {})
                if "enabled" in data:
                    w["enabled"] = bool(data["enabled"])
                for k in ("gateway", "external", "dns_probe", "dns_server"):
                    if data.get(k) is not None:
                        w[k] = str(data[k]).strip()
                if data.get("interval_seconds") is not None:
                    w["interval_seconds"] = max(15, int(data["interval_seconds"]))
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/update":
            action = data.get("action")
            if action not in ("update", "rollback"):
                return self._send({"ok": False, "error": "action: update | rollback"}, 400)
            ok, msg = update.update_start(action, by="дашборд")
            self._send({"ok": ok, "message" if ok else "error": msg}, 200 if ok else 409)
        elif path == "/api/auth/set":
            self._auth_set(data)
        elif path == "/api/auth/disable":
            a = core.cfg("auth", {}) or {}
            if webauth.auth_enabled() and not webauth.verify_password(data.get("current") or ""):
                return self._send({"ok": False, "error": "неверный текущий пароль"}, 403)
            with core.CONFIG_LOCK:
                a = core.CONFIG.setdefault("auth", {})
                a["enabled"] = False
                a["password_hash"] = ""
                a["salt"] = ""
                webauth._bump_epoch(a)
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/auth/logout-all":
            webauth.revoke_all_sessions()
            self._send({"ok": True})
        elif path == "/api/token/generate":
            new_tok = secrets.token_urlsafe(32)
            with core.CONFIG_LOCK:
                core.CONFIG.setdefault("api", {})["token"] = new_tok
                core.save_config()
            # shown to the user exactly once; UI stores only "a token exists"
            self._send({"ok": True, "token": new_tok})
        elif path == "/api/token/revoke":
            with core.CONFIG_LOCK:
                core.CONFIG.setdefault("api", {})["token"] = ""
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/schedule/add":
            self._add_schedule(data)
        elif path == "/api/schedule/delete":
            with core.CONFIG_LOCK:
                core.CONFIG["wol_schedule"] = [r for r in core.CONFIG.get("wol_schedule", [])
                                          if r["id"] != data.get("id")]
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/schedule/toggle":
            with core.CONFIG_LOCK:
                for r in core.CONFIG.get("wol_schedule", []):
                    if r["id"] == data.get("id"):
                        r["enabled"] = not r.get("enabled", True)
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/schedule/run":
            rule = next((r for r in (core.cfg("wol_schedule", []) or [])
                         if r["id"] == data.get("id")), None)
            if not rule:
                return self._send({"ok": False, "error": "правило не найдено"}, 404)
            threading.Thread(target=wolschedule.run_schedule_rule, args=(dict(rule),), daemon=True).start()
            self._send({"ok": True, "targets": len(wolschedule.schedule_targets(rule))})
        elif path == "/api/subnets/delete":
            with core.CONFIG_LOCK:
                core.CONFIG["subnets"] = [s for s in core.CONFIG.get("subnets", []) if s["id"] != data.get("id")]
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/subnets/scan":
            self._scan_subnet(data)
        elif path == "/api/settings":
            self._save_settings(data)
        elif path == "/api/degradation":
            with core.CONFIG_LOCK:
                dg = core.CONFIG.setdefault("degradation", {})
                if "enabled" in data:
                    dg["enabled"] = bool(data["enabled"])
                if data.get("ratio_threshold") is not None:
                    dg["ratio_threshold"] = max(1.2, float(data["ratio_threshold"]))
                if data.get("sustain_minutes") is not None:
                    dg["sustain_minutes"] = max(1, int(data["sustain_minutes"]))
                core.save_config()
            degradation._BASELINE_CACHE.clear()  # thresholds changed — re-judge from scratch
            self._send({"ok": True})
        elif path == "/api/runbook":
            with core.CONFIG_LOCK:
                rb = core.CONFIG.setdefault("runbook", {})
                if "enabled" in data:
                    rb["enabled"] = bool(data["enabled"])
                if "auto_wake" in data:
                    rb["auto_wake"] = bool(data["auto_wake"])
                if data.get("recheck_after_seconds") is not None:
                    rb["recheck_after_seconds"] = max(15, int(data["recheck_after_seconds"]))
                core.save_config()
            self._send({"ok": True})
        elif path == "/api/heartbeat":
            self._save_heartbeat(data)
        elif path == "/api/heartbeat/test":
            url = ((core.cfg("heartbeat", {}) or {}).get("url") or "").strip()
            if not url:
                self._send({"ok": False, "detail": "не задан Ping URL"})
            else:
                ok, detail = degradation.ping_heartbeat(url)
                self._send({"ok": ok, "detail": detail})
        elif path == "/api/telegram":
            self._save_telegram(data)
        elif path == "/api/telegram/detect":
            chats, err = alerting.tg_detect_chats()
            self._send({"ok": err is None, "chats": chats or [], "error": err})
        elif path == "/api/telegram/test":
            ok, detail = telegram.tg_send("✅ Тестовое сообщение от Филина.", queue=False)
            self._send({"ok": ok, "detail": detail})
        else:
            self._send({"error": "not found"}, 404)

    # -- mutations ---------------------------------------------------------
    def _mutate_hosts(self, fn):
        with core.CONFIG_LOCK:
            core.CONFIG["hosts"] = fn(core.CONFIG.get("hosts", []))
            core.save_config()
        livestate.reconcile_state()

    def _add_host(self, d):
        t = d.get("type", "ping")
        name = (d.get("name") or "").strip()
        host = (d.get("host") or "").strip()
        url = (d.get("url") or "").strip()
        if t == "http" and not url:
            return self._send({"ok": False, "error": "нужен URL"}, 400)
        if t in ("ping", "tcp", "host") and not host:
            return self._send({"ok": False, "error": "нужен хост/IP"}, 400)
        if t == "tcp" and not d.get("port"):
            return self._send({"ok": False, "error": "нужен порт"}, 400)
        if not name:
            name = url or (f"{host}:{d.get('port')}" if t == "tcp" else host)
        mac = (d.get("mac") or "").strip()
        if mac:
            try:
                checks.normalize_mac(mac)
            except ValueError as e:
                return self._send({"ok": False, "error": str(e)}, 400)
        new = {
            "id": uuid.uuid4().hex[:8], "name": name, "type": t,
            "host": host, "port": int(d.get("port") or 0), "url": url,
            "expect": (d.get("expect") or "").strip(),
            "mac": mac, "broadcast": (d.get("broadcast") or "").strip(),
            "parent": (d.get("parent") or "").strip(),
            "priority": d.get("priority") if d.get("priority") in ("critical", "watch") else "normal",
            "role": "ap" if d.get("role") == "ap" else "",
            "enabled": True, "source": "manual",
        }
        with core.CONFIG_LOCK:
            core.CONFIG.setdefault("hosts", []).append(new)
            core.save_config()
        livestate.reconcile_state()
        self._send({"ok": True, "host": new})

    def _network_scan(self, d):
        """Ping-sweep the given (or all configured) subnets, diff against the
        last snapshot, alert on new devices and MAC changes."""
        cidr = (d.get("cidr") or "").strip()
        res = netinventory.run_network_scan([cidr] if cidr else None)
        if res is None:
            return self._send({"ok": False, "error": "нет подсетей — добавь хотя бы одну"}, 400)
        netinventory.alert_network_changes(res["appeared"], res["changed"])
        self._send(dict(res, ok=True))

    def _inventory_scan(self, d):
        """Identify one host, or every host that has an IP."""
        with core.CONFIG_LOCK:
            hosts = [dict(h) for h in core.CONFIG.get("hosts", [])]
        if d.get("id"):
            hosts = [h for h in hosts if h["id"] == d["id"]]
            if not hosts:
                return self._send({"ok": False, "error": "хост не найден"}, 404)
        else:
            hosts = [h for h in hosts if h.get("host")]  # http-only targets have no IP
        if not hosts:
            return self._send({"ok": False, "error": "нечего опрашивать"}, 400)

        results = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            for inv in pool.map(lambda h: dhcp._safe_probe(h), hosts):
                if inv:
                    storage.db_inventory_save(inv)
                    results.append(inv)
        # a probe may discover a MAC the host record didn't have — keep it for WoL
        with core.CONFIG_LOCK:
            by_id = {h["id"]: h for h in core.CONFIG.get("hosts", [])}
            changed = False
            for inv in results:
                h = by_id.get(inv["host_id"])
                if h is not None and inv["mac"] and not h.get("mac"):
                    h["mac"] = inv["mac"]
                    changed = True
            if changed:
                core.save_config()
        self._send({"ok": True, "scanned": len(results)})

    def _wake_host(self, d):
        with core.CONFIG_LOCK:
            h = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == d.get("id")), None)
        if not h:
            return self._send({"ok": False, "error": "хост не найден"}, 404)
        if not h.get("mac"):
            return self._send({"ok": False, "error": "у хоста не задан MAC"}, 400)
        try:
            target = checks.send_wol(h["mac"], h.get("broadcast") or None)
        except Exception as e:
            return self._send({"ok": False, "error": core.short_err(e)}, 400)
        print(f"[wol] magic packet -> {h['name']} ({h['mac']}) via {target}")
        self._send({"ok": True, "sent_to": target, "mac": h["mac"]})

    def _add_schedule(self, d):
        t = str(d.get("time") or "").strip()
        try:
            hh, mm = t.split(":")[:2]
            hh, mm = int(hh), int(mm)
            assert 0 <= hh <= 23 and 0 <= mm <= 59
        except (ValueError, IndexError, AssertionError):
            return self._send({"ok": False, "error": "время в формате ЧЧ:ММ (пример: 08:30)"}, 400)
        days = [int(x) for x in (d.get("days") or []) if 0 <= int(x) <= 6]
        new = {
            "id": uuid.uuid4().hex[:8],
            "name": (d.get("name") or "").strip() or f"{hh:02d}:{mm:02d}",
            "time": f"{hh:02d}:{mm:02d}",
            "days": days,
            "hosts": [str(x) for x in (d.get("hosts") or [])],
            "verify": bool(d.get("verify", True)),
            "enabled": True,
        }
        with core.CONFIG_LOCK:
            core.CONFIG.setdefault("wol_schedule", []).append(new)
            core.save_config()
        self._send({"ok": True, "rule": new, "targets": len(wolschedule.schedule_targets(new))})

    def _add_subnet(self, d):
        cidr = (d.get("cidr") or "").strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return self._send({"ok": False, "error": "неверный CIDR (пример: 192.168.1.0/24)"}, 400)
        new = {
            "id": uuid.uuid4().hex[:8], "cidr": cidr,
            "type": d.get("type", "ping"), "port": int(d.get("port") or 0),
            "parent": (d.get("parent") or "").strip(),
            "enabled": True,
        }
        with core.CONFIG_LOCK:
            core.CONFIG.setdefault("subnets", []).append(new)
            core.save_config()
        self._send({"ok": True, "subnet": new})

    def _scan_subnet(self, d):
        with core.CONFIG_LOCK:
            sub = next((s for s in core.CONFIG.get("subnets", []) if s["id"] == d.get("id")), None)
        if not sub:
            return self._send({"ok": False, "error": "подсеть не найдена"}, 404)
        alive = status.scan_subnet(sub["cidr"], timeout=core.cfg("timeout_seconds", 3))
        # The sweep just populated the OS ARP cache — harvest MACs for Wake-on-LAN.
        arp = dhcp.arp_table()
        # Add newly discovered hosts (skip ones already tracked by target)
        with core.CONFIG_LOCK:
            existing = {h.get("host") for h in core.CONFIG.get("hosts", [])}
            added = []
            for ip in alive:
                if ip in existing:
                    continue
                stype = sub.get("type", "ping")
                new = {
                    "id": uuid.uuid4().hex[:8],
                    "name": ip, "type": stype, "host": ip,
                    "port": int(sub.get("port") or 0), "url": "",
                    "mac": arp.get(ip, ""), "broadcast": "",
                    "parent": sub.get("parent", ""),
                    "enabled": True, "source": "subnet",
                }
                core.CONFIG.setdefault("hosts", []).append(new)
                added.append(new)
            core.save_config()
        livestate.reconcile_state()
        self._send({"ok": True, "alive": alive, "added": len(added)})

    def _save_settings(self, d):
        with core.CONFIG_LOCK:
            for k in ("app_name",):
                if d.get(k):
                    core.CONFIG[k] = d[k]
            for k in ("check_interval_seconds", "timeout_seconds", "fail_threshold"):
                if d.get(k) is not None:
                    core.CONFIG[k] = max(1, int(d[k]))
            al = core.CONFIG.setdefault("alerts", {})
            if d.get("storm_threshold") is not None:
                al["storm_threshold"] = max(2, int(d["storm_threshold"]))
            if d.get("parent_suppression") is not None:
                al["parent_suppression"] = bool(d["parent_suppression"])
            if d.get("trace_on_down") is not None:
                al["trace_on_down"] = bool(d["trace_on_down"])
            if d.get("ip_conflict") is not None:
                al["ip_conflict"] = bool(d["ip_conflict"])
            if d.get("escalate_after_minutes") is not None:
                al["escalate_after_minutes"] = max(0, int(d["escalate_after_minutes"] or 0))
            if d.get("escalate_chat_id") is not None:
                al["escalate_chat_id"] = str(d["escalate_chat_id"]).strip()
            if d.get("passive_listen") is not None:
                al["passive_listen"] = bool(d["passive_listen"])
            if d.get("hold_down_seconds") is not None:
                al["hold_down_seconds"] = max(0, int(d["hold_down_seconds"] or 0))
            if d.get("hold_down_skip_critical") is not None:
                al["hold_down_skip_critical"] = bool(d["hold_down_skip_critical"])
            core.save_config()
        self._send({"ok": True})

    def _save_heartbeat(self, d):
        with core.CONFIG_LOCK:
            hb = core.CONFIG.setdefault("heartbeat", {})
            if "url" in d:
                hb["url"] = (d["url"] or "").strip()
            if "enabled" in d:
                hb["enabled"] = bool(d["enabled"])
            if d.get("interval_minutes") is not None:
                hb["interval_minutes"] = max(1, int(d["interval_minutes"]))
            core.save_config()
        self._send({"ok": True})

    def _save_telegram(self, d):
        with core.CONFIG_LOCK:
            tg = core.CONFIG.setdefault("telegram", {})
            if "bot_token" in d and d["bot_token"].strip():
                tg["bot_token"] = d["bot_token"].strip()
            if "chat_id" in d:
                tg["chat_id"] = str(d["chat_id"]).strip()
            if "poll_updates" in d:
                tg["poll_updates"] = bool(d["poll_updates"])
            if "site_prefix" in d:
                tg["site_prefix"] = bool(d["site_prefix"])
            core.save_config()
        self._send({"ok": True, "ready": telegram.telegram_ready()})


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import wifi, unifi, dahua, video, update  # noqa: E402
