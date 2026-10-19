"""UniFi controller as an RF source; AP online/offline alerts."""

import hashlib
import html
import http.cookiejar
import json
import os
import ssl
import threading
import time
from urllib import request as urlrequest

from . import core, storage, alerting, policy


# ============================================================================
# UniFi controller as an RF + AP-liveness source.
#
# Every adopted AP already listens to the air, so each one is modelled as a
# Wi-Fi *sensor* named "unifi:<ap>". Its own VAPs (from vap_table) are stored
# trusted — the controller is ground truth for "what is ours", which makes
# evil-twin detection exact instead of learned — and whatever that AP reports in
# stat/rogueap is stored untrusted. Everything downstream (evil-twin, rogue,
# channel conflict, the Wi-Fi tab) is the existing code, unchanged.
#
# Read-only Viewer account; credentials live outside the repo in
# ~/.config/signal-desk/unifi.json and are never logged or sent anywhere.
# ============================================================================
UNIFI_PREFIX = "unifi:"


_UNIFI = {"ok": False, "error": "", "last_poll": 0, "aps": [],
          "rogue_raw": 0, "rogue_bssids": 0, "own_bssids": 0, "ssids": []}


_UNIFI_LOCK = threading.Lock()


_UNIFI_DOWN = set()          # AP names currently reported offline (alert edges)


def unifi_creds_paths():
    """Every place the Viewer credentials may live, in priority order.

    `~` alone is a trap here: on the office box the monitor runs as a scheduled task
    under SYSTEM, whose home is C:\\Windows\\system32\\config\\systemprofile — not the
    operator's profile, so a file dropped in C:\\Users\\<name> is invisible to it.
    Hence app_dir() (next to the exe, alongside config.json) comes first, and an
    explicit UNIFI_CREDS env var overrides everything."""
    out = []
    env = (os.environ.get("UNIFI_CREDS") or "").strip()
    if env:
        out.append(env)
    out.append(os.path.join(core.app_dir(), "unifi.json"))
    out.append(os.path.join(os.path.expanduser("~"), ".config", "signal-desk", "unifi.json"))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p); uniq.append(p)
    return uniq


def unifi_creds():
    """(username, password) from the first readable secrets file, else None.
    The password is never logged, echoed, or written back anywhere."""
    for p in unifi_creds_paths():
        try:
            with open(p, "rb") as f:
                d = json.loads(f.read().decode("utf-8-sig"))
            u, pw = (d.get("username") or "").strip(), d.get("password") or ""
            if u and pw:
                return (u, pw)
        except Exception:
            continue
    return None


class UnifiPin:
    """Trust-on-first-use pin for the controller's self-signed certificate.
    Chain verification can't work (self-signed), but "is this the same
    controller as last time" can — and it must, because the next request
    carries the Viewer password."""

    def __init__(self, pin=None):
        self.pin = (pin or "").lower() or None
        self.seen = None
        self.mismatch = False

    def check(self, der):
        self.seen = hashlib.sha256(der or b"").hexdigest()
        if self.pin and self.seen != self.pin:
            self.mismatch = True
            raise ssl.SSLError(f"сертификат контроллера не совпадает с закреплённым "
                               f"(сейчас {self.seen[:16]}…)")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *a, pin=None, **kw):
        super().__init__(*a, **kw)
        self.unifi_pin = pin

    def connect(self):
        super().connect()
        try:
            self.unifi_pin.check(self.sock.getpeercert(binary_form=True))
        except ssl.SSLError:
            self.sock.close()   # before a single byte of the login goes out
            raise


class _PinnedHTTPSHandler(urlrequest.HTTPSHandler):
    def __init__(self, context, pin):
        super().__init__(context=context)
        self._ctx, self._pin = context, pin

    def https_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedHTTPSConnection(host, pin=self._pin, **kw),
                            req, context=self._ctx)


class UnifiClient:
    """Classic self-hosted Network Server API (:8443): cookie session + CSRF echo.
    The controller ships a self-signed cert: chain verification is off, the
    certificate itself is pinned on first use (UnifiPin)."""

    def __init__(self, base, site, pin=None):
        self.base = (base or "").rstrip("/")
        self.site = site or "default"
        self.jar = http.cookiejar.CookieJar()
        self.pin = UnifiPin(pin)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.op = urlrequest.build_opener(
            urlrequest.HTTPCookieProcessor(self.jar),
            _PinnedHTTPSHandler(ctx, self.pin))

    def _csrf(self):
        for c in self.jar:
            if c.name in ("csrf_token", "TOKEN"):
                return c.value
        return None

    def call(self, path, body=None, timeout=20):
        data = json.dumps(body).encode() if body is not None else None
        req = urlrequest.Request(self.base + path, data=data,
                                 method="POST" if data else "GET")
        req.add_header("Content-Type", "application/json")
        tok = self._csrf()
        if tok:
            req.add_header("X-Csrf-Token", tok)
        with self.op.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def login(self, user, pwd):
        self.call("/api/login", {"username": user, "password": pwd})

    def stat(self, tail):
        return (self.call("/api/s/%s/stat/%s" % (self.site, tail)) or {}).get("data", [])


_UNIFI_RADIO = {"na": "5 ГГц", "ng": "2.4 ГГц", "ac": "5 ГГц", "ax": "5 ГГц"}


def unifi_rows(dev, rogues_by_ap, own_other):
    """Pure: one AP's dict + the rogues it saw -> (own_rows, foreign_rows) in the
    same shape wifi_scan() produces. own_other = lowercased SSIDs of ours that run
    on other hardware; the controller can only see those as foreign."""
    own = []
    for v in (dev.get("vap_table") or []):
        b = (v.get("bssid") or "").lower().strip()
        if not b:
            continue
        own.append({"ssid": v.get("essid") or "", "bssid": b, "signal": 100,
                    "channel": v.get("channel"), "auth": "",
                    "radio": _UNIFI_RADIO.get(v.get("radio") or "", v.get("radio") or "")})
    foreign = []
    for r in rogues_by_ap:
        b = (r.get("bssid") or "").lower().strip()
        if not b:
            continue
        foreign.append({"ssid": r.get("essid") or "", "bssid": b,
                        "signal": r.get("rssi"), "channel": r.get("channel"),
                        "auth": r.get("security") or "",
                        "radio": _UNIFI_RADIO.get(r.get("radio") or "", r.get("band") or ""),
                        "ours_elsewhere": (r.get("essid") or "").strip().lower() in own_other})
    return own, foreign


def _unifi_store(sensor, rows, now, trusted_default):
    """Upsert scan rows for one pseudo-sensor. trusted_default forces trust for
    our own VAPs (and for our SSIDs living on other gear); otherwise an existing
    trust flag is preserved so operator decisions survive a poll."""
    for b in rows:
        bssid = b["bssid"]
        force = trusted_default or b.get("ours_elsewhere")
        row = storage._db.execute(
            "SELECT first_seen, trusted FROM wifi_seen WHERE bssid=? AND sensor=?",
            (bssid, sensor)).fetchone()
        first = row[0] if row else now
        trusted = 1 if force else (row[1] if row else 0)
        storage._db.execute(
            "INSERT OR REPLACE INTO wifi_seen "
            "(bssid,sensor,ssid,signal,channel,radio,auth,first_seen,last_seen,trusted) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (bssid, sensor, b.get("ssid", ""), b.get("signal"), b.get("channel"),
             b.get("radio", ""), b.get("auth", ""), first, now, trusted))


def unifi_alert_allowed(a):
    """Alert policy for the UniFi source. The netsh rules assume one trusted BSSID
    per mesh node in a quiet office; a controller in a shopping centre breaks both
    assumptions, so two rules are muted rather than rewritten:
      * chanconflict — an AP serves several SSIDs on one radio, so BSSIDs sharing
        a channel is the normal case here, not interference;
      * rogue — every customer's phone hotspot is a "new AP"; neighbours are
        listed in the Wi-Fi tab instead (opt in via unifi.alert_rogue).
    Evil-twin still fires: that one is worth waking someone for."""
    if not (a.get("sensor") or "").startswith(UNIFI_PREFIX):
        return True
    if a["type"] == "chanconflict":
        return False
    if a["type"] == "rogue":
        return bool((core.cfg("unifi", {}) or {}).get("alert_rogue"))
    return True


def unifi_evaluate():
    """One poll: pull devices + rogues, feed the Wi-Fi pipeline, alert on APs
    that dropped off the controller."""
    u = core.cfg("unifi", {}) or {}
    creds = unifi_creds()
    if not creds:
        with _UNIFI_LOCK:
            _UNIFI.update(ok=False, error="нет файла с кредами (~/.config/signal-desk/unifi.json)")
        return
    cl = UnifiClient(u.get("url") or "https://127.0.0.1:8443", u.get("site") or "default",
                     u.get("cert_sha256"))
    try:
        cl.login(*creds)
    except Exception:
        if cl.pin.mismatch:
            unifi_pin_alarm(cl.pin.seen)
            return
        raise
    _UNIFI_PIN_ALARM.clear()
    if not cl.pin.pin and cl.pin.seen:
        with core.CONFIG_LOCK:
            core.CONFIG.setdefault("unifi", {})["cert_sha256"] = cl.pin.seen
            core.save_config()
        print(f"[unifi] сертификат контроллера закреплён: {cl.pin.seen}")
    devices = cl.stat("device")
    rogues = cl.stat("rogueap")

    own_other = set(s.strip().lower() for s in (u.get("own_other_ssids") or []) if s.strip())
    by_ap = {}
    for r in rogues:
        by_ap.setdefault((r.get("ap_mac") or "").lower(), []).append(r)

    now = time.time()
    aps, ssids, own_n, seen_bssids = [], set(), 0, set()
    online_sensors, offline_names = [], []
    with storage._db_lock:
        for d in devices:
            name = (d.get("name") or d.get("mac") or "?").strip()
            sensor = UNIFI_PREFIX + name
            up = (d.get("state") == 1)
            own, foreign = unifi_rows(d, by_ap.get((d.get("mac") or "").lower(), []), own_other)
            aps.append({"name": name, "mac": d.get("mac"), "ip": d.get("ip"),
                        "model": d.get("model"), "version": d.get("version"),
                        "state": d.get("state"), "online": up,
                        "clients": d.get("num_sta"), "uptime": d.get("uptime"),
                        "upgradable": bool(d.get("upgradable")),
                        "neighbours": len(foreign)})
            if not up:
                # an offline AP is not an eye on the air: drop its sensor row so the
                # generic "sensor silent"/"radio gone" rules can't double-report it —
                # the explicit AP alert below owns this condition
                offline_names.append(name)
                storage._db.execute("DELETE FROM wifi_sensors WHERE sensor=?", (sensor,))
                continue
            _unifi_store(sensor, own, now, True)
            _unifi_store(sensor, foreign, now, False)
            for r in own:
                ssids.add(r["ssid"])
            own_n += len(own)
            for r in foreign:
                seen_bssids.add(r["bssid"])
            online_sensors.append(sensor)
        for s in online_sensors:
            storage._db.execute("INSERT OR REPLACE INTO wifi_sensors (sensor, last_report) VALUES (?,?)",
                        (s, now))
        storage._db.commit()

    with _UNIFI_LOCK:
        _UNIFI.update(ok=True, error="", last_poll=now,
                      aps=sorted(aps, key=lambda a: a["name"]),
                      rogue_raw=len(rogues), rogue_bssids=len(seen_bssids),
                      own_bssids=own_n, ssids=sorted(x for x in ssids if x))

    # An empty-but-successful device list (controller still starting) said
    # nothing about the APs — it used to announce every down AP "снова на связи".
    if u.get("alert_ap_offline", True) and aps:
        unifi_ap_alerts(set(offline_names))


# ----------------------------------------------------------------------------
# AP offline/online. 10-13 19:25 nine APs dropped (the mall powers them down
# for the night) and came back at 07:23: 18 single messages, the 07:23 batch
# inside quiet hours. Now: one message per poll; recovery only for APs whose
# drop was announced; an AP quiet window (default = quiet hours); and when the
# same APs drop at the same time as yesterday, a button to make it a window.
# ----------------------------------------------------------------------------

_UNIFI_AP_TOLD = set()   # AP names whose "отвалилась" went out (persisted)


UNIFI_AP_LOG = {}        # "ts" -> {"kind": "down"|"up", "names": [...]}, 3 days (persisted)


def ap_quiet_now(lt=None):
    """AP alerts' own quiet window if set, otherwise the general quiet hours."""
    w = (core.cfg("unifi", {}) or {}).get("ap_quiet") or {}
    if w.get("from") and w.get("to"):
        return policy.in_window(lt or time.localtime(), w["from"], w["to"])
    return policy.quiet_now(lt)


def _ap_list(names):
    names = sorted(names)
    return ", ".join(f"«{html.escape(n)}»" for n in names[:20]) + (
        f" и ещё {len(names) - 20}" if len(names) > 20 else "")


def _ap_pattern(names, now):
    """Same APs dropped ~24h ago? -> (from, to) of a window that would have
    covered it: 30 min before the drop, 30 min after the following recovery."""
    names = set(names)
    best = None
    for ts, e in UNIFI_AP_LOG.items():
        t = float(ts)
        if e["kind"] != "down" or not (20 * 3600 <= now - t <= 28 * 3600):
            continue
        if len(names & set(e["names"])) * 2 >= len(names):
            best = t
    if best is None:
        return None
    ups = sorted(float(ts) for ts, e in UNIFI_AP_LOG.items()
                 if e["kind"] == "up" and float(ts) > best and set(e["names"]) & names)
    def hhmm(t, shift, round_up):
        lt = time.localtime(t)
        m = lt.tm_hour * 60 + lt.tm_min + shift
        m = ((m + 4) // 5 * 5 if round_up else m // 5 * 5) % 1440
        return f"{m // 60:02d}:{m % 60:02d}"
    frm = hhmm(best, -30, False)
    to = hhmm(ups[0], 30, True) if ups else (core.cfg("quiet", {}) or {}).get("to", "08:00")
    return frm, to


def unifi_ap_alerts(now_down, now=None, lt=None):
    now = now or time.time()
    prev = set(_UNIFI_DOWN)
    gone, back = sorted(now_down - prev), sorted(prev - now_down)
    for kind, names in (("down", gone), ("up", back)):
        if names:
            UNIFI_AP_LOG[str(int(now))] = {"kind": kind, "names": names}
    for ts in [k for k in UNIFI_AP_LOG if now - float(k) > 3 * 86400]:
        del UNIFI_AP_LOG[ts]
    _UNIFI_DOWN.clear()
    _UNIFI_DOWN.update(now_down)

    if ap_quiet_now(lt):
        return   # nothing rings; leftovers are announced when the window ends
    new = sorted(now_down - _UNIFI_AP_TOLD)
    if new:
        head = (f"Точка {_ap_list(new)} отвалилась от контроллера UniFi" if len(new) == 1
                else f"От контроллера UniFi отвалились {len(new)} точек: {_ap_list(new)}")
        markup = None
        pat = _ap_pattern(new, now) if len(new) >= 2 else None
        if pat:
            head += (f"\n\n🌙 Вчера в это же время отвалились те же точки — похоже на "
                     f"плановое отключение на ночь.")
            markup = json.dumps({"inline_keyboard": [[
                {"text": f"🌙 Не сообщать о точках {pat[0]}–{pat[1]}",
                 "callback_data": f"ap:q:{pat[0].replace(':', '')}:{pat[1].replace(':', '')}"}],
                [{"text": "🔕 Все алерты UniFi — на сутки", "callback_data": "flt:q:unifi"}]]})
        ok, detail = alerting.emit("unifi", f"📶 <b>Wi-Fi</b>\n{head}", markup=markup)
        if ok and detail not in ("muted", "maintenance"):
            _UNIFI_AP_TOLD.update(new)
    back_told = sorted(_UNIFI_AP_TOLD - now_down)
    if back_told:
        head = (f"Точка {_ap_list(back_told)} снова на связи" if len(back_told) == 1
                else f"Снова на связи {len(back_told)} точек: {_ap_list(back_told)}")
        alerting.emit("unifi", f"✅ <b>Wi-Fi</b>\n{head}")
        _UNIFI_AP_TOLD.difference_update(back_told)


_UNIFI_PIN_ALARM = set()   # fingerprints already alerted about


def unifi_pin_alarm(seen):
    """Certificate changed: the login was NOT sent. Either the controller was
    reinstalled/upgraded (reset the pin) or something in the LAN is answering
    for it — the same LAN where rogue DHCP is a known risk. Not kind-mutable."""
    msg = "сертификат контроллера сменился — логин не отправлен"
    with _UNIFI_LOCK:
        _UNIFI.update(ok=False, error=msg)
    if seen in _UNIFI_PIN_ALARM:
        return
    _UNIFI_PIN_ALARM.add(seen)
    alerting.emit("security", "🚨 <b>UniFi</b>\nСертификат контроллера не совпадает с закреплённым — "
            "логин и пароль <b>не отправлены</b>.\n"
            "Обновляли или переустанавливали контроллер — Настройки → Wi-Fi → UniFi → "
            "«Сбросить отпечаток». Не обновляли — кто-то в сети отвечает вместо контроллера.")


def unifi_view():
    with _UNIFI_LOCK:
        st = dict(_UNIFI)
    u = core.cfg("unifi", {}) or {}
    st["config"] = {k: u.get(k) for k in
                    ("enabled", "url", "site", "interval_seconds", "own_other_ssids",
                     "alert_ap_offline", "alert_rogue", "cert_sha256", "ap_quiet")}
    st["has_creds"] = unifi_creds() is not None
    st["creds_paths"] = unifi_creds_paths()      # shown in the UI so "no file" is self-diagnosing
    st["ago_sec"] = int(time.time() - st["last_poll"]) if st.get("last_poll") else None
    st["online"] = sum(1 for a in st.get("aps", []) if a.get("online"))
    st["clients"] = sum((a.get("clients") or 0) for a in st.get("aps", []))
    return st


# The controller itself (Java on an office PC) going away used to be silent:
# the loop printed the error and the Wi-Fi checks quietly stopped — silence
# that looks exactly like "all APs fine". Persisted in runtime_state.
UNIFI_CTRL = {"fails": 0, "since": 0.0, "announced": False}


UNIFI_CTRL_FAILS = 3


def unifi_health(ok, error, now=None):
    """Feed one poll result; alerts on the 3rd consecutive failure, and on the
    recovery of an outage that was announced."""
    now = now or time.time()
    st = UNIFI_CTRL
    if ok:
        if st["announced"]:
            alerting.emit("unifi", f"✅ <b>Wi-Fi</b>\nКонтроллер UniFi снова отвечает "
                          f"(не отвечал {alerting.fmt_duration(now - st['since'])})")
        st.update(fails=0, since=0.0, announced=False)
        return
    st["fails"] += 1
    st["since"] = st["since"] or now
    if st["fails"] >= UNIFI_CTRL_FAILS and not st["announced"]:
        st["announced"] = True
        alerting.emit("unifi", f"🔴 <b>Wi-Fi</b>\nКонтроллер UniFi не отвечает "
                      f"{alerting.fmt_duration(now - st['since'])}: {html.escape(error or '?')}\n"
                      f"Точки и эфир сейчас не контролируются.")


def unifi_loop():
    while True:
        u = core.cfg("unifi", {}) or {}
        try:
            if u.get("enabled"):
                unifi_evaluate()
                with _UNIFI_LOCK:
                    ok, err = _UNIFI.get("ok"), _UNIFI.get("error")
                # no creds / pin mismatch have their own message — not "controller down"
                if ok or not (err or "").startswith(("нет файла", "сертификат")):
                    unifi_health(bool(ok), err)
        except Exception as e:
            with _UNIFI_LOCK:
                _UNIFI.update(ok=False, error=core.short_err(e))
            print(f"[unifi] error: {core.short_err(e)}")
            unifi_health(False, core.short_err(e))
        try:
            interval = max(15, int(u.get("interval_seconds") or 60))
        except (TypeError, ValueError):
            interval = 60
        time.sleep(interval)
