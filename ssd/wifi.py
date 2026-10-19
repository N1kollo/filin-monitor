"""Wi-Fi: netsh sensors, evil-twin / rogue / dead-radio detection."""

import html
import json
import re
import socket
import subprocess
import time

from . import core, storage, alerting


# ============================================================================
# Wi-Fi / rogue-AP monitoring (D47).
# The brain box is wired and has no radio, so RF is scanned by *sensor* instances
# — `monitor.py --wifi-sensor <brain-url> <token> [name]` on a Windows box with a
# WiFi adapter, one per floor / RF domain. Sensors POST scans to the brain's
# /api/wifi/report; the brain learns a baseline of trusted BSSIDs and correlates
# the RF view with LAN liveness. All stdlib: netsh for the scan, urllib to report.
# ============================================================================
_MAC_RE = re.compile(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})')


def wifi_scan():
    """Visible WiFi via `netsh wlan show networks mode=bssid` (Windows, stdlib).
    One row per BSSID: {ssid, auth, bssid, signal, channel, radio}. Language- and
    codepage-agnostic (keys off 'SSID N'/'BSSID N'/MAC/'%'/802.11, not localized
    labels). Returns [] on non-Windows / no adapter / error — never raises."""
    try:
        p = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                           capture_output=True, timeout=20)
    except Exception:
        return []
    raw = p.stdout or b""
    text = None
    for enc in ("cp866", "cp437", "utf-8", "cp1251"):
        try:
            text = raw.decode(enc); break
        except Exception:
            continue
    if text is None:
        text = raw.decode("latin-1", "replace")
    out, ssid, auth, bss = [], None, "", None
    for line in text.splitlines():
        s = line.strip()
        if re.match(r'^SSID\s+\d+\s*:', s):
            ssid = s.split(":", 1)[1].strip(); auth = ""; bss = None
            continue
        if ssid is None:
            continue
        if not auth:
            m = re.search(r'(WPA3\S*|WPA2\S*|WPA\S*|WEP|Open|Открыт)', s, re.I)
            if m and 'BSSID' not in s and ':' in s:
                auth = m.group(1)
        if re.match(r'^BSSID\s+\d+\s*:', s):
            mac = _MAC_RE.search(s)
            bss = {"ssid": ssid, "auth": auth,
                   "bssid": (mac.group(1).lower() if mac else ""),
                   "signal": None, "channel": None, "radio": ""}
            if bss["bssid"]:
                out.append(bss)
            continue
        if bss is None:
            continue
        if bss["signal"] is None and s.endswith("%"):
            m = re.search(r'(\d+)\s*%', s)
            if m: bss["signal"] = int(m.group(1))
        if not bss["radio"]:
            m = re.search(r'(802\.11\S+)', s)
            if m: bss["radio"] = m.group(1)
        if bss["channel"] is None:
            m = re.match(r'^[^:]+:\s*(\d{1,3})\s*$', s)
            if m and not s.lstrip().startswith(("SSID", "BSSID")):
                v = int(m.group(1))
                if 1 <= v <= 196: bss["channel"] = v
    return out


def wifi_sensor_main(brain_url, token, name="", interval=60):
    """Sensor loop: scan RF, POST to the brain. Runs instead of the full monitor."""
    import urllib.request
    name = (name or socket.gethostname())[:64]
    url = brain_url.rstrip("/") + "/api/wifi/report"
    print(f"== Wi-Fi sensor '{name}' -> {url} каждые {interval}с ==")
    while True:
        scan = wifi_scan()
        payload = json.dumps({"sensor": name, "scan": scan}).encode()
        try:
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + token})
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            print(f"[wifi] {len(scan)} BSSID отправлено")
        except Exception as e:
            print(f"[wifi] ошибка отправки: {e}")
        time.sleep(interval)


def wifi_ingest(d):
    """Brain side: store a sensor's scan into wifi_seen, preserving trust."""
    sensor = ((d.get("sensor") or "?").strip() or "?")[:64]
    now = time.time()
    n = 0
    with storage._db_lock:
        for b in (d.get("scan") or []):
            bssid = (b.get("bssid") or "").lower().strip()
            if not bssid:
                continue
            row = storage._db.execute(
                "SELECT first_seen, trusted FROM wifi_seen WHERE bssid=? AND sensor=?",
                (bssid, sensor)).fetchone()
            first = row[0] if row else now
            trusted = row[1] if row else 0
            storage._db.execute(
                "INSERT OR REPLACE INTO wifi_seen "
                "(bssid,sensor,ssid,signal,channel,radio,auth,first_seen,last_seen,trusted) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (bssid, sensor, b.get("ssid", ""), b.get("signal"), b.get("channel"),
                 b.get("radio", ""), b.get("auth", ""), first, now, trusted))
            n += 1
        storage._db.execute(
            "INSERT OR REPLACE INTO wifi_sensors (sensor, last_report) VALUES (?,?)",
            (sensor, now))
        storage._db.commit()
    return {"ok": True, "stored": n}


def wifi_view():
    """Brain side: the Wi-Fi section payload — config, sensors, seen BSSIDs (each
    tagged with any active alert), and the alert list."""
    now = time.time()
    with storage._db_lock:
        rows = [dict(bssid=r[0], sensor=r[1], ssid=r[2], signal=r[3], channel=r[4],
                     radio=r[5], auth=r[6], first_seen=r[7], last_seen=r[8], trusted=r[9])
                for r in storage._db.execute(
                    "SELECT bssid,sensor,ssid,signal,channel,radio,auth,first_seen,"
                    "last_seen,trusted FROM wifi_seen ORDER BY ssid, last_seen DESC").fetchall()]
        sensors = [{"sensor": r[0], "last_report": r[1]} for r in
                   storage._db.execute("SELECT sensor,last_report FROM wifi_sensors ORDER BY sensor").fetchall()]
    w = core.cfg("wifi", {}) or {}
    stale = float(w.get("sensor_stale_minutes", 15)) * 60
    for s in sensors:
        s["fresh"] = (now - s["last_report"]) < stale
        s["ago_min"] = int((now - s["last_report"]) / 60)
    alerts = wifi_detect(rows, {s["sensor"]: s["last_report"] for s in sensors}, w, now) if rows else []
    flag = {a["bssid"]: a["type"] for a in alerts if a.get("bssid")}
    for r in rows:
        r["flag"] = flag.get(r["bssid"], "")
        r["ago_min"] = int((now - r["last_seen"]) / 60)
    return {"config": {k: w.get(k) for k in ("enabled", "watch_ssids", "learn_hours",
            "radio_gone_minutes", "rogue_min_signal", "sensor_stale_minutes")},
            "sensors": sensors, "nets": rows, "alerts": alerts}


def wifi_detect(rows, sensors, w, now):
    """Pure: given wifi_seen rows + {sensor: last_report} + config, return alert
    dicts. No DB / clock — known-answer testable. rows are dicts with keys
    bssid, sensor, ssid, signal, channel, auth, last_seen, trusted."""
    gone_secs = float(w.get("radio_gone_minutes", 10)) * 60
    rogue_min = int(w.get("rogue_min_signal", 40))
    stale_secs = float(w.get("sensor_stale_minutes", 15)) * 60
    known = set(r["bssid"] for r in rows if r["trusted"])
    our_ssids = set((r["ssid"] or "") for r in rows if r["trusted"] and r["ssid"])
    watch = set(w.get("watch_ssids") or []) or our_ssids
    fresh_sensor = {s: (now - t) < stale_secs for s, t in sensors.items()}
    out = []
    # sensor down — a whole floor's eyes went dark
    for s, t in sensors.items():
        if (now - t) >= stale_secs:
            out.append({"type": "sensordown", "key": "sensor:" + s, "sensor": s,
                        "detail": f"Сенсор «{s}» молчит {int((now - t) / 60)} мин — "
                                  f"этаж без RF-контроля"})
    for r in rows:
        recent = (now - r["last_seen"]) < gone_secs
        if recent and (r["ssid"] in watch) and (r["bssid"] not in known):
            out.append({"type": "eviltwin", "key": "et:" + r["bssid"], "bssid": r["bssid"], "sensor": r["sensor"],
                        "detail": f"🚨 SSID «{r['ssid']}» вещается с ЧУЖОГО BSSID {r['bssid']} "
                                  f"(защита {r.get('auth') or '?'}, сигнал {r.get('signal')}%, "
                                  f"сенсор {r['sensor']}) — возможен evil-twin, кража паролей гостей"})
        elif (recent and r["bssid"] not in known and r["ssid"] not in our_ssids
              and (r.get("signal") or 0) >= rogue_min):
            out.append({"type": "rogue", "key": "rg:" + r["bssid"], "bssid": r["bssid"], "sensor": r["sensor"],
                        "detail": f"Новая точка «{r['ssid'] or '(скрытый SSID)'}» {r['bssid']} "
                                  f"сигнал {r.get('signal')}%, сенсор {r['sensor']}"})
    # radio down: a trusted BSSID stopped showing up, but its sensor is still alive
    for r in rows:
        if r["trusted"] and (now - r["last_seen"]) >= gone_secs and fresh_sensor.get(r["sensor"]):
            out.append({"type": "radiogone", "key": "rd:" + r["bssid"] + ":" + r["sensor"],
                        "bssid": r["bssid"], "sensor": r["sensor"], "ssid": r["ssid"],
                        "detail": f"Нода {r['bssid']} («{r['ssid']}») пропала из эфира на сенсоре "
                                  f"{r['sensor']}, хотя сенсор на связи — радио ноды могло крашнуться"})
    # channel conflict: >=2 trusted nodes on one channel at one sensor
    bychan = {}
    for r in rows:
        if r["trusted"] and r["channel"]:
            bychan.setdefault((r["sensor"], r["channel"]), set()).add(r["bssid"])
    for (s, ch), bs in bychan.items():
        if len(bs) >= 2:
            out.append({"type": "chanconflict", "key": f"cc:{s}:{ch}", "sensor": s,
                        "detail": f"Сенсор {s}: {len(bs)} нод на канале {ch} — интерференция, "
                                  f"гостевой Wi-Fi проседает"})
    return out


_WIFI_ALERTED = {}   # dedup: alert key -> ts; cleared when the condition resolves


_WIFI_ALERTED_LOADED = False   # mirrored in wifi_alerted, loaded on first evaluate


_WIFI_CLEAR_SINCE = {}  # alert key -> ts the condition was first seen gone


WIFI_REARM_SECONDS = 600  # a flapping node re-alerted every flicker (mesh-2: 2 in 2 min)


def _node_key(key):
    """"rd:<bssid>:<sensor>" (<= 0.50.0) -> "rdn:<bssid>". A BSSID has 6 colon parts."""
    parts = key.split(":")
    return "rdn:" + ":".join(parts[1:7]) if key.startswith("rd:") and len(parts) >= 7 else key


def _wifi_alerted_load():
    global _WIFI_ALERTED_LOADED
    if _WIFI_ALERTED_LOADED:
        return
    with storage._db_lock:
        rows = storage._db.execute("SELECT key, ts FROM wifi_alerted").fetchall()
        old = [k for k, _ in rows if k.startswith("rd:")]
        for k, ts in rows:
            _WIFI_ALERTED[_node_key(k)] = max(ts, _WIFI_ALERTED.get(_node_key(k), 0))
        if old:   # migrate once: per-sensor keys -> per-node, so the upgrade itself is silent
            storage._db.executemany("DELETE FROM wifi_alerted WHERE key=?", [(k,) for k in old])
            storage._db.executemany("INSERT OR REPLACE INTO wifi_alerted (key, ts) VALUES (?,?)",
                            [(k, v) for k, v in _WIFI_ALERTED.items() if k.startswith("rdn:")])
            storage._db.commit()
    _WIFI_ALERTED_LOADED = True


def fmt_radiogone(alerts):
    """One message for every node that went quiet this pass. A dead node is heard
    by several APs, so per-(bssid, sensor) alerts came out as 6-8 copies each."""
    nodes = {}
    for a in alerts:
        n = nodes.setdefault(a["bssid"], {"ssid": a.get("ssid") or "", "sensors": []})
        n["sensors"].append(a["sensor"])
    n = len(nodes)
    word = "нода" if n % 10 == 1 and n % 100 != 11 else (
        "ноды" if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14) else "нод")
    lines = [f"📴 <b>Wi-Fi</b>: пропали из эфира — {n} {word}, хотя сенсоры на связи"]
    for bssid, n in sorted(nodes.items(), key=lambda x: (x[1]["ssid"], x[0])):
        lines.append(f"• <code>{bssid}</code> «{html.escape(n['ssid'])}» — "
                     f"{', '.join(html.escape(x) for x in sorted(n['sensors']))}")
    return "\n".join(lines)


def wifi_evaluate(now=None):
    w = core.cfg("wifi", {}) or {}
    now = now or time.time()
    with storage._db_lock:
        rows = [dict(bssid=r[0], sensor=r[1], ssid=r[2], signal=r[3], channel=r[4],
                     radio=r[5], auth=r[6], first_seen=r[7], last_seen=r[8], trusted=r[9])
                for r in storage._db.execute(
                    "SELECT bssid,sensor,ssid,signal,channel,radio,auth,first_seen,"
                    "last_seen,trusted FROM wifi_seen").fetchall()]
        sensors = {r[0]: r[1] for r in
                   storage._db.execute("SELECT sensor,last_report FROM wifi_sensors").fetchall()}
    if not rows:
        return
    # Baseline: while still inside the learn window (measured from the very first
    # BSSID ever recorded), trust everything the sensors see — that IS the mesh.
    # UniFi rows are exempt: the controller states outright which BSSIDs are ours,
    # so blanket-trusting during the learn window would only enrol the neighbours.
    learn_secs = float(w.get("learn_hours", 24)) * 3600
    if (now - min(r["first_seen"] for r in rows)) < learn_secs:
        with storage._db_lock:
            for r in rows:
                if r["sensor"].startswith(unifi.UNIFI_PREFIX):
                    continue
                if not r["trusted"]:
                    storage._db.execute("UPDATE wifi_seen SET trusted=1 WHERE bssid=? AND sensor=?",
                                (r["bssid"], r["sensor"]))
                    r["trusted"] = 1
            storage._db.commit()
    _wifi_alerted_load()
    active, fresh, gone = set(), [], []
    new_nodes = set()
    for a in wifi_detect(rows, sensors, w, now):
        if not unifi.unifi_alert_allowed(a):
            continue
        # A vanished node is ONE problem however many APs used to hear it: keyed
        # per node, so an AP coming back at 09:33 doesn't re-announce it.
        key = "rdn:" + a["bssid"] if a["type"] == "radiogone" else a["key"]
        active.add(key)
        if key in _WIFI_ALERTED and key not in new_nodes:
            continue
        if key not in _WIFI_ALERTED:
            _WIFI_ALERTED[key] = now
            fresh.append(key)
        if a["type"] == "radiogone":
            new_nodes.add(key)
            gone.append(a)
            continue
        icon = {"eviltwin": "🚨", "rogue": "📡",
                "chanconflict": "📶", "sensordown": "🛰"}.get(a["type"], "📶")
        alerting.emit("wifi", f"{icon} <b>Wi-Fi</b>\n{html.escape(a['detail'], quote=False)}")
    if gone:
        alerting.emit("wifi", fmt_radiogone(gone))
    # Re-arm only after the condition has stayed resolved for a while: a node
    # that flickers back into the air for one pass is not "fixed".
    for key in active:
        _WIFI_CLEAR_SINCE.pop(key, None)
    # 10-15: the APs (= the sensors) are powered down overnight, so "node gone"
    # stopped being observable, counted as resolved, and re-fired at 07:23 when
    # the APs came back. A vanished node is resolved only by being SEEN again.
    gone_secs = float(w.get("radio_gone_minutes", 10)) * 60
    seen_now = {r["bssid"] for r in rows if now - r["last_seen"] < gone_secs}
    stale_secs = float(w.get("sensor_stale_minutes", 15)) * 60
    any_eyes = any(now - ts < stale_secs for ts in sensors.values())
    resolved = []
    for key in [k for k in _WIFI_ALERTED if k not in active]:
        if not any_eyes:
            # every sensor dark (APs powered down for the night): nothing is
            # observable, so nothing can be called fixed
            _WIFI_CLEAR_SINCE.pop(key, None)
            continue
        if key.startswith("rdn:") and key[4:] not in seen_now:
            _WIFI_CLEAR_SINCE.pop(key, None)   # unobserved, not fixed
            continue
        if now - _WIFI_CLEAR_SINCE.setdefault(key, now) >= WIFI_REARM_SECONDS:
            resolved.append(key)
            del _WIFI_ALERTED[key]
            _WIFI_CLEAR_SINCE.pop(key, None)
    if fresh or resolved:
        with storage._db_lock:
            storage._db.executemany("INSERT OR REPLACE INTO wifi_alerted (key, ts) VALUES (?,?)",
                            [(k, now) for k in fresh])
            storage._db.executemany("DELETE FROM wifi_alerted WHERE key=?", [(k,) for k in resolved])
            storage._db.commit()


def wifi_loop():
    # Like wan_loop/degradation_loop: let the first UniFi poll and sensor
    # reports land. After downtime >15 min every stored last_report is stale and
    # an immediate evaluate fired "сенсор молчит" for each one.
    time.sleep(90)
    while True:
        try:
            if core.cfg("wifi", {}).get("enabled"):
                wifi_evaluate()
        except Exception as e:
            print(f"[wifi] eval error: {core.short_err(e)}")
        time.sleep(60)


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import unifi  # noqa: E402
