"""Services: «1С 8 не работает» instead of «S08 не отвечает»."""

import html
import time

from . import core


# ----------------------------------------------------------------------------
# Services — what people in the office call "broken": «1С 8 не работает», not
# «S08 не отвечает на 445». A service is built from what is already watched:
#   hosts  — VMs/servers; their parent chain (VM -> Hyper-V host) counts too,
#            and the TOPMOST dead node is reported as the cause;
#   wan    — the internet ladder (gateway / uplink / DNS);
#   unifi  — the APs on the controller;
#   group  — a whole subnet by ping (cameras): k of n, where n is the usual
#            count, learned as the 7-day maximum — 73 cameras are not 73 hosts.
# Config: services = [{id, name, hosts?|wan?|unifi?|group?: {cidr, min_pct}}]
# ----------------------------------------------------------------------------

GROUPS = {}   # service id -> {"ts", "alive": [ips], "expected": int, "max": {date: n}, "told": bool}


def _host_chain(hid, hosts):
    """hid and its ancestors, nearest first (a VM, then its Hyper-V host...)."""
    out, seen = [], set()
    while hid and hid in hosts and hid not in seen:
        seen.add(hid)
        out.append(hid)
        hid = hosts[hid].get("parent")
    return out


def service_status(svc, hosts=None, states=None, now=None):
    """-> {"id","name","status": ok|warn|down|unknown, "detail", "cause"}"""
    now = now or time.time()
    out = {"id": svc.get("id"), "name": svc.get("name", svc.get("id")), "status": "unknown",
           "detail": "", "cause": ""}
    if svc.get("hosts"):
        if hosts is None:
            with core.CONFIG_LOCK:
                hosts = {h["id"]: h for h in core.CONFIG.get("hosts", []) if h.get("enabled", True)}
        if states is None:
            with livestate.STATE_LOCK:
                states = {k: v.get("status") for k, v in livestate.STATE.items()}
        comps = [hid for hid in svc["hosts"] if hid in hosts]
        if not comps:
            out["detail"] = "компоненты не найдены (хост удалён или выключен)"
            return out
        dead = []
        for hid in comps:
            chain = _host_chain(hid, hosts)
            down = [x for x in chain if states.get(x) == "down"]
            if down:
                dead.append((hid, down[-1]))     # topmost dead ancestor explains it
        if dead:
            cause = dead[0][1]
            out.update(status="down", cause=hosts[cause].get("name", cause),
                       detail=f"лежит {hosts[cause].get('name', cause)}"
                              + ("" if cause == dead[0][0] else f" → {hosts[dead[0][0]].get('name')}"))
        elif all(states.get(h) == "up" for h in comps):
            out.update(status="ok", detail="в строю")
        else:
            out.update(status="unknown", detail="проверяется")
        return out
    if svc.get("wan"):
        legs = {leg: (wanwatch.WAN_STATE.get(leg) or {}).get("up") for leg in wanwatch.WAN_IDS}
        if all(v is None for v in legs.values()):
            out["detail"] = "нет данных"
            return out
        label = {"gw": "шлюз", "inet": "канал", "dns": "DNS"}
        bad = [label[leg] for leg, v in legs.items() if v is False]
        out.update(status="down" if bad else "ok", detail=("не работает: " + ", ".join(bad)) if bad else "в строю",
                   cause=bad[0] if bad else "")
        return out
    if svc.get("unifi"):
        with unifi._UNIFI_LOCK:
            ok, aps = unifi._UNIFI.get("ok"), list(unifi._UNIFI.get("aps") or [])
        if not ok and unifi.UNIFI_CTRL.get("announced"):
            out.update(status="down", detail="контроллер UniFi не отвечает", cause="контроллер")
            return out
        if not aps:
            out["detail"] = "нет данных"
            return out
        on = sum(1 for a in aps if a.get("online"))
        night = unifi.ap_quiet_now()
        acked = core.cfg("acked_issues", {}) or {}
        known = [a["name"] for a in aps if not a.get("online") and ("ap:" + a.get("name", "")) in acked]
        bad = len(aps) - on - len(known)         # offline AND not «принято» in «Висит»
        st = "ok" if bad <= 0 or night else ("down" if on * 2 < len(aps) else "warn")
        note = " (ночное окно)" if night and on < len(aps) else (
            f" ({', '.join(known)} — принято)" if known else "")
        out.update(status=st, detail=f"точек на связи {on} из {len(aps)}{note}")
        return out
    if svc.get("group"):
        g = GROUPS.get(svc["id"]) or {}
        if not g.get("ts"):
            out["detail"] = "первый обход ещё не прошёл"
            return out
        n, exp = len(g.get("alive") or []), max(1, int(g.get("expected") or 1))
        pct = int((svc["group"].get("min_pct") or 90))
        st = "ok" if n * 100 >= exp * pct else ("down" if n * 2 < exp else "warn")
        out.update(status=st, detail=f"на связи {n} из {exp} обычных")
        return out
    return out


def services_view():
    out = []
    for svc in (core.cfg("services", []) or []):
        d = service_status(svc)
        g = GROUPS.get(svc.get("id")) if svc.get("group") else None
        if g:
            d["outage"] = _outage_brief(g["outage"]) if g.get("outage") else None
            d["outages"] = list(g.get("outages", []))[-7:]
        out.append(d)
    return out


def services_hit(host_id):
    """Names of services this host is part of — directly or as a parent of a part."""
    with core.CONFIG_LOCK:
        hosts = {h["id"]: h for h in core.CONFIG.get("hosts", [])}
        svcs = list(core.CONFIG.get("services", []) or [])
    hit = []
    for svc in svcs:
        if any(host_id in _host_chain(c, hosts) for c in (svc.get("hosts") or [])):
            hit.append(svc.get("name", svc.get("id")))
    return hit


def _hm(ts, ref=None):
    lt, rt = time.localtime(ts), time.localtime(ref or ts)
    return time.strftime("%H:%M" if lt[:3] == rt[:3] else "%d.%m %H:%M", lt)


def _outage_brief(o):
    """since / first back / 90 % back / all back — the shape of a night."""
    n = len(o["missing"])
    back = sorted((v[0], ip, v[1]) for ip, v in o["back"].items())
    out = {"since": o["since"], "approx": bool(o.get("approx")), "ended": o.get("ended"), "n": n, "back": len(back),
           "first": list(back[0]) if back else None, "p90": None, "all": None}
    need = -(-n * 9 // 10)                    # ceil(0.9 n)
    if n and len(back) >= need:
        out["p90"] = back[need - 1][0]
    if n and len(back) == n:
        out["all"] = back[-1][0]
    return out


def outage_text(b):
    if not b:
        return ""
    parts = [f"пропали {'до ' if b.get('approx') else ''}{_hm(b['since'])}"]
    if b["first"]:
        ts, ip, how = b["first"]
        parts.append(f"первая вернулась {_hm(ts, b['since'])} (<code>{html.escape(ip)}</code>, {html.escape(how)})")
    if b["p90"]:
        parts.append(f"90 % — {_hm(b['p90'], b['since'])}")
    parts.append(f"все — {_hm(b['all'], b['since'])}" if b["all"] else f"вернулось {b['back']} из {b['n']}")
    return "\n" + " · ".join(parts) + "\n<i>по пингу — с точностью до обхода (5 мин), по объявлениям — точно</i>"


def _outage_track(g, st, alive, now):
    """While a group is short, note when each missing device comes back. The
    night-time hypothesis (10-15: 9 of 97 at 19:11 — power plan or failure?)
    is answered by the morning timeline, not by guessing."""
    o = g.get("outage")
    bad = st["status"] in ("warn", "down")
    tail = g.get("tail")
    if tail and not bad:
        # the group is «ok» at 90 % — keep watching the stragglers so the
        # history gets «все вернулись в …» too (up to 12 h)
        for ip in alive:
            if ip in tail["missing"] and ip not in tail["back"]:
                tail["back"][ip] = [now, "пинг"]
        g["outages"][-1] = _outage_brief(tail)
        if len(tail["back"]) == len(tail["missing"]) or now - tail["ended"] > 12 * 3600:
            g["tail"] = None
    if bad and not o:
        g["tail"] = None
        # already told before tracking existed (upgrade mid-outage): the real
        # start is earlier and unknown — say «до», don't invent a time
        g["outage"] = {"since": now, "back": {}, "approx": bool(g.get("told")),
                       "missing": sorted(ip for ip in g.get("known", {}) if ip not in alive)}
        return
    if not o:
        return
    for ip in alive:
        if ip in o["missing"] and ip not in o["back"]:
            o["back"][ip] = [now, "пинг"]
    if not bad:
        o["ended"] = now
        brief = _outage_brief(o)
        hist = g.setdefault("outages", [])
        hist.append(brief)
        del hist[:-14]
        g["outage"] = None
        g["last_brief"] = brief
        g["tail"] = o if brief["all"] is None else None


def group_note_seen(ip, ts, how):
    """A device announced itself (SSDP/mDNS) — exact time, not sweep time."""
    for g in list(GROUPS.values()):
        o = g.get("outage")
        if o and ip in o["missing"] and ip not in o["back"]:
            o["back"][ip] = [ts, how]


def group_sweep(svc, now=None, scan=None):
    """One sweep of a subnet group; alerts on crossing the threshold (both ways,
    the recovery only if the drop was told)."""
    now = now or time.time()
    scan = scan or status.scan_subnet
    gcfg = svc["group"]
    alive = scan(gcfg["cidr"], timeout=1.0)
    g = GROUPS.setdefault(svc["id"], {"max": {}, "told": False, "known": {}})
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    g["max"][day] = max(g["max"].get(day, 0), len(alive))
    for d in sorted(g["max"])[:-7]:          # keep 7 days of daily maxima
        del g["max"][d]
    for ip in alive:
        g.setdefault("known", {})[ip] = now
    for ip in [k for k, ts in g["known"].items() if now - ts > 7 * 86400]:
        del g["known"][ip]
    g.update(ts=now, alive=alive, expected=max(g["max"].values()))
    st = service_status(svc, now=now)
    _outage_track(g, st, alive, now)
    if st["status"] in ("warn", "down") and not g["told"]:
        missing = sorted((ip for ip in g["known"] if ip not in alive),
                         key=lambda x: tuple(int(o) for o in x.split(".")))
        miss = ", ".join(missing[:12]) + (f" и ещё {len(missing) - 12}" if len(missing) > 12 else "")
        ok, detail = alerting.emit("cameras", f"📹 <b>{html.escape(svc.get('name', 'Группа'))}</b>: {st['detail']}"
                          + (f"\nНе отвечают: <code>{miss}</code>" if missing else ""))
        if ok and detail not in ("muted", "maintenance"):
            g["told"] = True
    elif st["status"] == "ok" and g["told"]:
        alerting.emit("cameras", f"✅ <b>{html.escape(svc.get('name', 'Группа'))}</b>: снова {st['detail']}"
                      + outage_text(g.get("last_brief")))
        g["told"] = False
    return st


def groups_loop():
    time.sleep(60)
    while True:
        for svc in (core.cfg("services", []) or []):
            if svc.get("group"):
                try:
                    group_sweep(svc)
                except Exception as e:
                    print(f"[group] {svc.get('name')}: {core.short_err(e)}")
        try:
            iv = max(1, int((core.cfg("groups", {}) or {}).get("interval_minutes") or 5)) * 60
        except (TypeError, ValueError):
            iv = 300
        time.sleep(iv)


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import wanwatch, alerting, livestate, status, unifi  # noqa: E402
