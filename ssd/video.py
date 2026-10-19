"""Video section: cameras per recorder, pings, still frames."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import core, checks, services, dahua


# Video section: which camera sits on which recorder, is it answering, and a
# still frame on demand. Inventory is slow to change (30 min); pings every 2 min.
VIDEO_LOCK = threading.Lock()


VIDEO = {"nvrs": {}, "alive": {}, "ts": 0.0, "ping_ts": 0.0}


_SNAP_LOCKS = {}


_SNAP_CACHE = {}          # (nvr, ch) -> (ts, jpeg)


def video_refresh(probe=None):
    probe = probe or dahua.nvr_probe
    conf, _ = dahua.nvr_config()
    for ip, c in conf.items():
        try:
            d = probe(ip)
        except Exception as e:
            d = {"ok": False, "error": core.short_err(e)}
        d.pop("sample", None)
        d.update(ip=ip, name=c["name"], ts=time.time())
        with VIDEO_LOCK:
            prev = VIDEO["nvrs"].get(ip)
            if not d.get("ok") and prev and prev.get("cameras"):
                # unreachable for a moment: keep what we knew, say it's stale
                d = dict(prev, ok=False, error=d.get("error"), ts=prev.get("ts"))
            VIDEO["nvrs"][ip] = d
    with VIDEO_LOCK:
        for ip in [k for k in VIDEO["nvrs"] if k not in conf]:
            del VIDEO["nvrs"][ip]
        VIDEO["ts"] = time.time()


def video_ping(ping=None):
    ping = ping or (lambda ip: checks.check_ping(ip, 1.0)[0])
    with VIDEO_LOCK:
        ips = sorted({c["ip"] for d in VIDEO["nvrs"].values() for c in d.get("cameras") or [] if c.get("ip")}
                     | set(VIDEO["nvrs"]))
    with ThreadPoolExecutor(max_workers=40) as pool:
        res = dict(zip(ips, pool.map(ping, ips)))
    with VIDEO_LOCK:
        VIDEO.update(alive=res, ping_ts=time.time())


def video_loop():
    time.sleep(90)
    last = 0.0
    while True:
        try:
            if dahua.nvr_config()[0]:
                if time.time() - last > 1800:
                    video_refresh()
                    last = time.time()
                video_ping()
        except Exception as e:
            print(f"[video] {core.short_err(e)}")
        time.sleep(120)


def video_view():
    with VIDEO_LOCK:
        nvrs = {k: dict(v) for k, v in VIDEO["nvrs"].items()}
        alive = dict(VIDEO["alive"])
        ts, ping_ts = VIDEO["ts"], VIDEO["ping_ts"]
    where = {}
    for ip, d in nvrs.items():
        for c in d.get("cameras") or []:
            if c.get("ip"):
                where.setdefault(c["ip"], []).append((ip, f"{d.get('name') or ip} · канал {c.get('channel')}"))
    out = []
    for ip, d in sorted(nvrs.items(), key=lambda kv: kv[1].get("name") or kv[0]):
        cams = []
        for c in d.get("cameras") or []:
            x = dict(c)
            x["alive"] = alive.get(c["ip"]) if c.get("ip") else None
            x["also"] = [lbl for nip, lbl in where.get(c.get("ip"), []) if nip != ip]
            cams.append(x)
        out.append({"ip": ip, "name": d.get("name") or ip, "model": d.get("model") or "",
                    "ok": bool(d.get("ok")), "error": d.get("error") or "", "ts": d.get("ts"),
                    "alive": alive.get(ip),
                    "disks": [{"name": k.get("Name", ""), "state": k.get("State", ""),
                               "error": str(k.get("IsError", "")).lower() == "true"} for k in d.get("disks") or []],
                    "cameras": cams})
    # answering in a camera group, but on no recorder and not a known host
    with core.CONFIG_LOCK:
        known = {h.get("host") for h in core.CONFIG.get("hosts", [])}
    seen = set(where) | set(nvrs) | known
    # until every recorder has given its list, «not on a recorder» is a lie
    # (10-15: the first 90 s after start showed the whole subnet as orphans)
    complete = bool(nvrs) and all(d.get("cameras") or d.get("ok") for d in nvrs.values())
    orphans = sorted({a for g in services.GROUPS.values() for a in (g.get("alive") or []) if a not in seen},
                     key=lambda x: tuple(int(o) for o in x.split("."))) if complete else []
    return {"configured": bool(dahua.nvr_config()[0]), "nvrs": out, "orphans": orphans, "ts": ts, "ping_ts": ping_ts}


def nvr_snapshot(ip, ch):
    """-> (jpeg, None) or (None, error). One NVR at a time; a frame is reused for
    1.5 s so two open tabs don't double the load on an old XVR."""
    conf, mtime = dahua.nvr_config()
    c = conf.get(ip)
    if not c or not c["user"] or not c["password"]:
        return None, "нет логина для регистратора в nvr.json"
    if dahua.NVR_AUTH_FAIL.get(ip) == mtime:
        return None, "логин отклонён — исправь nvr.json"
    hit = _SNAP_CACHE.get((ip, ch))
    if hit and time.time() - hit[0] < 1.5:
        return hit[1], None
    lock = _SNAP_LOCKS.setdefault(ip, threading.Lock())
    if not lock.acquire(timeout=10):
        return None, "регистратор занят"
    try:
        code, body, sent = dahua.dahua_get(ip, f"/cgi-bin/snapshot.cgi?channel={ch}", c["user"], c["password"],
                                     timeout=10, raw=True)
    except Exception as e:
        return None, core.short_err(e)
    finally:
        lock.release()
    if code == 401 and sent:
        dahua.NVR_AUTH_FAIL[ip] = mtime
        return None, "логин отклонён регистратором"
    if code != 200 or not body or body[:2] != b"\xff\xd8":
        return None, f"кадра нет (HTTP {code})"
    _SNAP_CACHE[(ip, ch)] = (time.time(), body)
    return body, None
