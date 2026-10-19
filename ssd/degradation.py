"""Degradation: latency creeping up before a host dies."""

import html
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import error as urlerror
from urllib import request as urlrequest

from . import core, storage, passive, alerting, livestate, policy, holddown


# ----------------------------------------------------------------------------
# Degradation detection — the difference between reporting outages and
# predicting them. Rolling median baseline vs recent median.
# ----------------------------------------------------------------------------

DEGRADED = {}        # host_id -> {"since", "base", "cur", "ratio"}


_DEG_PENDING = {}    # host_id -> consecutive passes over the threshold, not yet announced


_BASELINE_CACHE = {}  # host_id -> (value, samples, computed_at)


_BASELINE_TTL = 3600  # baselines move slowly; recomputing every minute is waste


def get_baseline(host_id, hours, until):
    hit = _BASELINE_CACHE.get(host_id)
    now = time.time()
    if hit and (now - hit[2]) < _BASELINE_TTL:
        return hit[0], hit[1]
    med, n = storage.db_median_latency(host_id, now - hours * 3600, until)
    _BASELINE_CACHE[host_id] = (med, n, now)
    return med, n


def evaluate_degradation():
    """Returns (newly_degraded, recovered) events. Pure arithmetic, no ML."""
    d = core.cfg("degradation", {}) or {}
    if not d.get("enabled", True):
        return [], []
    try:
        ratio_th = float(d.get("ratio_threshold") or 3.0)
        sustain = max(1, int(d.get("sustain_minutes") or 10)) * 60
        base_hours = max(1, int(d.get("baseline_hours") or 168))
        min_samples = max(10, int(d.get("min_samples") or 60))
        floor_ms = float(d.get("min_latency_ms") or 5.0)
        # 10-14 15:41 «ДЕГРАДАЦИЯ 1.26», 15:42 «НОРМА»: a one-minute spike cost
        # two messages. Entering now needs this many passes in a row (~1/min).
        # 3 still let a 5-minute morning spike through as a pair (10-15 10:31/10:33):
        # sustained = as long as the window the "current" median is taken over.
        confirm = max(1, int(d.get("confirm_passes") or 10))
    except (TypeError, ValueError):
        return [], []

    now = time.time()
    newly, recovered = [], []
    hosts = {h["id"]: h for h in livestate.enabled_hosts()}

    for hid, h in hosts.items():
        with livestate.STATE_LOCK:
            st = livestate.STATE.get(hid)
        # a DOWN host isn't "slow" — that's a different alert entirely
        if not st or st["status"] != "up":
            continue
        base, n = get_baseline(hid, base_hours, now - sustain)
        if base is None or n < min_samples:
            continue  # not enough history to have an opinion
        cur, cn = storage.db_median_latency(hid, now - sustain)
        if cur is None or cn < 3:
            continue
        ratio = cur / base if base > 0 else 1.0
        # 1ms -> 4ms is "4x worse" and completely meaningless. The floor is
        # what the CURRENT median must clear to ENTER degradation — by the
        # threshold, or a 1.7ms LAN host "degrades" every time a packet takes
        # 8ms. It must not gate recovery: placed before the recovery branch it
        # kept four hosts 🐢 for 14h at 1 ms after one night spike (10-14).
        if hid in DEGRADED:
            # hysteresis: don't flap out right at the threshold; back under the
            # floor (by the hysteresis margin) is "normal" whatever the ratio
            if ratio < ratio_th * 0.8 or cur < floor_ms * ratio_th * 0.8:
                info = DEGRADED.pop(hid)
                recovered.append({"host": h, "base": base, "cur": cur,
                                  "duration": now - info["since"]})
            else:
                DEGRADED[hid].update({"cur": cur, "ratio": ratio, "base": base})
        elif ratio >= ratio_th and cur >= floor_ms * ratio_th:
            n = _DEG_PENDING.get(hid, 0) + 1
            if n >= confirm:
                _DEG_PENDING.pop(hid, None)
                DEGRADED[hid] = {"since": now, "base": base, "cur": cur, "ratio": ratio}
                newly.append({"host": h, "base": base, "cur": cur, "ratio": ratio})
            else:
                _DEG_PENDING[hid] = n
        else:
            _DEG_PENDING.pop(hid, None)

    # forget hosts that went down or were deleted
    for stale in [k for k in DEGRADED if k not in hosts]:
        DEGRADED.pop(stale, None)
    with livestate.STATE_LOCK:
        for hid in list(DEGRADED):
            s = livestate.STATE.get(hid)
            if not s or s["status"] != "up":
                DEGRADED.pop(hid, None)
    return newly, recovered


def _fmt_ms(v):
    return f"{v:.0f} мс" if v >= 10 else f"{v:.1f} мс"


def dispatch_degradation(newly, recovered):
    # Same audibility rules as regular alerts: watch never rings, normal is
    # held during quiet hours, critical always rings, maintenance silences all.
    q = policy.quiet_now()
    newly = [e for e in newly if policy.audible(e["host"], q) and not policy.in_maintenance(e["host"])]
    recovered = [e for e in recovered if policy.audible(e["host"], q) and not policy.in_maintenance(e["host"])]
    al = core.cfg("alerts", {}) or {}
    try:
        storm = max(2, int(al.get("storm_threshold") or 5))
    except (TypeError, ValueError):
        storm = 5

    def send(t):
        ok, detail = alerting.emit("degradation", t)
        if not ok:
            print(f"[telegram] деградация не отправлена: {detail}")

    if newly:
        if len(newly) >= storm:
            lines = [f"⚠️ <b>МАССОВАЯ ДЕГРАДАЦИЯ</b>: {len(newly)} хостов отвечают хуже обычного",
                     "Похоже на общую проблему сети, а не на отдельные железки.", ""]
            for e in newly[:15]:
                lines.append(f"🐢 {html.escape(str(e['host'].get('name','')))} — "
                             f"{_fmt_ms(e['cur'])} вместо {_fmt_ms(e['base'])} (×{e['ratio']:.1f})")
            if len(newly) > 15:
                lines.append(f"… и ещё {len(newly)-15}")
            send("\n".join(lines))
        else:
            for e in newly:
                send(f"⚠️ <b>ДЕГРАДАЦИЯ</b>: {html.escape(str(e['host'].get('name','')))}\n"
                     f"<code>{html.escape(passive.host_target(e['host']))}</code>\n"
                     f"Отвечает {_fmt_ms(e['cur'])} вместо обычных {_fmt_ms(e['base'])} "
                     f"(<b>в {e['ratio']:.1f} раз хуже</b>)\n"
                     f"Хост пока жив — но обычно это предвестник.")
    if recovered:
        if len(recovered) >= storm:
            send(f"✅ <b>Деградация закончилась</b>: {len(recovered)} хостов вернулись к норме")
        else:
            for e in recovered:
                send(f"✅ <b>НОРМА</b>: {html.escape(str(e['host'].get('name','')))}\n"
                     f"Отклик вернулся: {_fmt_ms(e['cur'])} (норма ~{_fmt_ms(e['base'])})\n"
                     f"Деградация длилась {alerting.fmt_duration(e['duration'])}")


def degradation_loop():
    time.sleep(45)  # let the first checks land before judging anything
    while True:
        try:
            newly, recovered = evaluate_degradation()
            dispatch_degradation(newly, recovered)
        except Exception as e:
            print(f"[degradation] {core.short_err(e)}")
        time.sleep(60)


def ping_heartbeat(url):
    """Ping the dead man's switch (healthchecks.io or similar)."""
    try:
        req = urlrequest.Request(url, headers={"User-Agent": "ServerSignalDesk/1.0"})
        with urlrequest.urlopen(req, timeout=10) as r:
            code = r.status
        return (code < 400), f"HTTP {code}"
    except urlerror.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, core.short_err(e)


HEARTBEAT_STATE = {"last_try": 0.0, "last_ok": 0.0, "ok": None, "detail": ""}


# Wall-clock of the last fully completed check cycle. Surfaced in /api/status
# so the UI can show liveness that reflects the monitor loop, not the HTTP one.
LAST_CYCLE = {"ts": 0.0}


STARTED_AT = time.time()


def cycle_stale(now):
    """Seconds the check loop has been stuck, or 0 if it is alive. Heartbeat
    lives in its own thread, so without this it vouched for a monitor whose
    cycle had been throwing for hours."""
    try:
        interval = max(1, int(core.cfg("check_interval_seconds", 30)))
    except (TypeError, ValueError):
        interval = 30
    grace = max(3 * interval, 180)
    ref = LAST_CYCLE["ts"] or STARTED_AT
    age = now - ref
    return age if age > grace else 0


def heartbeat_loop():
    last = 0.0
    while True:
        hb = core.cfg("heartbeat", {}) or {}
        url = (hb.get("url") or "").strip()
        try:
            interval = max(1, int(hb.get("interval_minutes") or 5)) * 60
        except (TypeError, ValueError):
            interval = 300
        if hb.get("enabled") and url and (time.time() - last) >= interval:
            stale = cycle_stale(time.time())
            if stale:
                # Not pinging IS the alert: the external watchdog notices the
                # silence. Pinging here would vouch for a blind monitor.
                HEARTBEAT_STATE["ok"] = False
                HEARTBEAT_STATE["detail"] = f"цикл проверок стоит {alerting.fmt_duration(stale)} — пинг придержан"
                print(f"[heartbeat] {HEARTBEAT_STATE['detail']}")
                time.sleep(15)
                continue
            ok, detail = ping_heartbeat(url)
            last = time.time()
            HEARTBEAT_STATE["last_try"] = last
            HEARTBEAT_STATE["ok"] = ok
            HEARTBEAT_STATE["detail"] = detail
            if ok:
                HEARTBEAT_STATE["last_ok"] = last
            else:
                print(f"[heartbeat] пинг не прошёл: {detail}")
        time.sleep(15)  # short tick so config changes apply quickly


def monitor_loop():
    pool = ThreadPoolExecutor(max_workers=64)
    tick = 0
    while True:
        start = time.perf_counter()
        try:
            holddown.monitor_cycle(pool)
            # Stamped only on a cycle that actually completed — the dashboard
            # pulses its logo off this, so it must mean "checks ran", not
            # "the web server answered".
            LAST_CYCLE["ts"] = time.time()
            if not update._UPDATE_MARKED["done"]:
                update.update_mark_healthy()
        except Exception as e:
            print(f"[monitor] cycle error: {core.short_err(e)}")
        try:
            storage.runtime_save()
        except Exception as e:
            print(f"[runtime] snapshot error: {core.short_err(e)}")
        tick += 1
        interval = core.cfg("check_interval_seconds", 30)
        if tick % max(1, int(3600 / max(interval, 1))) == 0:
            storage.db_prune()
        time.sleep(max(1.0, interval - (time.perf_counter() - start)))


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import update  # noqa: E402
