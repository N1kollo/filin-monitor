"""Quiet hours, priorities, escalation, maintenance windows, mutes."""

import html
import json
import os
import time

from . import core, storage, passive, telegram, alerting, livestate


# ----------------------------------------------------------------------------
# Quiet hours + host priority — the 3am printer alert is how monitoring gets
# muted forever. Priorities: critical (always rings), normal (held during
# quiet hours, lands in the morning digest), watch (journal only, never rings).
# Events are ALWAYS recorded — quiet only decides what reaches the phone.
# ----------------------------------------------------------------------------


def alert_class(host):
    p = host.get("priority") or "normal"
    return p if p in ("critical", "watch") else "normal"


def _hhmm_minutes(s):
    try:
        hh, mm = str(s).split(":")[:2]
        hh, mm = int(hh), int(mm)
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh * 60 + mm
    except (ValueError, IndexError):
        pass
    return None


def in_window(lt, start, end):
    """Is local time inside [start, end)? Handles windows crossing midnight
    (22:00 -> 08:00). start == end means the window is empty, not 24h."""
    a, b = _hhmm_minutes(start), _hhmm_minutes(end)
    if a is None or b is None or a == b:
        return False
    now = lt.tm_hour * 60 + lt.tm_min
    if a < b:
        return a <= now < b
    return now >= a or now < b


def quiet_now(lt=None):
    q = core.cfg("quiet", {}) or {}
    if not q.get("enabled"):
        return False
    return in_window(lt or time.localtime(), q.get("from", "22:00"), q.get("to", "08:00"))


def audible(host, quiet):
    """Does this host's alert reach Telegram right now?"""
    c = alert_class(host)
    if c == "watch":
        return False
    if quiet and c != "critical":
        return False
    return True


# ----------------------------------------------------------------------------
# Escalation — one missed 3am alert must not stay missed. A critical host that
# is still down after N minutes with no human reaction ("✅ Принял" or "🔇")
# alerts again, louder, optionally to a second chat.
# ----------------------------------------------------------------------------

ESCALATE = {}   # host_id -> {"since": ts, "done": bool}


# Hosts whose "упал" actually went out. A recovery is announced only for these:
# held (hold-down, quiet hours), suppressed (parent), muted or maintenance
# downs used to stay silent while their "восстановлен" still rang.
ANNOUNCED = set()


ACKED = set()   # host_ids a human confirmed they're handling (until recovery)


def seed_escalations():
    """A critical host already down at startup: the clock runs from when it went
    down, not from the restart (snapshot wins when it has the entry)."""
    with livestate.STATE_LOCK:
        downs = {k: v["since"] for k, v in livestate.STATE.items() if v["status"] == "down"}
    for h in livestate.enabled_hosts():
        if h["id"] in downs and alert_class(h) == "critical":
            ESCALATE.setdefault(h["id"], {"since": downs[h["id"]], "done": False})


def track_escalations(events):
    """Feed down/up transitions into the escalation ledger."""
    for e in events:
        hid = e["host"]["id"]
        if e["type"] == "down" and alert_class(e["host"]) == "critical":
            ESCALATE[hid] = {"since": time.time(), "done": False}
        elif e["type"] == "up":
            ESCALATE.pop(hid, None)
            ACKED.discard(hid)


def check_escalations(now=None):
    """Called once per cycle. Returns the list of hosts escalated this pass
    (for tests); sending happens here too."""
    al = core.cfg("alerts", {}) or {}
    try:
        after = int(al.get("escalate_after_minutes") or 0)
    except (TypeError, ValueError):
        after = 0
    if after <= 0:
        return []
    now = now or time.time()
    hosts = {h["id"]: h for h in livestate.enabled_hosts()}
    with livestate.STATE_LOCK:
        statuses = {k: v["status"] for k, v in livestate.STATE.items()}
    fired = []
    for hid, rec in list(ESCALATE.items()):
        if rec["done"] or hid in ACKED or is_muted(hid):
            continue
        h = hosts.get(hid)
        if not h or statuses.get(hid) != "down":
            ESCALATE.pop(hid, None)
            continue
        if now - rec["since"] < after * 60:
            continue
        # Planned work, or a dead parent that already explains it: "nobody
        # reacted" would be false. Not marked done — resumes when that ends.
        if in_maintenance(h) or livestate.parent_is_down(h.get("parent")):
            continue
        mins = int((now - rec["since"]) / 60)
        text = (f"🚨 <b>ЭСКАЛАЦИЯ</b>: {html.escape(str(h.get('name', '')))} "
                f"(критичный) лежит уже <b>{mins} мин</b> — никто не отреагировал.\n"
                f"<code>{html.escape(passive.host_target(h))}</code>")
        ok, _ = alerting.emit("escalation", text, host=h, markup=down_keyboard(h))
        extra = str(al.get("escalate_chat_id") or "").strip()
        if extra:
            _, err = alerting.tg_send_to(extra, text)
            ok = ok or err is None
        # Marked done only once someone could actually have seen it: the
        # escalation is the safety net for a missed alert, so a failed send
        # retries next cycle instead of being lost with the alert it guards.
        if ok:
            rec["done"] = True
            fired.append(hid)
    return fired


def build_night_digest(events, still_down, window_label):
    """Morning summary of what the quiet hours swallowed. events = rows from
    the events table for the window (chronological). Returns text or None."""
    downs = [e for e in events if e["type"] == "down"]
    ups = [e for e in events if e["type"] == "up"]
    if not downs and not ups and not still_down:
        return None
    by_host = {}
    for e in downs:
        by_host[e["name"]] = by_host.get(e["name"], 0) + 1
    total_down = sum(e.get("downtime") or 0 for e in ups)
    lines = [f"🌙 Сводка за тихие часы ({window_label}):"]
    if downs:
        worst = sorted(by_host.items(), key=lambda kv: -kv[1])
        what = ", ".join(f"{n}×{c}" if c > 1 else n for n, c in worst[:8])
        if len(worst) > 8:
            what += f" и ещё {len(worst) - 8}"
        lines.append(f"падало: {what}")
        if total_down:
            lines.append(f"суммарный простой: {alerting.fmt_duration(total_down)}")
    if still_down:
        lines.append("⚠️ до сих пор лежат: " + ", ".join(still_down[:8]))
    elif downs:
        lines.append("сейчас всё в строю, само поднялось")
    if not downs and not still_down:
        lines.append("падений не было")
    return "\n".join(lines)


_DIGEST_FIRED = {}  # date-str -> True


def quiet_digest_loop():
    while True:
        q = core.cfg("quiet", {}) or {}
        lt = time.localtime()
        stamp = f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d}"
        end = q.get("to", "08:00")
        # A 2-hour catch-up window instead of the exact minute: a restart or
        # reboot at 08:00 used to cost the digest — the only channel that
        # carries the night's events. _DIGEST_FIRED is persisted, so the
        # window can't double-send either.
        if (q.get("enabled") and q.get("digest", True)
                and _hhmm_minutes(end) is not None
                and (lt.tm_hour * 60 + lt.tm_min - _hhmm_minutes(end)) % 1440 < 120
                and stamp not in _DIGEST_FIRED):
            _DIGEST_FIRED[stamp] = True
            try:
                start_min = _hhmm_minutes(q.get("from", "22:00")) or 0
                end_min = _hhmm_minutes(end) or 0
                hours = ((end_min - start_min) % (24 * 60)) / 60.0 or 24
                events = storage.db_events_all(limit=500, hours=hours + 0.05)
                with livestate.STATE_LOCK:
                    down_ids = [hid for hid, s in livestate.STATE.items() if s["status"] == "down"]
                still = [h.get("name", hid) for hid in down_ids
                         for h in [next((x for x in core.cfg("hosts", []) if x["id"] == hid), {})]]
                text = build_night_digest(list(reversed(events)), still,
                                          f"{q.get('from')}–{end}")
                if text:
                    ok, detail = alerting.emit("digest", html.escape(text))
                    if ok and detail not in ("muted", "maintenance"):
                        # The digest told the human these are down — so their
                        # recovery later in the day is news worth a message.
                        ANNOUNCED.update(down_ids)
            except Exception as e:
                print(f"[digest] {core.short_err(e)}")
        time.sleep(20)


# ----------------------------------------------------------------------------
# Maintenance windows — planned work silences even critical hosts (you're the
# one rebooting it). Events are still journaled; only the phone stays quiet.
# ----------------------------------------------------------------------------


def window_active(win, lt):
    """Is this maintenance window active at local time `lt`? A window crossing
    midnight (22:00->02:00, days=[Fri]) belongs to its START day: at 01:00
    Saturday it is still Friday's window."""
    if not win.get("enabled", True):
        return False
    a, b = _hhmm_minutes(win.get("from")), _hhmm_minutes(win.get("to"))
    if a is None or b is None or a == b:
        return False
    days = win.get("days") or []
    now = lt.tm_hour * 60 + lt.tm_min
    if a < b:
        return (a <= now < b) and (not days or lt.tm_wday in days)
    # crossing midnight: evening part counts as today, morning as yesterday's
    if now >= a:
        return not days or lt.tm_wday in days
    if now < b:
        return not days or (lt.tm_wday - 1) % 7 in days
    return False


def maint_until(key):
    """Ad-hoc window set from the bot ("*" = whole network): until_ts or 0."""
    until = ((core.cfg("maint_until", {}) or {}).get(key) or 0)
    return until if until > time.time() else 0


def set_maint(key, seconds):
    """seconds None/0 = lift. Expired entries are dropped on every write."""
    now = time.time()
    with core.CONFIG_LOCK:
        m = {k: v for k, v in (core.CONFIG.get("maint_until") or {}).items() if v > now}
        if seconds:
            m[key] = now + seconds
        else:
            m.pop(key, None)
        core.CONFIG["maint_until"] = m
        core.save_config()


def in_maintenance(host, lt=None):
    lt = lt or time.localtime()
    hid = host.get("id")
    if maint_until("*") or maint_until(hid):
        return True
    for win in (core.cfg("maintenance", []) or []):
        if not window_active(win, lt):
            continue
        ids = win.get("hosts") or []
        if not ids or hid in ids:
            return True
    return False


# ----------------------------------------------------------------------------
# Mutes — what the human told the bot to shut up about. Kept in config, so a
# restart doesn't bring back the noise someone already silenced.
#   alerts.muted_hosts: host_id -> until_ts  (the "🔇" button under a down alert)
#   alerts.muted_kinds: kind    -> until_ts, 0 = until switched back on
# ----------------------------------------------------------------------------

# Alert kinds the filter (/mute, "🔕 Такие") may silence. Absent on purpose:
# down/up/trace/escalation (filtered per host — 🔇, priority, maintenance;
# critical always rings, D28), security (cert pin), system, manual.
ALERT_KINDS = {
    "degradation": "📉 Деградация",
    "wan":         "🌐 Интернет / WAN",
    "netdiff":     "🆕 Новые и пропавшие устройства",
    "ipconflict":  "🔥 Конфликт IP",
    "dhcp":        "📋 Чужой DHCP",
    "wifi":        "📶 Wi-Fi",
    "unifi":       "📡 UniFi",
    "wol":         "⏻ WoL и runbook",
    "digest":      "🌅 Утренняя сводка",
    "cameras":     "📹 Камеры",
}


def _mute_until(table, key):
    """until_ts (0 = indefinitely) if muted right now, else None."""
    with core.CONFIG_LOCK:
        m = (core.CONFIG.get("alerts") or {}).get(table) or {}
        until = m.get(key)
        if until is None:
            return None
        if until and until < time.time():
            m.pop(key, None)
            core.save_config()
            return None
        return until


def set_mute(table, key, seconds):
    """seconds: None = unmute, 0 = until switched back on, N = for N seconds."""
    with core.CONFIG_LOCK:
        m = core.CONFIG.setdefault("alerts", {}).setdefault(table, {})
        if seconds is None:
            m.pop(key, None)
        else:
            m[key] = time.time() + seconds if seconds else 0
        core.save_config()


def is_muted(host_id):
    return _mute_until("muted_hosts", host_id) is not None


def kind_muted(kind):
    return _mute_until("muted_kinds", kind) is not None


def fmt_until(until):
    if until == 0:
        return "пока не включишь"
    lt = time.localtime(until)
    if time.strftime("%Y-%m-%d", lt) == time.strftime("%Y-%m-%d"):
        return "до " + time.strftime("%H:%M", lt)
    return "до " + time.strftime("%d.%m %H:%M", lt)


MUTE_CHOICES = [("1 ч", 3600), ("8 ч", 8 * 3600), ("сутки", 86400), ("неделя", 7 * 86400)]


def filter_view():
    """/mute screen: every silenceable kind with its state + muted hosts."""
    lines = ["🔕 <b>Фильтр алертов</b>", ""]
    kb, row = [], []
    for k, label in ALERT_KINDS.items():
        until = _mute_until("muted_kinds", k)
        state = "🔔 звенит" if until is None else "🔕 " + fmt_until(until)
        lines.append(f"{label} — {state}")
        row.append({"text": ("🔕 " if until is not None else "") + label, "callback_data": f"flt:k:{k}"})
        if len(row) == 2:
            kb.append(row)
            row = []
    if row:
        kb.append(row)
    with core.CONFIG_LOCK:
        names = {h["id"]: h["name"] for h in core.CONFIG.get("hosts", [])}
        mh = list(((core.CONFIG.get("alerts") or {}).get("muted_hosts") or {}).keys())
    mh = [hid for hid in mh if is_muted(hid)]
    if mh:
        lines += ["", "<b>Заглушённые хосты:</b>"]
        for hid in mh:
            nm = names.get(hid, hid)
            lines.append(f"🔇 {html.escape(nm)} — {fmt_until(_mute_until('muted_hosts', hid))}")
            kb.append([{"text": f"🔊 {nm}", "callback_data": f"flt:uh:{hid}"}])
    if mh or any(kind_muted(k) for k in ALERT_KINDS):
        kb.append([{"text": "🔊 Включить всё", "callback_data": "flt:all"}])
    apq = (core.cfg("unifi", {}) or {}).get("ap_quiet") or {}
    if apq.get("from"):
        lines += ["", f"🌙 О точках UniFi не сообщаю {apq['from']}–{apq['to']}"]
        kb.append([{"text": "🔔 Снять ночное окно точек", "callback_data": "ap:x"}])
    lines += ["", "<i>Падения хостов глушатся кнопкой 🔇 под алертом, "
                  "критичные звенят всегда.</i>"]
    kb.append([{"text": "☰ Меню", "callback_data": "m:menu"}])
    return "\n".join(lines), json.dumps({"inline_keyboard": kb})


def filter_kind_view(kind):
    label = ALERT_KINDS[kind]
    until = _mute_until("muted_kinds", kind)
    state = "звенит" if until is None else "заглушено " + fmt_until(until)
    kb = [[{"text": t, "callback_data": f"flt:s:{kind}:{sec}"} for t, sec in MUTE_CHOICES],
          [{"text": "🔕 Пока не включу", "callback_data": f"flt:s:{kind}:0"}]]
    if until is not None:
        kb[1].append({"text": "🔊 Включить", "callback_data": f"flt:s:{kind}:-1"})
    kb.append([{"text": "← Фильтр", "callback_data": "flt:l"},
               {"text": "☰ Меню", "callback_data": "m:menu"}])
    return f"{label}\nСейчас: {state}\n\nЗаглушить на:", json.dumps({"inline_keyboard": kb})


def alert_audibility(h):
    """Why a host's down alert would or would not reach the phone right now.
    The dashboard showed a red host and nothing explained the silent phone:
    the reasons lived in the bot (🔇, maintenance) and in config."""
    hid = h.get("id")
    why = []
    if not h.get("enabled", True):
        why.append("проверка хоста выключена")
    if alert_class(h) == "watch":
        why.append("приоритет «только журнал» — не звенит никогда")
    if is_muted(hid):
        why.append(f"заглушён {fmt_until(_mute_until('muted_hosts', hid))}")
    until = max(maint_until(hid), maint_until("*"))
    if until:
        why.append(f"обслуживание до {time.strftime('%H:%M', time.localtime(until))}"
                   + (" (вся сеть)" if maint_until("*") >= maint_until(hid) else ""))
    elif in_maintenance(h):
        win = next((w for w in (core.cfg("maintenance", []) or []) if window_active(w, time.localtime())
                    and (not w.get("hosts") or hid in w.get("hosts"))), {})
        why.append(f"окно обслуживания «{win.get('name') or 'по расписанию'}»")
    if h.get("parent") and livestate.parent_is_down(h["parent"]):
        with core.CONFIG_LOCK:
            pn = next((x.get("name") for x in core.CONFIG.get("hosts", []) if x["id"] == h["parent"]), h["parent"])
        why.append(f"родитель «{pn}» лежит — его алерт объясняет и этот")
    if quiet_now() and alert_class(h) != "critical":
        q = core.cfg("quiet", {}) or {}
        why.append(f"тихие часы {q.get('from')}–{q.get('to')} — утром будет в сводке")
    notes = []
    al = core.cfg("alerts", {}) or {}
    hold = int(al.get("hold_down_seconds") or 0)
    if hold and not (alert_class(h) == "critical" and al.get("hold_down_skip_critical", True)):
        notes.append(f"звенит, если лежит дольше {hold} с")
    return {"rings": not why, "why": why, "notes": notes}


def silence_view():
    """Everything currently keeping the phone quiet — for the Overview strip."""
    now = time.time()
    with core.CONFIG_LOCK:
        names = {h["id"]: h.get("name", h["id"]) for h in core.CONFIG.get("hosts", [])}
        al = dict(core.CONFIG.get("alerts") or {})
    hosts = [{"id": k, "name": names.get(k, k), "until": v}
             for k, v in (al.get("muted_hosts") or {}).items() if is_muted(k)]
    kinds = [{"kind": k, "label": ALERT_KINDS.get(k, k), "until": v}
             for k, v in (al.get("muted_kinds") or {}).items() if k in ALERT_KINDS and kind_muted(k)]
    maint = [{"key": k, "name": "вся сеть" if k == "*" else names.get(k, k), "until": v}
             for k, v in (core.cfg("maint_until", {}) or {}).items() if v > now]
    apq = (core.cfg("unifi", {}) or {}).get("ap_quiet") or None
    q = core.cfg("quiet", {}) or {}
    with storage._db_lock:
        queued = storage._db.execute("SELECT COUNT(*) FROM tg_outbox").fetchone()[0]
    return {"kinds": ALERT_KINDS, "muted_hosts": hosts, "muted_kinds": kinds, "maint": maint,
            "ap_quiet": apq, "ap_quiet_active": bool(apq) and unifi.ap_quiet_now(),
            "quiet": {"enabled": bool(q.get("enabled")), "from": q.get("from"), "to": q.get("to"),
                      "active": quiet_now()},
            "outbox": queued}


ISSUE_HOST_MIN = 1800   # a host down this long is a standing problem, not an event


def standing_issues(now=None):
    """Problems that have been there long enough to stop being news: hosts down
    > 30 min, APs off the controller outside their quiet window, Wi-Fi nodes
    already announced as vanished. Each can be acknowledged («принято»): it
    stays listed, greyed. An acknowledgement dies with the problem."""
    now = now or time.time()
    out = []
    with core.CONFIG_LOCK:
        hosts = {h["id"]: h for h in core.CONFIG.get("hosts", []) if h.get("enabled", True)}
    with livestate.STATE_LOCK:
        st = {k: dict(v) for k, v in livestate.STATE.items()}
    for hid, h in hosts.items():
        v = st.get(hid) or {}
        if v.get("status") == "down" and v.get("since") and now - v["since"] >= ISSUE_HOST_MIN:
            out.append({"key": "host:" + hid, "kind": "host", "since": v["since"],
                        "title": f"{h.get('name', hid)} лежит"})
    if not unifi.ap_quiet_now():
        for name in sorted(unifi._UNIFI_DOWN):
            downs = sorted(float(ts) for ts, e in unifi.UNIFI_AP_LOG.items()
                           if e["kind"] == "down" and name in e["names"])
            out.append({"key": "ap:" + name, "kind": "ap", "since": downs[-1] if downs else None,
                        "title": f"точка UniFi «{name}» не на связи"})
    nodes = [k[4:] for k in wifi._WIFI_ALERTED if k.startswith("rdn:")]
    if nodes:
        with storage._db_lock:
            ssid = dict(storage._db.execute("SELECT bssid, MAX(ssid) FROM wifi_seen GROUP BY bssid").fetchall())
        for b in sorted(nodes):
            # we know when it was REPORTED, not when it vanished — say so
            out.append({"key": "node:" + b, "kind": "node", "since": wifi._WIFI_ALERTED.get("rdn:" + b),
                        "since_label": "сообщили",
                        "title": f"Wi-Fi-нода «{ssid.get(b) or '?'}» {b} пропала из эфира"})
    acked = core.cfg("acked_issues", {}) or {}
    live = {i["key"] for i in out}
    stale = [k for k in acked if k not in live]
    if stale:   # the problem is gone — so is its «принято»
        with core.CONFIG_LOCK:
            for k in stale:
                core.CONFIG.setdefault("acked_issues", {}).pop(k, None)
            core.save_config()
    for i in out:
        i["acked"] = i["key"] in acked
    out.sort(key=lambda i: (i["acked"], i["since"] or 0))
    return out


def ack_issue(key, on=True):
    with core.CONFIG_LOCK:
        a = core.CONFIG.setdefault("acked_issues", {})
        if on:
            a[key] = time.time()
        else:
            a.pop(key, None)
        core.save_config()


LOG_ERROR_MARKS = (" ERROR ", "error", "ошибк", "умер", "не удал", "не запущен", "traceback",
                   "не отправлен", "выброшено")


def log_tail(lines=300, errors_only=False, path=None):
    """Last lines of logs/monitor.log for the dashboard. 10-14 reading it meant
    RDP + Notepad + a phone photo of the screen."""
    path = path or os.path.join(core.LOG_DIR, "monitor.log")
    if not os.path.exists(path):
        return {"path": path, "lines": [], "note": "лог не найден — монитор запущен без записи в файл"}
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - 512 * 1024))
        text = f.read().decode("utf-8", errors="replace")
    out = text.splitlines()[1:] if len(text) >= 512 * 1024 else text.splitlines()
    if errors_only:
        out = [ln for ln in out if any(k in ln.lower() for k in LOG_ERROR_MARKS)]
    return {"path": path, "lines": out[-max(1, min(int(lines), 2000)):]}


def handle_filter_callback(cq, cid, msg, data):
    def show(view):
        text, kb = view
        telegram.tg_api("editMessageText", {"chat_id": cid, "message_id": msg.get("message_id"),
                                   "text": text, "parse_mode": "HTML", "reply_markup": kb})
        telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"]})

    parts = data.split(":") + ["", "", ""]
    op, arg = parts[1], parts[2]
    if op == "q" and arg in ALERT_KINDS:
        # Tapped under the alert itself: don't overwrite the alert, just confirm.
        set_mute("muted_kinds", arg, 86400)
        telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "show_alert": "true",
               "text": f"🔕 {ALERT_KINDS[arg]}: тишина "
                       f"{fmt_until(_mute_until('muted_kinds', arg))}. Вернуть — /mute"})
    elif op == "k" and arg in ALERT_KINDS:
        show(filter_kind_view(arg))
    elif op == "s" and arg in ALERT_KINDS:
        sec = int(parts[3])
        set_mute("muted_kinds", arg, None if sec < 0 else sec)
        show(filter_view())
    elif op == "uh":
        set_mute("muted_hosts", arg, None)
        show(filter_view())
    elif op == "all":
        with core.CONFIG_LOCK:
            al = core.CONFIG.setdefault("alerts", {})
            al["muted_kinds"], al["muted_hosts"] = {}, {}
            core.save_config()
        show(filter_view())
    else:
        show(filter_view())


def down_keyboard(host, with_recheck=True):
    row = []
    if host.get("mac"):
        row.append({"text": "⏻ Разбудить", "callback_data": f"wake:{host['id']}"})
    if with_recheck:
        row.append({"text": "🔄 Перепроверить", "callback_data": f"recheck:{host['id']}"})
    row.append({"text": "🔇 1ч", "callback_data": f"mute:{host['id']}"})
    if alert_class(host) == "critical":
        row.append({"text": "✅ Принял", "callback_data": f"ack:{host['id']}"})
    # :n = answer with a NEW message — editing would wipe the alert itself
    row2 = [{"text": "🖥 Карточка", "callback_data": f"m:h:{host['id']}:n"},
            {"text": "🔧 Обслуж. 1ч", "callback_data": f"m:mh:{host['id']}:n"}]
    return json.dumps({"inline_keyboard": [row, row2]})


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import wifi, unifi  # noqa: E402
