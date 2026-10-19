"""Button-driven Telegram bot."""

import html
import json
import re
import socket
import time

from . import core, storage, checks, netinventory, passive, recovery, telegram, alerting, policy, status


# ----------------------------------------------------------------------------
# Button-driven bot. Every screen is (text, keyboard); a tap edits the same
# message in place, so navigating doesn't flood the chat. Callback data is
# "m:<screen>[:<arg>][:n]" — ":n" (from an alert) answers with a new message.
# ----------------------------------------------------------------------------

BOT_COMMANDS = [
    ("menu", "☰ меню с кнопками"), ("status", "все хосты"), ("down", "только упавшие"),
    ("hosts", "карточки хостов"), ("wake", "разбудить машину"), ("maint", "обслуживание — не звенеть"),
    ("mute", "фильтр алертов"), ("noise", "что шумело за неделю"),
    ("who", "кто это: /who 192.168.1.37 или MAC"), ("version", "версия"),
]


_MENU_BTN = {"text": "☰ Меню", "callback_data": "m:menu"}


def _kb(rows):
    return json.dumps({"inline_keyboard": rows})


def _host_by_id(hid):
    with core.CONFIG_LOCK:
        return next((dict(h) for h in core.CONFIG.get("hosts", []) if h["id"] == hid), None)


def _when(ts):
    lt = time.localtime(ts)
    fmt = "%H:%M" if time.strftime("%Y-%m-%d", lt) == time.strftime("%Y-%m-%d") else "%d.%m %H:%M"
    return time.strftime(fmt, lt)


def menu_view():
    s = status.build_status()["summary"]
    head = (f"☰ <b>{html.escape(str(core.cfg('app_name')))}</b>\n"
            f"🟢 {s['up']}   🔴 {s['down']}" + (f"   🐢 {s['degraded']}" if s.get("degraded") else ""))
    if policy.maint_until("*"):
        head += f"\n🔧 обслуживание до {_when(policy.maint_until('*'))}"
    return head, _kb([
        [{"text": "📊 Статус", "callback_data": "m:st"}, {"text": "🔴 Упавшие", "callback_data": "m:dn"}],
        [{"text": "🖥 Хосты", "callback_data": "m:hl"}, {"text": "⏻ Разбудить", "callback_data": "m:wk"}],
        [{"text": "🔧 Обслуживание", "callback_data": "m:mt"}, {"text": "🔕 Фильтр", "callback_data": "flt:l"}],
        [{"text": "⏻ Поднять упавшие", "callback_data": "m:rv"}, {"text": "📈 Шум за неделю", "callback_data": "m:nz"}],
        [{"text": "🔄 Версия и обновление", "callback_data": "m:ud"}],
    ])


def _mb(n):
    return f"{n / 1048576:.1f} МБ"


def upd_bot_view():
    d = update.update_view()
    lines = [f"🔄 <b>Версия {d['version']}</b>"]
    st = d["state"]
    if st.get("state"):
        mark = {"healthy": "✅", "rolled_back": "⚠️", "failed": "⚠️", "broken": "🔴",
                "swapping": "⏳", "starting": "⏳"}.get(st["state"], "·")
        what = {"healthy": "прошло", "rolled_back": "откатилось", "failed": "не удалось", "broken": "сломалось",
                "swapping": "идёт", "starting": "идёт"}.get(st["state"], st["state"])
        lines.append(f"{mark} последнее: v{st.get('from')} → v{st.get('to')} — {what}"
                     + (f", {_when(st['ts'])}" if st.get("ts") else "")
                     + (f"\n   {html.escape(st['error'])}" if st.get("error") else ""))
    rows = []
    c = d["candidates"]
    if c:
        lines.append(f"⬆️ новая: <b>v{c[0]['version']}</b> ({_mb(c[0]['size'])})")
        rows.append([{"text": f"⬆️ Обновить до v{c[0]['version']}", "callback_data": "m:uq:u"}])
    else:
        lines.append("Новых версий нет — пришли exe через Taildrop, он ляжет в «Загрузки».")
    b = d["backups"]
    if b:
        lines.append("↩️ в backup: " + ", ".join("v" + x["version"] for x in b))
        rows.append([{"text": f"↩️ Откатить на v{b[0]['version']}", "callback_data": "m:uq:r"}])
    if not d["frozen"]:
        lines.append("<i>запущен из исходников — обновление только у exe</i>")
    return "\n".join(lines), _kb(rows + [[{"text": "🔄 Обновить", "callback_data": "m:ud"}], [_MENU_BTN]])


def upd_confirm_view(kind):
    d = update.update_view()
    tgt = (d["candidates"] if kind == "u" else d["backups"])[:1]
    if not tgt:
        return "Цели нет — список изменился.", _kb([[{"text": "‹ Назад", "callback_data": "m:ud"}]])
    v = tgt[0]["version"]
    text = (f"{'⬆️ Обновить' if kind == 'u' else '↩️ Откатить'} <b>v{d['version']} → v{v}</b>?\n"
            "Монитор перезапустится (~1 мин без проверок). Если новая версия не пройдёт первый "
            f"цикл за {update.UPDATE_HEALTH_SEC // 60} мин — вернётся v{d['version']}.")
    return text, _kb([[{"text": "✅ Да", "callback_data": f"m:ug:{kind}"},
                       {"text": "Отмена", "callback_data": "m:ud"}]])


def recovery_view():
    d = recovery.recovery_view_data()
    if d["running"]:
        lines = ["⏻ <b>Восстановление идёт</b>"]
        for x in d["steps"]:
            mark = {"up": "✅", "sent": "📨", "pending": "⏳", "down": "❌", "skip": "⚪"}.get(x["result"], "·")
            lines.append(f"{mark} {html.escape(x['name'])}")
        return "\n".join(lines), _kb([[{"text": "🔄 Обновить", "callback_data": "m:rv"}], [_MENU_BTN]])
    plan = d["plan"]
    if not plan:
        return "⏻ Упавших нет — поднимать нечего.", _kb([[_MENU_BTN]])
    what = {"wol": "⏻ разбужу", "wait_parent": "⏳ встанет с хостом", "vm_manual": "🖥 VM — только в Hyper-V",
            "no_mac": "⚪ нет MAC"}
    lines = ["⏻ <b>Поднять упавшие</b> — план:"]
    for x in plan:
        wave = f" (волна {x['wave']})" if x["action"] == "wol" else ""
        lines.append(f"• {html.escape(x['name'])} — {what[x['action']]}{wave}")
    rows = [[{"text": "▶ Запустить", "callback_data": "m:rg"}]] if d["actionable"] else []
    return "\n".join(lines), _kb(rows + [[_MENU_BTN]])


def status_view(down_only=False):
    return status.format_status_message(down_only=down_only), _kb([
        [{"text": "🔄 Обновить", "callback_data": "m:dn" if down_only else "m:st"},
         {"text": "📊 Все" if down_only else "🔴 Упавшие", "callback_data": "m:st" if down_only else "m:dn"}],
        [_MENU_BTN]])


def _status_icon(x):
    if x["status"] == "down":
        return "🔴"
    if x.get("degraded"):
        return "🐢"
    return "🟢" if x["status"] == "up" else "🟡"


def hosts_view():
    servers = status.build_status()["servers"]
    rows, row = [], []
    for x in servers[:40]:
        row.append({"text": f"{_status_icon(x)} {x['name']}"[:40], "callback_data": f"m:h:{x['id']}"})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([_MENU_BTN])
    text = "🖥 <b>Хосты</b> — тап открывает карточку" if servers else "Целей нет — добавь в веб-настройках."
    return text, _kb(rows)


def host_view(hid):
    h = _host_by_id(hid)
    x = next((v for v in status.build_status()["servers"] if v["id"] == hid), None)
    if not h or not x:
        return "Хост не найден (удалён или выключен).", _kb([[{"text": "← Хосты", "callback_data": "m:hl"}]])
    state = {"down": "лежит", "up": "в строю", "pending": "проверяется"}.get(x["status"], x["status"])
    lines = [f"{_status_icon(x)} <b>{html.escape(h['name'])}</b> — <code>{html.escape(x['target'])}</code>",
             f"Статус: <b>{state}</b>" + (f" · {x['since_human']}" if x.get("since_human") else "")]
    if x.get("latency") is not None:
        lat = f"Отклик: {x['latency']} мс"
        if x.get("degraded"):
            lat += f" — 🐢 ×{x['deg_ratio']} к норме {x.get('deg_base')} мс"
        lines.append(lat)
    elif x.get("error"):
        lines.append(f"Ошибка: {html.escape(x['error'])}")
    up24, up7 = storage.db_uptime(hid, 24), storage.db_uptime(hid, 168)
    lines.append("Аптайм: 24ч " + (f"{up24}%" if up24 is not None else "—")
                 + " · 7д " + (f"{up7}%" if up7 is not None else "—"))
    marks = []
    if policy.alert_class(h) != "normal":
        marks.append({"critical": "🔥 критичный", "watch": "👁 только журнал"}[policy.alert_class(h)])
    if policy.is_muted(hid):
        marks.append(f"🔇 заглушён {policy.fmt_until(policy._mute_until('muted_hosts', hid))}")
    if policy.maint_until(hid) or policy.maint_until("*"):
        marks.append(f"🔧 обслуживание до {_when(max(policy.maint_until(hid), policy.maint_until('*')))}")
    if marks:
        lines.append(" · ".join(marks))
    evs = [e for e in storage.db_events(hid, 6) if e["type"] in ("down", "up")][:3]
    if evs:
        lines.append("")
        for e in evs:
            what = "🔴 упал" if e["type"] == "down" else (
                "🟢 поднялся" + (f" (лежал {alerting.fmt_duration(e['downtime'])})" if e.get("downtime") else ""))
            lines.append(f"{_when(e['ts'])} {what}")
    row1 = [{"text": "🔄 Перепроверить", "callback_data": f"m:rc:{hid}"}]
    if h.get("mac"):
        row1.append({"text": "⏻ Разбудить", "callback_data": f"wake:{hid}"})
    row2 = [{"text": "🔊 Вернуть звук", "callback_data": f"m:um:{hid}"} if policy.is_muted(hid)
            else {"text": "🔇 Тишина 1ч", "callback_data": f"m:mu:{hid}"},
            {"text": "✅ Снять обслуж.", "callback_data": f"m:mxh:{hid}"} if policy.maint_until(hid)
            else {"text": "🔧 Обслуж. 1ч", "callback_data": f"m:mh:{hid}"}]
    return "\n".join(lines), _kb([row1, row2, [{"text": "← Хосты", "callback_data": "m:hl"}, _MENU_BTN]])


MAINT_CHOICES = [("30 мин", 1800), ("1 ч", 3600), ("2 ч", 7200), ("4 ч", 14400)]


def maint_view():
    lines = ["🔧 <b>Обслуживание</b> — алерты по хостам не звенят",
             "(журнал пишется, Wi-Fi/DHCP/безопасность звенят как обычно)", ""]
    rows = [[{"text": t, "callback_data": f"m:mg:{sec}"} for t, sec in MAINT_CHOICES]]
    active = [(k, v) for k, v in (core.cfg("maint_until", {}) or {}).items() if v > time.time()]
    if not active:
        lines.append("Сейчас ничего не обслуживается. Вся сеть на:")
    for key, until in sorted(active, key=lambda kv: kv[1]):
        name = "Вся сеть" if key == "*" else (_host_by_id(key) or {}).get("name", key)
        lines.append(f"🔧 {html.escape(name)} — до {_when(until)}")
        rows.append([{"text": f"✅ Снять: {name}"[:40], "callback_data": f"m:mx:{key}"}])
    rows.append([_MENU_BTN])
    return "\n".join(lines), _kb(rows)


def noise_view():
    st = telegram.db_tg_sent_stats(168)
    lines = [f"📈 <b>Шум за неделю</b>: отправлено {st['total'] - st['muted']}, "
             f"проглочено фильтром {st['muted']}" + (f", не доставлено {st['failed']}" if st["failed"] else ""), ""]
    kind_rows = []
    for k in st["by_kind"][:10]:
        label = policy.ALERT_KINDS.get(k["kind"]) or k["kind"]
        lines.append(f"{k['sent']:>4}  {label}")
        if k["kind"] in policy.ALERT_KINDS and not policy.kind_muted(k["kind"]):
            kind_rows.append([{"text": f"🔕 {label}"[:40], "callback_data": f"flt:k:{k['kind']}"}])
    if not st["by_kind"]:
        lines.append("Тишина — за неделю ничего не отправлялось.")
    return "\n".join(lines), _kb(kind_rows[:6] + [[_MENU_BTN]])


def wake_view():
    kb = wake_keyboard()
    rows = json.loads(kb)["inline_keyboard"] if kb else []
    rows.append([_MENU_BTN])
    text = "⏻ Кого разбудить?" if kb else "Нет хостов с MAC-адресом — добавь MAC в настройках."
    return text, _kb(rows)


def who_view(q):
    """Everything the monitor knows about one IP or MAC."""
    q = (q or "").strip().lower().replace("-", ":")
    if not q:
        return "Напиши так: <code>/who 192.168.1.37</code> или <code>/who aa:bb:cc:dd:ee:ff</code>"
    is_mac = re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", q) is not None
    with storage._db_lock:
        rows = storage._db.execute("SELECT ip, mac, vendor, hostname, first_seen, last_seen, present "
                           "FROM arp_seen WHERE " + ("lower(mac)=?" if is_mac else "ip=?"), (q,)).fetchall()
    hosts = [h for h in core.cfg("hosts", []) if (h.get("host") == q) or (is_mac and (h.get("mac") or "").lower() == q)]
    inv = storage.db_inventory_all()
    if not rows and not hosts:
        return f"Про <code>{html.escape(q)}</code> ничего не знаю — в сканах сети не встречался."
    out = []
    for ip, mac, vendor, hostname, first, last, present in rows:
        out.append(f"{'🟢' if present else '⚪'} <code>{ip}</code> — {html.escape(vendor or 'вендор неизвестен')}")
        if hostname or passive.PASSIVE.get(ip, {}).get("name"):
            out.append(f"   имя: {html.escape(hostname or passive.PASSIVE[ip]['name'])}")
        out.append(f"   MAC <code>{mac}</code>" + ("  📱 случайный (приватный) MAC" if netinventory.mac_is_random(mac) else ""))
        out.append(f"   впервые {_when(first)} · последний раз {_when(last)}")
    for h in hosts:
        rec = inv.get(h["id"], {})
        out.append(f"🖥 в мониторинге как <b>{html.escape(h['name'])}</b>")
        if rec.get("os"):
            out.append(f"   ОС: {html.escape(rec['os'])}")
        ports = rec.get("ports") or []
        if ports:
            out.append("   порты: " + ", ".join(str(pp.get("port")) for pp in ports[:12]))
    return "\n".join(out)


def bot_send_view(cid, view):
    text, kb = view
    return telegram.tg_api("sendMessage", {"chat_id": cid, "text": text, "parse_mode": "HTML",
                                  "reply_markup": kb, "disable_web_page_preview": "true"})


def handle_menu_callback(cq, cid, msg, data):
    parts = data.split(":")
    new = parts[-1] == "n"
    if new:
        parts = parts[:-1]
    screen, arg = parts[1], (parts[2] if len(parts) > 2 else "")
    note = None

    if screen == "rc":
        h = _host_by_id(arg)
        if h:
            up, latency, error = checks.run_check(h, core.cfg("timeout_seconds", 3))
            note = (f"🟢 {h['name']}: отвечает" + (f" ({round(latency)} мс)" if latency is not None else "")
                    if up else f"🔴 {h['name']}: {error or 'нет ответа'}")
        screen = "h"
    elif screen in ("mu", "um"):
        policy.set_mute("muted_hosts", arg, 3600 if screen == "mu" else None)
        screen = "h"
    elif screen == "mh":
        policy.set_maint(arg, 3600)
        note = "🔧 Обслуживание на 1 час — алерты по хосту не звенят"
        screen = "h"
    elif screen == "mg":
        policy.set_maint("*", int(arg))
        note = f"🔧 Вся сеть: не звеню до {_when(policy.maint_until('*'))}"
        screen = "mt"
    elif screen in ("mx", "mxh"):
        policy.set_maint(arg, None)
        screen = "h" if screen == "mxh" else "mt"
    elif screen == "rg":
        note = ("⏻ Запущено — итог пришлю сообщением" if recovery.recovery_start("Telegram")
                else "Восстановление уже идёт")
        screen = "rv"
    elif screen == "ug":
        ok, said = update.update_start("update" if arg == "u" else "rollback", by="Telegram")
        note = ("⏳ " + said + " — итог пришлю") if ok else ("⚠️ " + said)
        screen = "ud"

    views = {"menu": menu_view, "st": status_view, "dn": lambda: status_view(True),
             "hl": hosts_view, "mt": maint_view, "nz": noise_view, "wk": wake_view, "rv": recovery_view,
             "ud": upd_bot_view, "uq": lambda: upd_confirm_view(arg),
             "h": lambda: host_view(arg)}
    view = (views.get(screen) or menu_view)()
    if new:
        bot_send_view(cid, view)
    else:
        text, kb = view
        telegram.tg_api("editMessageText", {"chat_id": cid, "message_id": msg.get("message_id"),
                                   "text": text, "parse_mode": "HTML", "reply_markup": kb,
                                   "disable_web_page_preview": "true"})
    p = {"callback_query_id": cq["id"]}
    if note:
        p.update(text=note, show_alert="true")
    telegram.tg_api("answerCallbackQuery", p)


def bot_register_commands():
    """The "/" menu in Telegram's input field."""
    telegram.tg_api("setMyCommands", {"commands": json.dumps(
        [{"command": c, "description": d} for c, d in BOT_COMMANDS], ensure_ascii=False)})


def wake_keyboard():
    hosts = [h for h in core.cfg("hosts", []) if h.get("mac")]
    if not hosts:
        return None
    rows = [[{"text": f"⏻ {h['name']}", "callback_data": f"wake:{h['id']}"}] for h in hosts[:20]]
    return json.dumps({"inline_keyboard": rows})


def handle_update(u):
    owner = str((core.cfg("telegram", {}) or {}).get("chat_id", ""))
    if "message" in u:
        m = u["message"]
        chat = m.get("chat", {})
        cid = str(chat.get("id"))
        alerting.SEEN_CHATS[cid] = alerting.chat_name(chat)
        # SEEN_CHATS is filled BEFORE the guard on purpose — that's what feeds
        # the "Определить чат" button while chat_id is still empty.
        if not owner:
            # No owner configured yet: the bot token is live but unclaimed, so
            # anyone who finds it would otherwise get /status and /wake. Answer
            # with a setup hint and nothing else.
            return alerting.tg_send_to(cid, "Бот ещё не привязан к чату. Владельцу: дашборд → "
                                   "Настройки → Telegram → «Определить чат».")
        if cid != owner:
            return  # only respond to the configured owner
        text = (m.get("text") or "").strip().lower()
        if text in ("/menu", "/start", "menu", "меню", "старт"):
            bot_send_view(cid, menu_view())
        elif text in ("/status", "status", "статус"):
            alerting.tg_send_to(cid, status.format_status_message(), with_kb=True)
        elif text in ("/hosts", "hosts", "хосты"):
            bot_send_view(cid, hosts_view())
        elif text in ("/maint", "maint", "обслуживание"):
            bot_send_view(cid, maint_view())
        elif text in ("/noise", "noise", "шум"):
            bot_send_view(cid, noise_view())
        elif text.split(" ")[0] in ("/who", "who", "кто"):
            alerting.tg_send_to(cid, who_view(text.partition(" ")[2]))
        elif text in ("/down", "down", "упавшие"):
            alerting.tg_send_to(cid, status.format_status_message(down_only=True), with_kb=True)
        elif text in ("/wake", "wake", "разбудить"):
            kb = wake_keyboard()
            if not kb:
                alerting.tg_send_to(cid, "Нет хостов с MAC-адресом. Добавь MAC в настройках "
                                "или отсканируй подсеть — MAC подтянутся сами.")
            else:
                telegram.tg_api("sendMessage", {"chat_id": cid, "text": "Кого разбудить?", "reply_markup": kb})
        elif text in ("/version", "version", "/версия"):
            alerting.tg_send_to(cid, f"📡 <b>{html.escape(str(core.cfg('app_name')))}</b>\n"
                            f"Версия: <b>{core.__version__}</b>\n"
                            f"Хост: <code>{html.escape(socket.gethostname())}</code>")
        elif text in ("/mute", "/filter", "mute", "фильтр", "тишина", "/тишина"):
            t, kb = policy.filter_view()
            telegram.tg_api("sendMessage", {"chat_id": cid, "text": t, "parse_mode": "HTML", "reply_markup": kb})
        elif text in ("/help", "help", "/помощь"):
            alerting.tg_send_to(cid, "Команды:\n/status — все хосты\n/down — только упавшие\n"
                            "/wake — разбудить машину (Wake-on-LAN)\n"
                            "/mute — фильтр: заглушить типы алертов, снять мьют с хостов\n"
                            "/version — версия и на какой машине крутится")
    elif "callback_query" in u:
        cq = u["callback_query"]
        msg = cq.get("message", {})
        chat = msg.get("chat", {})
        cid = str(chat.get("id"))
        if not owner or cid != owner:
            telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"]})
            return
        data = cq.get("data") or ""
        if data.startswith("recheck:"):
            hid = data.split(":", 1)[1]
            with core.CONFIG_LOCK:
                h = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == hid), None)
            if not h:
                telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": "Хост не найден"})
                return
            up, latency, error = checks.run_check(h, core.cfg("timeout_seconds", 3))
            if up:
                msg = f"🟢 {h['name']}: отвечает" + (f" ({round(latency)} мс)" if latency is not None else "")
            else:
                msg = f"🔴 {h['name']}: {error or 'нет ответа'}"
            telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": msg, "show_alert": "true"})
            return
        if data.startswith("ack:"):
            hid = data.split(":", 1)[1]
            policy.ACKED.add(hid)
            telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"],
                    "text": "✅ Принято — эскалации по этому хосту не будет", "show_alert": "true"})
            return
        if data.startswith("flt:"):
            policy.handle_filter_callback(cq, cid, msg, data)
            return
        if data.startswith("m:"):
            handle_menu_callback(cq, cid, msg, data)
            return
        if data.startswith("ap:"):
            parts = data.split(":")
            with core.CONFIG_LOCK:
                uc = core.CONFIG.setdefault("unifi", {})
                if parts[1] == "q" and len(parts) == 4:
                    frm, to = f"{parts[2][:2]}:{parts[2][2:]}", f"{parts[3][:2]}:{parts[3][2:]}"
                    uc["ap_quiet"] = {"from": frm, "to": to}
                    note = f"🌙 О точках UniFi не сообщаю {frm}–{to}. Снять — /mute"
                else:
                    uc.pop("ap_quiet", None)
                    note = "🔔 Ночное окно точек снято — снова как тихие часы"
                core.save_config()
            if parts[1] == "x":
                text, kb = policy.filter_view()
                telegram.tg_api("editMessageText", {"chat_id": cid, "message_id": msg.get("message_id"),
                                           "text": text, "parse_mode": "HTML", "reply_markup": kb})
            telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": note, "show_alert": "true"})
            return
        if data.startswith("mute:"):
            hid = data.split(":", 1)[1]
            policy.set_mute("muted_hosts", hid, 3600)
            with core.CONFIG_LOCK:
                h = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == hid), None)
            nm = h["name"] if h else hid
            telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"],
                    "text": f"🔇 {nm}: алерты заглушены на 1 час", "show_alert": "true"})
            return
        if data.startswith("wake:"):
            hid = data.split(":", 1)[1]
            with core.CONFIG_LOCK:
                h = next((x for x in core.CONFIG.get("hosts", []) if x["id"] == hid), None)
            if h and h.get("mac"):
                try:
                    checks.send_wol(h["mac"], h.get("broadcast") or None)
                    telegram.tg_api("answerCallbackQuery", {
                        "callback_query_id": cq["id"],
                        "text": f"⏻ Пакет отправлен: {h['name']}", "show_alert": "true"})
                    alerting.tg_send_to(cid, f"⏻ Magic packet отправлен: <b>{html.escape(h['name'])}</b>\n"
                                    f"<code>{h['mac']}</code>\nЖди 30-60 сек, потом /status.")
                except Exception as e:
                    telegram.tg_api("answerCallbackQuery", {
                        "callback_query_id": cq["id"],
                        "text": f"Ошибка: {core.short_err(e)}", "show_alert": "true"})
            else:
                telegram.tg_api("answerCallbackQuery", {
                    "callback_query_id": cq["id"], "text": "Нет MAC у хоста", "show_alert": "true"})
            return
        text = status.format_status_message(down_only=(data == "down"))
        telegram.tg_api("editMessageText", {
            "chat_id": cid, "message_id": msg.get("message_id"),
            "text": text, "parse_mode": "HTML",
            "reply_markup": alerting.KEYBOARD, "disable_web_page_preview": "true",
        })
        telegram.tg_api("answerCallbackQuery", {"callback_query_id": cq["id"]})


def telegram_backlog_offset():
    """Offset past everything Telegram queued while we were down. Those taps and
    commands are stale: replaying them after a restart re-sent WoL packets and
    re-ran rechecks nobody asked for anymore. offset=-1 returns only the newest
    update and lets us acknowledge it without acting on it."""
    res, err = telegram.tg_api("getUpdates", {"offset": -1, "timeout": 0}, timeout=15)
    if err or not res:
        return None
    last = res.get("result") or []
    if last:
        print(f"[telegram] пропускаю накопившиеся обновления до #{last[-1]['update_id']}")
        return last[-1]["update_id"] + 1
    return 0


def telegram_bot_loop():
    """Single getUpdates long-poll consumer: handles /commands and button taps."""
    offset = None
    while True:
        _tg = core.cfg("telegram", {}) or {}
        tok = _tg.get("bot_token", "")
        if not tok or not _tg.get("poll_updates", True):
            time.sleep(3)
            continue
        if offset is None:
            offset = telegram_backlog_offset()
            if offset is None:
                time.sleep(3)
                continue
            try:
                bot_register_commands()
            except Exception as e:
                print(f"[telegram] setMyCommands: {core.short_err(e)}")
        params = {"timeout": 25, "allowed_updates": json.dumps(["message", "callback_query"])}
        if offset:
            params["offset"] = offset
        res, err = telegram.tg_api("getUpdates", params, timeout=30)
        if err or not res:
            time.sleep(3)
            continue
        for u in res.get("result", []):
            offset = u["update_id"] + 1
            try:
                handle_update(u)
            except Exception as e:
                print(f"[telegram] update error: {core.short_err(e)}")


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import update  # noqa: E402
