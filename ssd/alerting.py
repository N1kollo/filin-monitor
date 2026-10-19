"""emit(): the one door every alert walks through."""

import json

from . import core, telegram


# ----------------------------------------------------------------------------
# emit() — the one door every alert walks through. Kind is explicit: guessing
# it from the sender's function name broke silently the moment wan_loop's body
# moved into _wan_step (0.43 -> WAN mute stopped working, nobody noticed).
# Gates, in order: kind mute -> host mute -> maintenance window. Priority and
# quiet hours stay with the producers that know about hosts (dispatch_*), the
# storm/parent logic stays in dispatch_alerts — it is topology, not policy.
# ----------------------------------------------------------------------------

HOST_KINDS = {"down", "up", "trace", "escalation", "degradation"}


# Never kind-muted: security, the monitor's own lifecycle, and answers to an
# action a human just asked for (recovery report).
NOTICE_KINDS = {"security", "system", "recovery"}


def emit(kind, text, host=None, markup=None, queue=True):
    chat = (core.cfg("telegram", {}) or {}).get("chat_id", "")
    why = None
    if kind in policy.ALERT_KINDS and policy.kind_muted(kind):
        why = "muted"
    elif host and kind in HOST_KINDS:
        if policy.is_muted(host["id"]):
            why = "muted"
        elif policy.in_maintenance(host):
            why = "maintenance"
    if why:
        telegram.tg_log_sent({"chat_id": chat, "text": text}, why, kind=kind)
        return True, why
    if markup is None and kind in policy.ALERT_KINDS:
        markup = json.dumps({"inline_keyboard": [[
            {"text": "🔕 Такие — на сутки", "callback_data": f"flt:q:{kind}"},
        ]]})
    return telegram._broadcast(text, markup, kind, queue)


# Chats that have messaged the bot — filled by the bot poll loop, read by the
# "Определить чат" button. The loop is the single getUpdates consumer (avoids 409).
SEEN_CHATS: dict = {}


KEYBOARD = json.dumps({"inline_keyboard": [[
    {"text": "🔄 Обновить", "callback_data": "refresh"},
    {"text": "🔴 Только упавшие", "callback_data": "down"},
], [{"text": "☰ Меню", "callback_data": "m:menu"}]]})


def chat_name(chat):
    return (chat.get("title")
            or (chat.get("first_name", "") + " " + chat.get("last_name", "")).strip()
            or chat.get("username") or str(chat.get("id")))


def tg_send_to(cid, text, with_kb=False):
    p = {"chat_id": cid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": "true"}
    if with_kb:
        p["reply_markup"] = KEYBOARD
    return telegram.tg_api("sendMessage", p)


def tg_detect_chats():
    """Chats seen by the bot loop (user must have messaged the bot first)."""
    return [{"id": k, "name": v} for k, v in SEEN_CHATS.items()], None


def fmt_duration(seconds):
    s = int(seconds)
    if s < 60:
        return f"{s}с"
    if s < 3600:
        return f"{s//60}м {s%60}с"
    if s < 86400:
        return f"{s//3600}ч {(s%3600)//60}м"
    return f"{s//86400}д {(s%86400)//3600}ч"


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import policy  # noqa: E402
