"""Telegram Bot API transport and the send journal."""

import html
import json
import re
import sys
import time
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from . import core, storage


# ----------------------------------------------------------------------------
# Telegram
# ----------------------------------------------------------------------------


def telegram_ready():
    tg = core.cfg("telegram", {}) or {}
    tok, chat = tg.get("bot_token", ""), str(tg.get("chat_id", ""))
    return bool(tok) and bool(chat)


def tg_api(method, params, timeout=10):
    res, err = _tg_call(method, params, timeout)
    if method == "sendMessage":
        tg_log_sent(params, err)
        if err is None:
            outbox.OUTBOX_KICK.set()
    return res, err


def _tg_call(method, params, timeout):
    """One API call. If Telegram rejects the HTML markup, the same text goes again
    as plain text: names from the air and the LAN (a Wi-Fi SSID «<b») must not be
    able to silence the alert that reports them."""
    res, err = _tg_post(method, params, timeout)
    if err and params.get("parse_mode") and "can't parse entities" in err:
        plain = {k: v for k, v in params.items() if k != "parse_mode"}
        plain["text"] = html.unescape(re.sub(r"<[^>]*>", "", params.get("text", "")))
        res, err = _tg_post(method, plain, timeout)
    return res, err


def _tg_post(method, params, timeout):
    tok = (core.cfg("telegram", {}) or {}).get("bot_token", "")
    if not tok:
        return None, "нет токена бота"
    url = f"https://api.telegram.org/bot{tok}/{method}"
    data = urlparse.urlencode(params).encode()
    try:
        with urlrequest.urlopen(url, data=data, timeout=timeout) as r:
            return json.loads(r.read().decode()), None
    except urlerror.HTTPError as e:
        return None, f"Telegram API {e.code}: {e.read().decode()[:150]}"
    except Exception as e:
        return None, core.short_err(e)


def _tg_sender():
    """Name of the function that asked to send — the first frame outside the
    tg_* plumbing. Saves threading a `kind` through ~34 call sites."""
    f = sys._getframe(1)
    while f:
        name = f.f_code.co_name
        top = getattr(f.f_globals.get(name), "__code__", None) is f.f_code
        if top and not name.startswith(("tg_", "_tg_")):
            return name
        f = f.f_back
    return "?"


def tg_log_sent(params, err, kind=None):
    try:
        with storage._db_lock:
            storage._db.execute(
                "INSERT INTO tg_sent (ts, kind, chat_id, ok, error, text) VALUES (?,?,?,?,?,?)",
                (time.time(), kind or _tg_sender(), str(params.get("chat_id", "")),
                 0 if err else 1, err, str(params.get("text", ""))[:1000]),
            )
            storage._db.commit()
    except Exception:
        pass  # bookkeeping must never cost an alert


def db_tg_sent_stats(hours):
    since = time.time() - hours * 3600
    with storage._db_lock:
        by_kind = storage._db.execute(
            "SELECT kind, COUNT(*), SUM(ok) FROM tg_sent WHERE ts >= ? "
            "GROUP BY kind ORDER BY COUNT(*) DESC", (since,)).fetchall()
        rows = storage._db.execute(
            "SELECT ts, kind, ok, error, text FROM tg_sent WHERE ts >= ? "
            "ORDER BY ts DESC LIMIT 500", (since,)).fetchall()
    by_day, by_hour = {}, [0] * 24
    for ts, *_ in rows:
        lt = time.localtime(ts)
        d = time.strftime("%Y-%m-%d", lt)
        by_day[d] = by_day.get(d, 0) + 1
        by_hour[lt.tm_hour] += 1
    with storage._db_lock:
        muted = storage._db.execute("SELECT COUNT(*) FROM tg_sent WHERE ts >= ? "
                            "AND error IN ('muted', 'maintenance')",
                            (since,)).fetchone()[0]
    return {
        "hours": hours,
        "total": sum(r[1] for r in by_kind),
        "muted": muted,
        "failed": sum(r[1] - (r[2] or 0) for r in by_kind) - muted,
        "by_kind": [{"kind": k, "sent": n, "ok": ok or 0} for k, n, ok in by_kind],
        "by_day": by_day,
        "by_hour": by_hour,
        "recent": [{"ts": ts, "kind": k, "ok": bool(ok), "error": e, "text": t}
                   for ts, k, ok, e, t in rows],
    }


def _site_prefix():
    """[app_name] prefix for broadcast alerts — lets two sites share one chat.
    Off by default (single site); turn on per site with distinct app_names."""
    if (core.cfg("telegram", {}) or {}).get("site_prefix"):
        return f"[{html.escape(str(core.cfg('app_name', '')))}] "
    return ""


def _broadcast(text, markup, kind, queue=True):
    """Send to the owner chat. Transient failures go to the outbox."""
    if not telegram_ready():
        return False, "Telegram не настроен"
    chat = (core.cfg("telegram", {}) or {}).get("chat_id", "")
    params = {
        "chat_id": chat, "text": _site_prefix() + text,
        "parse_mode": "HTML", "disable_web_page_preview": "true",
    }
    if markup:
        params["reply_markup"] = markup
    res, err = _tg_call("sendMessage", params, 10)
    tg_log_sent(params, err, kind=kind)
    if err is None:
        outbox.OUTBOX_KICK.set()
        return True, "ok"
    if queue and outbox.tg_retryable(err):
        outbox.outbox_put(params, kind, err)
        return True, f"в очереди: {err}"
    return False, err


def tg_send(text, queue=True):
    """Kind-less broadcast — only for the settings "send test" button. Every
    alert goes through emit()."""
    return _broadcast(text, None, "manual", queue)


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import outbox  # noqa: E402
