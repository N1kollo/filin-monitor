"""Outbox: alerts retried, not lost, on a dead link."""

import html
import json
import re
import threading
import time

from . import core, storage, checks, passive, services, telegram, alerting


# ----------------------------------------------------------------------------
# Outbox — an alert that hits a dead link is retried, not lost. The transition
# that produced it is already consumed, so without this a provider blink at the
# wrong second meant a down host nobody ever heard about.
# ----------------------------------------------------------------------------

OUTBOX_MAX_AGE = 24 * 3600


OUTBOX_KICK = threading.Event()


def tg_retryable(err):
    """Network errors, 5xx and 429 pass; other 4xx (bad markup, bot blocked,
    chat gone) will fail the same way forever."""
    m = re.match(r"Telegram API (\d+)", err or "")
    if not m:
        return True
    code = int(m.group(1))
    return code == 429 or code >= 500


def outbox_put(params, kind, err):
    with storage._db_lock:
        storage._db.execute("INSERT INTO tg_outbox (created, kind, params, attempts, next_try, last_error) "
                    "VALUES (?,?,?,?,?,?)",
                    (time.time(), kind, json.dumps(params, ensure_ascii=False), 1,
                     time.time() + 30, err))
        storage._db.commit()


def outbox_flush(now=None):
    """Send what is due. Returns (sent, dropped). Order kept: stop at the first
    failure, so a later alert never overtakes an earlier one."""
    now = now or time.time()
    with storage._db_lock:
        rows = storage._db.execute("SELECT id, created, kind, params, attempts FROM tg_outbox "
                           "WHERE next_try <= ? ORDER BY id", (now,)).fetchall()
    sent = dropped = 0
    for oid, created, kind, raw, attempts in rows:
        if now - created > OUTBOX_MAX_AGE:
            print(f"[outbox] выброшено после {attempts} попыток: {raw[:120]}")
            with storage._db_lock:
                storage._db.execute("DELETE FROM tg_outbox WHERE id=?", (oid,))
                storage._db.commit()
            dropped += 1
            continue
        params = json.loads(raw)
        late = time.strftime("%H:%M", time.localtime(created))
        params["text"] = f"⏳ <i>с задержкой, событие в {late}</i>\n" + params.get("text", "")
        res, err = telegram._tg_call("sendMessage", params, 10)
        telegram.tg_log_sent(params, err, kind=kind)
        with storage._db_lock:
            if err is None or not tg_retryable(err):
                storage._db.execute("DELETE FROM tg_outbox WHERE id=?", (oid,))
                if err:
                    print(f"[outbox] отказ Telegram, не повторяю: {err}")
            else:
                storage._db.execute("UPDATE tg_outbox SET attempts=?, next_try=?, last_error=? WHERE id=?",
                            (attempts + 1, now + min(30 * 2 ** attempts, 600), err, oid))
            storage._db.commit()
        if err is None:
            sent += 1
        elif tg_retryable(err):
            break
    return sent, dropped


def outbox_loop():
    while True:
        OUTBOX_KICK.wait(30)
        OUTBOX_KICK.clear()
        try:
            if telegram.telegram_ready():
                outbox_flush()
        except Exception as e:
            print(f"[outbox] {core.short_err(e)}")


def maybe_runbook(down_events):
    """Auto-fix the obvious case: a host with a MAC goes down -> send WoL,
    wait, recheck, report. Returns the set of host ids it took over."""
    rb = core.cfg("runbook", {}) or {}
    if not rb.get("enabled"):
        return set()
    handled = set()
    if rb.get("auto_wake", True):
        wait = max(15, int(rb.get("recheck_after_seconds") or 120))
        for e in down_events:
            h = e["host"]
            if h.get("mac"):
                threading.Thread(target=_runbook_wake, args=(h, wait), daemon=True).start()
                handled.add(h["id"])
    return handled


def _runbook_wake(host, wait):
    name = html.escape(str(host.get("name", "")))
    try:
        checks.send_wol(host["mac"], host.get("broadcast") or None)
    except Exception as e:
        alerting.emit("wol", f"⚙️ Авто-runbook: не смог отправить WoL для {name} — {html.escape(core.short_err(e))}")
        return
    time.sleep(wait)
    up, latency, error = checks.run_check(host, core.cfg("timeout_seconds", 3))
    if up:
        lat = f" ({round(latency)} мс)" if latency is not None else ""
        alerting.emit("wol", f"✅ <b>Авто-runbook сработал</b>: {name} поднялся после WoL{lat}.\n"
                f"Тебя не дёргали зря.")
    else:
        alerting.emit("wol", f"🔴 <b>Авто-runbook не помог</b>: {name} не ответил после WoL "
                f"({html.escape(str(error or 'нет ответа'))}). Нужен ты.")


def _affected_line(host_id):
    hit = services.services_hit(host_id)
    return f"\n⚠️ Затронуто: <b>{html.escape(', '.join(hit))}</b>" if hit else ""


def _down_text(e, extra=""):
    h = e["host"]
    return (f"🔴 <b>НЕДОСТУПЕН</b>: {html.escape(str(h.get('name', '')))}\n"
            f"<code>{html.escape(passive.host_target(h))}</code>\n"
            f"Ошибка: {html.escape(str(e.get('error') or 'нет ответа'))}"
            f"{_affected_line(h.get('id'))}{extra}")


def _up_text(e):
    h = e["host"]
    return (f"🟢 <b>ВОССТАНОВЛЕН</b>: {html.escape(str(h.get('name', '')))}\n"
            f"<code>{html.escape(passive.host_target(h))}</code>\n"
            f"Был недоступен {alerting.fmt_duration(e['downtime'])}")


def _storm_text(events, kind, suppressed=0):
    if kind == "down":
        head = (f"⚠️ <b>МАССОВОЕ ПАДЕНИЕ</b>: {len(events)} хостов недоступны разом\n"
                f"Похоже на сетевую проблему, а не на {len(events)} отдельных поломок.")
        icon = "🔴"
    else:
        head = f"✅ <b>МАССОВОЕ ВОССТАНОВЛЕНИЕ</b>: {len(events)} хостов вернулись"
        icon = "🟢"
    lines = [head, ""]
    for e in events[:15]:
        h = e["host"]
        lines.append(f"{icon} {html.escape(str(h.get('name', '')))} — "
                     f"<code>{html.escape(passive.host_target(h))}</code>")
    if len(events) > 15:
        lines.append(f"… и ещё {len(events) - 15}")
    if suppressed:
        lines.append(f"\n({suppressed} алертов подавлено по родительским хостам)")
    if kind == "down":
        hit = sorted({n for e in events for n in services.services_hit(e["host"].get("id"))})
        if hit:
            lines.append(f"\n⚠️ Затронуто: <b>{html.escape(', '.join(hit))}</b>")
    lines.append("\n/status — подробности")
    return "\n".join(lines)
