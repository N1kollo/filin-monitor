"""Wake-on-LAN schedule."""

import html
import threading

from . import core, checks


# ----------------------------------------------------------------------------
# WoL schedule — "wake the shop at 08:30 on weekdays". Rides on the existing
# WoL sender; fires once per rule per day, then verifies who actually came up.
# The monitor cannot wake itself (D15) — that's what BIOS auto-power-on is for.
# ----------------------------------------------------------------------------

_SCHED_FIRED = {}  # rule_id -> "YYYY-MM-DD HH:MM" (double-fire guard, in-memory)


def schedule_targets(rule):
    """Hosts this rule wakes: the listed ids, or every enabled host with a MAC."""
    ids = rule.get("hosts") or []
    out = []
    for h in livestate.enabled_hosts():
        if not h.get("mac"):
            continue
        if ids and h["id"] not in ids:
            continue
        out.append(h)
    return out


def schedule_due(rule, lt, fired=None):
    """Is this rule due at local time `lt` (a time.struct_time)? Pure logic:
    enabled + HH:MM matches + weekday allowed + not already fired this minute."""
    if not rule.get("enabled", True):
        return False
    t = str(rule.get("time") or "")
    try:
        hh, mm = t.split(":")[:2]
        hh, mm = int(hh), int(mm)
    except (ValueError, IndexError):
        return False
    if lt.tm_hour != hh or lt.tm_min != mm:
        return False
    days = rule.get("days") or []
    if days and lt.tm_wday not in days:
        return False
    stamp = f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d} {hh:02d}:{mm:02d}"
    return (fired if fired is not None else _SCHED_FIRED).get(rule.get("id")) != stamp


def run_schedule_rule(rule):
    targets = schedule_targets(rule)
    name = html.escape(str(rule.get("name") or rule.get("time") or "расписание"))
    if not targets:
        alerting.emit("wol", f"⏰ Расписание «{name}»: будить некого — нет включённых хостов с MAC.")
        return
    sent, failed = [], []
    for h in targets:
        try:
            checks.send_wol(h["mac"], h.get("broadcast") or None)
            sent.append(h)
        except Exception as e:
            failed.append((h, core.short_err(e)))
    lines = [f"⏰ <b>WoL по расписанию</b> «{name}»: отправлено пакетов — {len(sent)}"]
    for h, err in failed:
        lines.append(f"⚠️ {html.escape(str(h.get('name', '')))}: не отправлен ({html.escape(err)})")
    alerting.emit("wol", "\n".join(lines))
    if rule.get("verify", True) and sent:
        threading.Thread(target=recovery._schedule_verify, args=(name, sent), daemon=True).start()


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import recovery, alerting, livestate  # noqa: E402
