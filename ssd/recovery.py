"""Recovery after a power cut: wake hosts in waves by parent."""

import html
import json
import threading
import time

from . import core, checks, wolschedule


# ----------------------------------------------------------------------------
# Recovery after a power cut. The real case (10-2026): the building lost power,
# nobody on site, everything brought back from Telegram with /wake, one host at
# a time, in whatever order memory suggested. The monitor knows the order:
# Hyper-V hosts first (VMs autostart with them — WoL can't reach a VM anyway),
# re-check, then whatever is still dark and has a MAC.
# ----------------------------------------------------------------------------

RECOVERY_LOCK = threading.Lock()


RECOVERY = {"running": False, "started": 0.0, "finished": 0.0, "by": "", "steps": []}


HYPERV_VM_MAC = "00:15:5d"


def _is_vm(h):
    return (h.get("mac") or "").lower().replace("-", ":").startswith(HYPERV_VM_MAC)


def recovery_plan(hosts=None, statuses=None):
    """Pure: down hosts -> ordered steps. action: wol (wave 1 = nothing above it
    is down, wave 2 = waits for its parent) | wait_parent (a VM behind a down
    host: it comes up with the host) | vm_manual (a VM down while its host is
    fine: start it in Hyper-V) | no_mac (nothing to wake it with)."""
    hosts = livestate.enabled_hosts() if hosts is None else hosts
    if statuses is None:
        with livestate.STATE_LOCK:
            statuses = {k: v["status"] for k, v in livestate.STATE.items()}
    down = [h for h in hosts if statuses.get(h["id"]) == "down"]
    down_ids = {h["id"] for h in down}
    steps = []
    for h in down:
        parent_down = bool(h.get("parent")) and h["parent"] in down_ids
        if _is_vm(h):
            action, wave = ("wait_parent", 2) if parent_down else ("vm_manual", 0)
        elif not h.get("mac"):
            action, wave = "no_mac", 0
        else:
            action, wave = "wol", (2 if parent_down else 1)
        steps.append({"id": h["id"], "name": h.get("name", h["id"]), "action": action, "wave": wave,
                      "result": "pending" if action in ("wol", "wait_parent") else "skip"})
    steps.sort(key=lambda x: (x["wave"] or 9, x["name"].lower()))
    return steps


def _names(steps):
    return ", ".join(html.escape(x["name"]) for x in steps[:15]) + (
        f" и ещё {len(steps) - 15}" if len(steps) > 15 else "")


def recovery_report(steps):
    up = [x for x in steps if x["result"] == "up"]
    lines = ["⏻ <b>Восстановление: итог</b>"]
    if up:
        lines.append(f"✅ Встали: {_names(up)}")
    dead = [x for x in steps if x["result"] == "down" and x["action"] == "wol"]
    if dead:
        lines.append(f"❌ Не встали после WoL: {_names(dead)}")
    vms = [x for x in steps if x["result"] == "down" and x["action"] == "wait_parent"]
    vms += [x for x in steps if x["action"] == "vm_manual"]
    if vms:
        lines.append(f"🖥 VM лежат — запусти в «Диспетчере Hyper-V»: {_names(vms)}")
    nomac = [x for x in steps if x["action"] == "no_mac"]
    if nomac:
        lines.append(f"⚪ Без MAC, будить нечем: {_names(nomac)}")
    return "\n".join(lines)


def recovery_run(by="", wait=None):
    """Wave 1 -> wait -> re-check -> wave 2 -> wait -> re-check -> report.
    Returns False if a run is already in progress."""
    with RECOVERY_LOCK:
        if RECOVERY["running"]:
            return False
        steps = recovery_plan()
        RECOVERY.update(running=True, started=time.time(), finished=0.0, by=by, steps=steps)
    try:
        if wait is None:
            try:
                wait = max(30, int((core.cfg("recovery", {}) or {}).get("wait_seconds") or 180))
            except (TypeError, ValueError):
                wait = 180
        hosts = {h["id"]: h for h in livestate.enabled_hosts()}
        timeout = core.cfg("timeout_seconds", 3)
        w1 = [x for x in steps if x["action"] == "wol" and x["wave"] == 1]
        later = [x for x in steps if x["wave"] == 2]
        if not [x for x in steps if x["result"] == "pending"]:
            alerting.emit("recovery", recovery_report(steps))
            return True
        alerting.emit("recovery", "⏻ <b>Поднимаю упавшие</b>"
             + (f"\nСейчас: {_names(w1)}" if w1 else "")
             + (f"\nЗатем, когда встанут их хосты: {_names(later)}" if later else "")
             + f"\nПроверю через {wait // 60} мин." + (f" Запустил: {html.escape(by)}." if by else ""))

        def wake(items):
            for x in items:
                h = hosts.get(x["id"]) or {}
                try:
                    checks.send_wol(h["mac"], h.get("broadcast") or None)
                    x["result"] = "sent"
                except Exception as e:
                    print(f"[recovery] WoL {x['name']}: {core.short_err(e)}")

        def recheck():
            for x in steps:
                if x["result"] in ("pending", "sent") and x["id"] in hosts:
                    if checks.run_check(hosts[x["id"]], timeout)[0]:
                        x["result"] = "up"

        wake(w1)
        time.sleep(wait)
        recheck()
        w2 = [x for x in steps if x["action"] == "wol" and x["wave"] == 2 and x["result"] != "up"]
        if w2 or [x for x in steps if x["result"] in ("pending", "sent")]:
            wake(w2)
            time.sleep(wait)
            recheck()
        for x in steps:
            if x["result"] in ("pending", "sent"):
                x["result"] = "down"
        alerting.emit("recovery", recovery_report(steps))
        return True
    finally:
        with RECOVERY_LOCK:
            RECOVERY.update(running=False, finished=time.time())


def recovery_start(by=""):
    """Kick off a run in the background. False if one is already running."""
    with RECOVERY_LOCK:
        if RECOVERY["running"]:
            return False
    threading.Thread(target=recovery_run, kwargs={"by": by}, daemon=True).start()
    return True


def recovery_view_data():
    with RECOVERY_LOCK:
        st = json.loads(json.dumps(RECOVERY))
    plan = [] if st["running"] else recovery_plan()
    st["plan"] = plan
    st["actionable"] = sum(1 for x in plan if x["result"] == "pending")
    return st


def _schedule_verify(name, hosts, wait=180):
    """The follow-through: a magic packet is fire-and-forget, so N minutes
    later re-check every target and report the ones still dark."""
    time.sleep(wait)
    timeout = core.cfg("timeout_seconds", 3)
    dead = []
    for h in hosts:
        up, _, _ = checks.run_check(h, timeout)
        if not up:
            dead.append(h)
    if dead:
        who = ", ".join(html.escape(str(h.get("name", ""))) for h in dead[:10])
        more = f" и ещё {len(dead) - 10}" if len(dead) > 10 else ""
        alerting.emit("wol", f"⚠️ Расписание «{name}»: через {wait // 60} мин не поднялись: {who}{more}")
    else:
        alerting.emit("wol", f"✅ Расписание «{name}»: все {len(hosts)} в строю.")


def wol_schedule_loop():
    while True:
        lt = time.localtime()
        for rule in (core.cfg("wol_schedule", []) or []):
            try:
                if wolschedule.schedule_due(rule, lt):
                    wolschedule._SCHED_FIRED[rule.get("id")] = (
                        f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d} "
                        f"{lt.tm_hour:02d}:{lt.tm_min:02d}")
                    threading.Thread(target=wolschedule.run_schedule_rule,
                                     args=(dict(rule),), daemon=True).start()
            except Exception as e:
                print(f"[schedule] {core.short_err(e)}")
        time.sleep(20)  # 3 ticks per minute — a due minute can't slip through


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting, livestate  # noqa: E402
