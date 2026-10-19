"""Hold-down: «упал» vs «моргнул»."""

import json
import time
from concurrent.futures import TimeoutError as FutureTimeout

from . import core, checks, ipconflict, pathdiag, alerting, livestate, policy, outbox


# ----------------------------------------------------------------------------
# Hold-down — the difference between "упал" and "моргнул". A transition is
# journaled the moment it happens (the dashboard always tells the truth); the
# PHONE only rings if the host is still down when the hold expires. A recovery
# that arrives first cancels the pending alert and its own "восстановлен" with
# it: nobody needs the recovery of an outage they were never told about.
# Trace-on-down rides inside dispatch_alerts, so blinks stop tracing too.
# ----------------------------------------------------------------------------

PENDING_DOWN = {}  # host_id -> {"event": ev, "due": ts}


def hold_for(host):
    """Seconds to hold this host's down alert. Critical hosts skip the wait —
    D28 says critical always rings, and waiting is a form of not ringing."""
    al = core.cfg("alerts", {}) or {}
    try:
        hold = max(0, int(al.get("hold_down_seconds") or 0))
    except (TypeError, ValueError):
        return 0
    if hold and al.get("hold_down_skip_critical", True)             and policy.alert_class(host) == "critical":
        return 0
    return hold


def apply_hold_down(events, now=None):
    """Split transitions into what rings now and what waits for confirmation.
    Returns the events dispatch_alerts should act on."""
    now = now or time.time()
    out = []
    for e in events:
        hid = e["host"]["id"]
        if e["type"] == "down":
            hold = hold_for(e["host"])
            if hold:
                PENDING_DOWN[hid] = {"event": e, "due": now + hold}
            else:
                out.append(e)
        elif PENDING_DOWN.pop(hid, None) is not None:
            continue  # blink ended before the phone ever rang
        else:
            out.append(e)

    for hid, rec in list(PENDING_DOWN.items()):
        if rec["due"] > now:
            continue
        PENDING_DOWN.pop(hid, None)
        with livestate.STATE_LOCK:
            st = livestate.STATE.get(hid)
        if st and st["status"] == "down":
            # report the error we are looking at now, not the first miss
            rec["event"]["error"] = st.get("error") or rec["event"].get("error")
            out.append(rec["event"])
    return out


def dispatch_alerts(events):
    """Decide what actually reaches Telegram: individual alerts, a storm digest,
    or nothing (because a parent host is down and explains the children)."""
    if not events:
        return
    al = core.cfg("alerts", {}) or {}
    try:
        threshold = max(2, int(al.get("storm_threshold") or 5))
    except (TypeError, ValueError):
        threshold = 5

    downs = [e for e in events if e["type"] == "down"]
    ups = [e for e in events if e["type"] == "up"]

    # Muted hosts: the user tapped "🔇" — swallow their down alerts entirely.
    downs = [e for e in downs if not policy.is_muted(e["host"]["id"])]

    # Parent suppression: a dead gateway explains its children — don't spam.
    suppressed_by = {}
    if al.get("parent_suppression", True):
        keep = []
        for e in downs:
            pid = e["host"].get("parent")
            if pid and livestate.parent_is_down(pid):
                suppressed_by[pid] = suppressed_by.get(pid, 0) + 1
            else:
                keep.append(e)
        downs = keep
    total_suppressed = sum(suppressed_by.values())

    # Auto-runbook takes over hosts it can try to wake before we bother the
    # human — it acts even during quiet hours (fix silently before morning),
    # but never touches a host under maintenance: YOU are rebooting it.
    auto_handled = outbox.maybe_runbook([e for e in downs if not policy.in_maintenance(e["host"])])

    # Quiet hours + priority decide what actually RINGS. Everything is already
    # in the events table regardless — the morning digest reads it from there.
    # Maintenance windows silence even critical hosts: it's planned work.
    q = policy.quiet_now()
    downs = [e for e in downs if policy.audible(e["host"], q) and not policy.in_maintenance(e["host"])]
    # A recovery rings only if its outage did. Whatever the reason the down
    # stayed silent, the up is news about nothing; the journal and the morning
    # digest still have both.
    told = [e for e in ups if e["host"]["id"] in policy.ANNOUNCED]
    for e in ups:
        policy.ANNOUNCED.discard(e["host"]["id"])
    ups = [e for e in told if policy.audible(e["host"], q) and not policy.in_maintenance(e["host"])]

    def send(kind, text, host=None, markup=None):
        ok, detail = alerting.emit(kind, text, host=host, markup=markup)
        if not ok:
            print(f"[telegram] алерт не отправлен: {detail}")
        return ok and detail not in ("muted", "maintenance")

    # Path diagnosis rides along: WHERE the break is, as a follow-up message.
    pathdiag.maybe_trace(downs, storm=len(downs) >= threshold)

    if len(downs) >= threshold:
        # mass outage = likely a power cut: offer the one-tap recovery
        rec_kb = json.dumps({"inline_keyboard": [[{"text": "⏻ Поднять упавшие", "callback_data": "m:rv:n"}]]})
        if send("down", outbox._storm_text(downs, "down", total_suppressed), markup=rec_kb):
            policy.ANNOUNCED.update(e["host"]["id"] for e in downs)
    else:
        for e in downs:
            n = suppressed_by.get(e["host"]["id"], 0)
            extra = f"\n\n⚠️ За ним подавлено алертов: {n}" if n else ""
            auto = e["host"]["id"] in auto_handled
            if auto:
                wait = int((core.cfg("runbook", {}) or {}).get("recheck_after_seconds") or 120)
                extra += f"\n\n⚙️ Пробую разбудить автоматически, перепроверю через {wait}с…"
            if send("down", outbox._down_text(e, extra), host=e["host"],
                    markup=policy.down_keyboard(e["host"], with_recheck=not auto)):
                policy.ANNOUNCED.add(e["host"]["id"])

    if len(ups) >= threshold:
        send("up", outbox._storm_text(ups, "up"))
    else:
        for e in ups:
            send("up", outbox._up_text(e), host=e["host"])


CHECK_DEADLINE_MIN = 60  # seconds a whole round of checks may take, at least


def monitor_cycle(pool):
    livestate.reconcile_state()
    hosts = livestate.enabled_hosts()
    timeout = core.cfg("timeout_seconds", 3)
    futures = {pool.submit(checks.run_check, h, timeout): h for h in hosts}
    events = []
    # One overall deadline: a check stuck in name resolution (dead office DNS
    # has no timeout of its own) used to hold every alert behind it.
    deadline = time.monotonic() + max(CHECK_DEADLINE_MIN, timeout * 10)
    for fut, h in list(futures.items()):
        try:
            up, latency, error = fut.result(timeout=max(1.0, deadline - time.monotonic()))
        except FutureTimeout:
            up, latency, error = False, None, "проверка зависла (DNS?)"
        except Exception as e:
            up, latency, error = False, None, core.short_err(e)
        try:
            ev = livestate.process_result(h, up, latency, error)
        except Exception as e:
            # db locked / disk full on one host used to abort the cycle and drop
            # the transitions already collected for the others — forever.
            print(f"[monitor] {h.get('name', h.get('id'))}: {core.short_err(e)}")
            continue
        if ev:
            events.append(ev)
    # All state is settled now, so parent status is reliable — alert as a batch,
    # minus everything still serving its hold-down.
    alerts = apply_hold_down(events)
    try:
        dispatch_alerts(alerts)
    except Exception as e:
        print(f"[dispatch] {core.short_err(e)}")
    # The checks above just refreshed the OS ARP cache — free conflict watch.
    try:
        ipconflict.watch_arp_conflicts()
    except Exception as e:
        print(f"[conflict] {core.short_err(e)}")
    try:
        policy.track_escalations(alerts)
        policy.check_escalations()
    except Exception as e:
        print(f"[escalate] {core.short_err(e)}")
