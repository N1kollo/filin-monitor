"""Live host state and the check loop."""

import threading
import time

from . import core, storage


# ----------------------------------------------------------------------------
# Live state + monitor loop
# ----------------------------------------------------------------------------

STATE_LOCK = threading.Lock()


STATE: dict = {}  # host_id -> dict


def enabled_hosts():
    with core.CONFIG_LOCK:
        return [dict(h) for h in core.CONFIG.get("hosts", []) if h.get("enabled", True)]


def db_last_transition(host_id):
    """(type, ts) of the host's last down/up event, or None."""
    with storage._db_lock:
        return storage._db.execute(
            "SELECT type, ts FROM events WHERE host_id=? AND type IN ('down','up') "
            "ORDER BY ts DESC LIMIT 1", (host_id,)).fetchone()


def reconcile_state():
    hosts = enabled_hosts()
    ids = {h["id"] for h in hosts}
    new = [h for h in hosts if h["id"] not in STATE]
    # A host that was down when the monitor stopped starts as down: still down
    # -> no second "упал"; came back meanwhile -> "восстановлен" with the real
    # downtime. Starting from "pending" re-alerted the first and lost the second.
    last = {h["id"]: db_last_transition(h["id"]) for h in new}
    with STATE_LOCK:
        for h in new:
            st = {"id": h["id"], "status": "pending", "latency": None,
                  "error": None, "fails": 0, "since": time.time(), "last_ts": None}
            tr = last.get(h["id"])
            if tr and tr[0] == "down":
                st.update(status="down", since=tr[1], fails=core.cfg("fail_threshold", 2))
            STATE[h["id"]] = st
        for stale in [k for k in STATE if k not in ids]:
            del STATE[stale]


def process_result(host, up, latency, error):
    """Update state, log history, and RETURN a transition event (if any).
    Alerting is deliberately not done here — see dispatch_alerts()."""
    hid = host["id"]
    now = time.time()
    storage.db_record(hid, now, up, latency, error)
    threshold = core.cfg("fail_threshold", 2)
    event = None

    with STATE_LOCK:
        st = STATE.get(hid)
        if not st:
            return None
        prev = st["status"]
        st["latency"] = round(latency, 1) if latency is not None else None
        st["error"] = error
        st["last_ts"] = now
        if up:
            st["fails"] = 0
            if prev == "down":
                event = {"type": "up", "host": host, "downtime": now - st["since"]}
            if prev != "up":
                st["status"] = "up"
                st["since"] = now
        else:
            st["fails"] += 1
            if st["fails"] >= threshold and prev != "down":
                st["status"] = "down"
                st["since"] = now
                event = {"type": "down", "host": host, "error": error}

    if event:
        storage.db_event(hid, now, event["type"],
                 event.get("error"), event.get("downtime"))
    return event


def parent_is_down(parent_id):
    if not parent_id:
        return False
    with STATE_LOCK:
        st = STATE.get(parent_id)
    return bool(st and st["status"] == "down")
