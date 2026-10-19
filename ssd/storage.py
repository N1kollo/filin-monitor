"""SQLite: schema, journal of events, pruning, runtime snapshot."""

import json
import sqlite3
import threading
import time

from . import core


# ----------------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------------

_db = sqlite3.connect(core.DB_PATH, check_same_thread=False)


_db_lock = threading.Lock()


def db_init():
    with _db_lock:
        _db.execute(
            """CREATE TABLE IF NOT EXISTS checks (
                host_id TEXT NOT NULL, ts REAL NOT NULL,
                up INTEGER NOT NULL, latency REAL, error TEXT )"""
        )
        _db.execute("CREATE INDEX IF NOT EXISTS idx_checks ON checks (host_id, ts)")
        _db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                host_id TEXT NOT NULL, ts REAL NOT NULL,
                type TEXT NOT NULL, detail TEXT, downtime REAL )"""
        )
        _db.execute("CREATE INDEX IF NOT EXISTS idx_events ON events (host_id, ts)")
        _db.execute(
            """CREATE TABLE IF NOT EXISTS inventory (
                host_id TEXT PRIMARY KEY, mac TEXT, vendor TEXT,
                hostname TEXT, os TEXT, ports TEXT, updated REAL )"""
        )
        inv_cols = [r[1] for r in _db.execute("PRAGMA table_info(inventory)").fetchall()]
        if "os" not in inv_cols:
            _db.execute("ALTER TABLE inventory ADD COLUMN os TEXT DEFAULT ''")
        # Network snapshots: ip -> mac at a point in time, for the diff view.
        # `present` = was alive in the LAST scan, so "disappeared" is reported
        # once (on the scan it drops out), not forever after.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS arp_seen (
                ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT,
                first_seen REAL, last_seen REAL, present INTEGER DEFAULT 1 )"""
        )
        cols = [r[1] for r in _db.execute("PRAGMA table_info(arp_seen)").fetchall()]
        if "present" not in cols:
            _db.execute("ALTER TABLE arp_seen ADD COLUMN present INTEGER DEFAULT 1")
        if "hostname" not in cols:
            _db.execute("ALTER TABLE arp_seen ADD COLUMN hostname TEXT")
        # MAC change log per IP — the raw material for IP conflict detection.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS mac_history (
                ip TEXT NOT NULL, mac TEXT NOT NULL, ts REAL NOT NULL )"""
        )
        _db.execute("CREATE INDEX IF NOT EXISTS idx_mac_history ON mac_history (ip, ts)")
        # Persisted traceroute paths -> lets the map draw router nodes between subnets.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS trace_hops (
                target TEXT PRIMARY KEY, hops TEXT, updated REAL )"""
        )
        # Wi-Fi RF view reported by sensors. One row per (bssid, sensor); `trusted`
        # marks the mesh baseline learned in the first learn_hours.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS wifi_seen (
                bssid TEXT NOT NULL, sensor TEXT NOT NULL, ssid TEXT,
                signal INTEGER, channel INTEGER, radio TEXT, auth TEXT,
                first_seen REAL, last_seen REAL, trusted INTEGER DEFAULT 0,
                PRIMARY KEY (bssid, sensor) )"""
        )
        _db.execute(
            """CREATE TABLE IF NOT EXISTS wifi_sensors (
                sensor TEXT PRIMARY KEY, last_report REAL )"""
        )
        # Every sendMessage the bot attempted. `events` says what happened on the
        # network; this says what actually reached the phone (after audible(),
        # hold-down, storm digest) — the only source for "how noisy is the bot".
        _db.execute(
            """CREATE TABLE IF NOT EXISTS tg_sent (
                ts REAL NOT NULL, kind TEXT NOT NULL, chat_id TEXT,
                ok INTEGER NOT NULL, error TEXT, text TEXT )"""
        )
        _db.execute("CREATE INDEX IF NOT EXISTS idx_tg_sent ON tg_sent (ts)")
        # Alerts Telegram didn't take (link down, 5xx, 429): retried with backoff
        # instead of lost with the state transition that produced them.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS tg_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL,
                kind TEXT, params TEXT NOT NULL, attempts INTEGER DEFAULT 0,
                next_try REAL NOT NULL, last_error TEXT )"""
        )
        # Snapshots of in-memory alert bookkeeping (escalations, acks, dedup
        # ledgers) so a restart doesn't replay or forget them. name -> JSON.
        _db.execute(
            """CREATE TABLE IF NOT EXISTS runtime_state (
                name TEXT PRIMARY KEY, value TEXT NOT NULL, ts REAL NOT NULL )"""
        )
        # Wi-Fi alerts already sent and still standing. In memory only, a restart
        # forgot them and re-sent every standing condition at once (31 on 10-13).
        _db.execute(
            """CREATE TABLE IF NOT EXISTS wifi_alerted (
                key TEXT PRIMARY KEY, ts REAL NOT NULL )"""
        )
        _db.commit()


def db_inventory_save(inv):
    with _db_lock:
        _db.execute(
            "INSERT OR REPLACE INTO inventory (host_id, mac, vendor, hostname, os, ports, updated) "
            "VALUES (?,?,?,?,?,?,?)",
            (inv["host_id"], inv["mac"], inv["vendor"], inv["hostname"],
             inv.get("os", ""), json.dumps(inv["ports"], ensure_ascii=False), inv["updated"]),
        )
        _db.commit()


def db_inventory_all():
    with _db_lock:
        rows = _db.execute(
            "SELECT host_id, mac, vendor, hostname, os, ports, updated FROM inventory"
        ).fetchall()
    out = {}
    for r in rows:
        try:
            ports = json.loads(r[5] or "[]")
        except ValueError:
            ports = []
        out[r[0]] = {"mac": r[1], "vendor": r[2], "hostname": r[3], "os": r[4] or "",
                     "ports": ports, "updated": r[6]}
    return out


def db_save_trace(target, hops):
    if not target:
        return
    with _db_lock:
        _db.execute(
            "INSERT OR REPLACE INTO trace_hops (target, hops, updated) VALUES (?,?,?)",
            (target, json.dumps(hops), time.time()))
        _db.commit()


def db_trace_paths():
    with _db_lock:
        rows = _db.execute("SELECT target, hops FROM trace_hops").fetchall()
    out = {}
    for tgt, hj in rows:
        try:
            out[tgt] = json.loads(hj or "[]")
        except ValueError:
            pass
    return out


def db_event(host_id, ts, type_, detail=None, downtime=None):
    with _db_lock:
        _db.execute(
            "INSERT INTO events (host_id, ts, type, detail, downtime) VALUES (?,?,?,?,?)",
            (host_id, ts, type_, detail, downtime),
        )
        _db.commit()


def db_events(host_id, limit=30):
    with _db_lock:
        rows = _db.execute(
            "SELECT ts, type, detail, downtime FROM events WHERE host_id=? ORDER BY ts DESC LIMIT ?",
            (host_id, limit),
        ).fetchall()
    return [{"ts": r[0], "type": r[1], "detail": r[2], "downtime": r[3]} for r in rows]


def db_record(host_id, ts, up, latency, error):
    with _db_lock:
        _db.execute(
            "INSERT INTO checks (host_id, ts, up, latency, error) VALUES (?,?,?,?,?)",
            (host_id, ts, 1 if up else 0, latency, error),
        )
        _db.commit()


def db_prune():
    cutoff = time.time() - core.cfg("history_retention_hours", 168) * 3600
    arp_cutoff = time.time() - 7 * 86400  # forget devices gone from ARP for a week
    tg_cutoff = time.time() - 90 * 86400  # noise analysis wants weeks, not the 7d of checks
    with _db_lock:
        _db.execute("DELETE FROM checks WHERE ts < ?", (cutoff,))
        _db.execute("DELETE FROM tg_sent WHERE ts < ?", (tg_cutoff,))
        # Events drive SLA reports (up to 365 days) — keep a bit over a year.
        _db.execute("DELETE FROM events WHERE ts < ?", (time.time() - 400 * 86400,))
        # Wi-Fi: a renamed AP or retired SSID left a trusted row that reported
        # "пропала из эфира" forever; mall hotspots piled up as untrusted rows.
        # Gone for 14 days = gone (its alert went out on day one).
        wifi_cutoff = time.time() - 14 * 86400
        _db.execute("DELETE FROM wifi_seen WHERE last_seen < ?", (wifi_cutoff,))
        _db.execute("DELETE FROM wifi_sensors WHERE last_report < ?", (wifi_cutoff,))
        _db.execute("DELETE FROM arp_seen WHERE present=0 AND last_seen < ?", (arp_cutoff,))
        _db.commit()


def db_history(host_id, limit=40):
    with _db_lock:
        rows = _db.execute(
            "SELECT ts, up, latency FROM checks WHERE host_id=? ORDER BY ts DESC LIMIT ?",
            (host_id, limit),
        ).fetchall()
    return list(reversed(rows))


def db_median_latency(host_id, since, until=None):
    """Median latency of successful checks in a window. Computed in SQL via
    ORDER BY + OFFSET — pulling a week of samples into Python per host per
    minute would not scale. Returns (median, sample_count)."""
    where = "host_id=? AND ts>=? AND up=1 AND latency IS NOT NULL"
    params = [host_id, since]
    if until is not None:
        where += " AND ts<?"
        params.append(until)
    with _db_lock:
        n = _db.execute(f"SELECT COUNT(*) FROM checks WHERE {where}", params).fetchone()[0]
        if not n:
            return None, 0
        row = _db.execute(
            f"SELECT latency FROM checks WHERE {where} ORDER BY latency LIMIT 1 OFFSET ?",
            params + [n // 2],
        ).fetchone()
    return (row[0] if row else None), n


def db_report(days=30):
    """Per-host uptime / incidents / downtime for an SLA report.
    NOTE: limited by history_retention_hours — a 30-day report on 7-day
    retention only has 7 days of data. We report the ACTUAL covered span so
    the number isn't a lie."""
    now = time.time()
    cutoff = now - days * 86400
    items = []
    total_down = 0.0
    worst_up = None
    for h in core.cfg("hosts", []):
        hid = h["id"]
        with _db_lock:
            row = _db.execute(
                "SELECT SUM(up), COUNT(*), MIN(ts) FROM checks WHERE host_id=? AND ts>=?",
                (hid, cutoff)).fetchone()
            evs = _db.execute(
                "SELECT type, downtime FROM events WHERE host_id=? AND ts>=?",
                (hid, cutoff)).fetchall()
        ups, total, earliest = (row[0] or 0), (row[1] or 0), row[2]
        uptime = round(100.0 * ups / total, 3) if total else None
        incidents = sum(1 for t, _ in evs if t == "down")
        downtime = sum(d for t, d in evs if t == "up" and d)
        total_down += downtime
        if uptime is not None and (worst_up is None or uptime < worst_up):
            worst_up = uptime
        items.append({
            "name": h.get("name", hid),
            "target": passive.host_target(h),
            "uptime": uptime,
            "incidents": incidents,
            "downtime": downtime,
            "downtime_human": alerting.fmt_duration(downtime) if downtime else "—",
            "covered_days": round((now - earliest) / 86400, 1) if earliest else 0,
        })
    items.sort(key=lambda x: (x["uptime"] is None, x["uptime"] if x["uptime"] is not None else 0))
    retention_days = round(core.cfg("history_retention_hours", 168) / 24, 1)
    return {
        "days": days,
        "retention_days": retention_days,
        "coverage_capped": days > retention_days,
        "generated": now,
        "items": items,
        "summary": {
            "hosts": len(items),
            "total_incidents": sum(i["incidents"] for i in items),
            "total_downtime_human": alerting.fmt_duration(total_down) if total_down else "—",
            "worst_uptime": worst_up,
        },
    }


def db_events_all(limit=100, hours=168):
    """Incident log across every host — powers the History section."""
    cutoff = time.time() - hours * 3600
    with _db_lock:
        rows = _db.execute(
            "SELECT host_id, ts, type, detail, downtime FROM events "
            "WHERE ts>=? ORDER BY ts DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    names = {h["id"]: h.get("name", h["id"]) for h in core.cfg("hosts", [])}
    names.update(wanwatch.WAN_EVENT_NAMES)
    return [{
        "host_id": r[0],
        "name": names.get(r[0], "(удалён)"),
        "ts": r[1], "type": r[2], "detail": r[3], "downtime": r[4],
    } for r in rows]


def db_series(host_id, hours=24, buckets=120):
    """Downsample raw checks into fixed time buckets for charting.
    24h at a 30s interval is ~2880 points — far more than a chart needs."""
    now = time.time()
    cutoff = now - hours * 3600
    width = (hours * 3600) / buckets
    with _db_lock:
        rows = _db.execute(
            "SELECT ts, up, latency FROM checks WHERE host_id=? AND ts>=? ORDER BY ts",
            (host_id, cutoff),
        ).fetchall()
    agg = [{"t": cutoff + i * width, "lat_sum": 0.0, "lat_n": 0, "up": 0, "n": 0}
           for i in range(buckets)]
    for ts, up, lat in rows:  # single pass
        i = int((ts - cutoff) / width)
        if i < 0 or i >= buckets:
            continue
        b = agg[i]
        b["n"] += 1
        b["up"] += 1 if up else 0
        if lat is not None:
            b["lat_sum"] += lat
            b["lat_n"] += 1
    return [{
        "t": b["t"],
        "lat": round(b["lat_sum"] / b["lat_n"], 1) if b["lat_n"] else None,
        "up": round(b["up"] / b["n"], 3) if b["n"] else None,
        "n": b["n"],
    } for b in agg]


def db_uptime(host_id, hours=24):
    cutoff = time.time() - hours * 3600
    with _db_lock:
        row = _db.execute(
            "SELECT SUM(up), COUNT(*) FROM checks WHERE host_id=? AND ts>=?",
            (host_id, cutoff),
        ).fetchone()
    ups, total = (row[0] or 0), (row[1] or 0)
    return round(100.0 * ups / total, 2) if total else None


# In-memory alert bookkeeping that must survive a restart. Each was a separate
# "restart replays alerts" bug (0.42.1 fixed Wi-Fi alone). Saved once per check
# cycle, restored before any thread starts; mutated in place so every
# reference held elsewhere stays valid.
def _runtime_registry():
    return {
        "escalate": policy.ESCALATE, "acked": policy.ACKED, "announced": policy.ANNOUNCED, "degraded": degradation.DEGRADED,
        "unifi_down": unifi._UNIFI_DOWN, "dhcp_alerted": dhcp._DHCP_ALERTED,
        "conflict_alerted": ipconflict._CONFLICT_ALERTED, "passive_alerted": passive._PASSIVE_ALERTED,
        "sched_fired": wolschedule._SCHED_FIRED, "digest_fired": policy._DIGEST_FIRED, "unifi_ctrl": unifi.UNIFI_CTRL,
        "unifi_ap_told": unifi._UNIFI_AP_TOLD, "unifi_ap_log": unifi.UNIFI_AP_LOG, "groups": services.GROUPS,
    }


def runtime_save():
    now = time.time()
    rows = []
    for name, obj in _runtime_registry().items():
        snap = sorted(obj) if isinstance(obj, set) else dict(obj)
        rows.append((name, json.dumps(snap, ensure_ascii=False), now))
    with _db_lock:
        _db.executemany("INSERT OR REPLACE INTO runtime_state (name, value, ts) VALUES (?,?,?)", rows)
        _db.commit()


def runtime_restore():
    """Returns the names that were actually restored."""
    with _db_lock:
        saved = dict(_db.execute("SELECT name, value FROM runtime_state").fetchall())
    restored = set()
    for name, obj in _runtime_registry().items():
        if name not in saved:
            continue
        try:
            val = json.loads(saved[name])
        except ValueError:
            continue
        obj.clear()
        obj.update(val)
        restored.add(name)
    return restored


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import dhcp, ipconflict, passive, wolschedule, services, wanwatch, alerting, policy, degradation, unifi  # noqa: E402
