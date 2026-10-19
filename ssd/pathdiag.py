"""Path diagnosis: where the break is when a host goes down."""

import html
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import parse as urlparse

from . import core, storage, checks


# ----------------------------------------------------------------------------
# Path diagnosis — a down alert should say WHERE the break is, not just that
# it happened: tracert to the target + what the monitor already knows about
# the target's /24 neighbours (free knowledge from STATE — no extra probing).
# ----------------------------------------------------------------------------

_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


_HOP_RE = re.compile(r"^(\d+)\s")


def trace_target(host):
    """The address worth tracing for this host record (hostname for http)."""
    if host.get("type") == "http":
        return urlparse.urlparse(host.get("url", "")).hostname or ""
    return host.get("host", "")


def parse_traceroute(text):
    """tracert/traceroute output -> list of hop IPs, None for silent hops.
    Locale-proof: relies only on the leading hop number and an IP somewhere in
    the line, so Russian and English Windows parse identically."""
    hops = []
    for line in text.splitlines():
        s = line.strip()
        m = _HOP_RE.match(s)
        if not m:
            continue
        ip = _IP_RE.search(s[m.end():])
        hops.append(ip.group(0) if ip else None)
    return hops


def trace_route(target, max_hops=8, wait_ms=700):
    """Run the system tracert, capped tight — on a LAN the path is 1-3 hops,
    the default 30x3s would stall for minutes. Returns hops or None."""
    is_win = os.name == "nt"
    if is_win:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(wait_ms), target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w",
               str(max(1, int(round(wait_ms / 1000.0)))), target]
    try:
        flags = subprocess.CREATE_NO_WINDOW if is_win else 0
        proc = subprocess.run(cmd, capture_output=True,
                              timeout=max_hops * 3 * (wait_ms / 1000.0) + 15,
                              creationflags=flags)
        return parse_traceroute(checks.console_text(proc.stdout))
    except Exception:
        return None


def neighbour_state(host):
    """How the OTHER monitored hosts in the target's /24 are doing right now.
    Distinguishes "this box died" from "the whole segment is gone"."""
    target = trace_target(host)
    if not _IP_RE.fullmatch(target or ""):
        return None
    prefix = target.rsplit(".", 1)[0] + "."
    with livestate.STATE_LOCK:
        statuses = {k: v["status"] for k, v in livestate.STATE.items()}
    alive = total = 0
    for h in livestate.enabled_hosts():
        if h["id"] == host.get("id"):
            continue
        t = h.get("host", "")
        if not (t.startswith(prefix) and _IP_RE.fullmatch(t)):
            continue
        st = statuses.get(h["id"])
        if st in ("up", "down"):
            total += 1
            if st == "up":
                alive += 1
    return {"alive": alive, "total": total, "prefix": prefix}


def build_diagnosis(host, hops, neigh):
    """Hop list + neighbour knowledge -> human verdict (plain text, RU).
    Returns None when there is nothing useful to say."""
    target = trace_target(host)
    names = {h.get("host"): h.get("name") for h in livestate.enabled_hosts() if h.get("host")}
    lines = []

    last = None
    if hops:
        for i, ip in enumerate(hops):
            if ip:
                last = i

    if hops:
        if last is None:
            lines.append("Трасса: ✗ — тишина уже на первом хопе.")
            lines.append("Похоже на проблему на стороне самого монитора или его линка.")
        else:
            path = " → ".join(hops[i] or "✗" for i in range(last + 1))
            reached = hops[last] == target
            if reached:
                lines.append(f"Трасса: {path} — маршрут до хоста проходит.")
                if host.get("type") in ("tcp", "http"):
                    lines.append("Машина отвечает — лежит сам сервис/порт, не сеть.")
                else:
                    lines.append("На ICMP хост жив — сбой был кратковременным, либо проверку что-то фильтрует.")
            else:
                lines.append(f"Трасса: {path} → ✗")
                brk = hops[last]
                who = names.get(brk)
                who_s = f" («{who}»)" if who else ""
                lines.append(f"Обрыв за {brk}{who_s}: хоп {last + 1} отвечает, дальше тишина.")

    if neigh and neigh["total"] >= 1:
        a, t, p = neigh["alive"], neigh["total"], neigh["prefix"]
        if a == t:
            lines.append(f"Соседи по {p}x: все {t} живы → сегмент в порядке, лёг именно этот хост.")
        elif a == 0:
            lines.append(f"Соседи по {p}x: все {t} молчат → похоже, лежит весь сегмент.")
        else:
            lines.append(f"Соседи по {p}x: {a} из {t} живы.")

    return "\n".join(lines) if lines else None


_TRACE_LOCK = threading.Lock()


_TRACE_BUSY = set()  # host_ids being traced right now — no duplicate traces


def maybe_trace(down_events, storm=False):
    """Kick off background path diagnosis for freshly-down hosts.
    In a storm one representative trace explains the whole event —
    tracing 40 hosts would be its own storm."""
    al = core.cfg("alerts", {}) or {}
    if not al.get("trace_on_down", True):
        return
    for e in (down_events[:1] if storm else down_events):
        h = e["host"]
        if not trace_target(h):
            continue
        with _TRACE_LOCK:
            if h["id"] in _TRACE_BUSY or len(_TRACE_BUSY) >= 3:
                continue
            _TRACE_BUSY.add(h["id"])
        threading.Thread(target=_trace_and_report, args=(h, storm), daemon=True).start()


def _trace_and_report(host, storm):
    try:
        hops = trace_route(trace_target(host))
        if hops:
            storage.db_save_trace(trace_target(host), hops)   # feed the map's router nodes
        text = build_diagnosis(host, hops, neighbour_state(host))
        if not text:
            return
        storage.db_event(host["id"], time.time(), "diag", text)
        name = html.escape(str(host.get("name", "")))
        head = (f"🔎 <b>Диагностика массового падения</b> (трасса до «{name}»)\n"
                if storm else f"🔎 <b>Диагностика</b>: {name}\n")
        alerting.emit("trace", head + html.escape(text), host=host)
    finally:
        with _TRACE_LOCK:
            _TRACE_BUSY.discard(host["id"])


def run_trace_paths():
    """Trace every monitored host once and persist the hop paths, so the map can
    place router nodes between subnets. Opt-in (manual button) — a burst of
    traceroutes is noisy (D14), so it never runs on its own."""
    hosts = [h for h in livestate.enabled_hosts() if trace_target(h)]

    def one(h):
        hops = trace_route(trace_target(h))
        if hops:
            storage.db_save_trace(trace_target(h), hops)
            return 1
        return 0

    done = 0
    if hosts:
        with ThreadPoolExecutor(max_workers=4) as pool:
            done = sum(pool.map(one, hosts))
    return done


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting, livestate  # noqa: E402
