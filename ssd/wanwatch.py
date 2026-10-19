"""WAN watch: gateway, uplink, DNS."""

import html
import os
import socket
import subprocess
import threading
import time

from . import core, storage, checks, pathdiag


# ----------------------------------------------------------------------------
# WAN watch — "the internet is down" is three different problems wearing one
# coat: the gateway died (our LAN), the uplink died (call the ISP), or DNS
# died (everything pings but nothing opens). Probe all three separately so
# the alert names the culprit. History goes into the normal checks table
# under reserved ids -> free charts via the existing series machinery.
# ----------------------------------------------------------------------------

WAN_IDS = {"gw": "_wan_gw", "inet": "_wan_inet", "dns": "_wan_dns"}


WAN_EVENT_NAMES = {"_wan_gw": "🌐 Шлюз", "_wan_inet": "🌐 Интернет-канал", "_wan_dns": "🌐 DNS"}


WAN_STATE = {}   # leg -> {"up": bool|None, "latency": float|None, "fails": int, "since": ts}


_WAN_LOCK = threading.Lock()


def detect_gateway():
    """Default IPv4 gateway from the OS route table. `route print -4` keys on
    numbers only, so any Windows locale parses the same."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        if os.name == "nt":
            proc = subprocess.run(["route", "print", "-4"], capture_output=True,
                                  timeout=10, creationflags=flags)
        else:
            proc = subprocess.run(["ip", "route"], capture_output=True, timeout=10)
        text = checks.console_text(proc.stdout)
        return parse_gateway(text)
    except Exception:
        return ""


def parse_gateway(text):
    for line in text.splitlines():
        parts = line.split()
        # Windows: "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.50  25"
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0" \
                and pathdiag._IP_RE.fullmatch(parts[2]):
            return parts[2]
        # POSIX: "default via 192.168.1.1 dev eth0"
        if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via" \
                and pathdiag._IP_RE.fullmatch(parts[2]):
            return parts[2]
    return ""


def dns_query(name, server, timeout=3.0, q_id=0x5344):
    """Minimal DNS A query over UDP — stdlib only, so we can ask a SPECIFIC
    server (socket.gethostbyname can't) and prove 'the office DNS died'.
    Returns (ok, latency_ms|None, error|None)."""
    try:
        q = q_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for label in name.strip(".").split("."):
            raw = label.encode("idna") if not label.isascii() else label.encode()
            q += bytes([len(raw)]) + raw
        q += b"\x00\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        start = time.perf_counter()
        try:
            s.sendto(q, (server, 53))
            resp, _ = s.recvfrom(512)
        finally:
            s.close()
        latency = (time.perf_counter() - start) * 1000
        if len(resp) < 12 or resp[:2] != q[:2]:
            return False, None, "кривой ответ DNS"
        rcode = resp[3] & 0x0F
        if rcode != 0:
            return False, None, f"DNS rcode {rcode}"
        answers = int.from_bytes(resp[6:8], "big")
        if answers < 1:
            return False, None, "DNS ответил без записей"
        return True, latency, None
    except socket.timeout:
        return False, None, "timeout"
    except Exception as e:
        return False, None, core.short_err(e)


def check_dns(name, server="", timeout=3.0):
    """Specific server -> raw query to it; otherwise the system resolver."""
    if server:
        return dns_query(name, server, timeout)
    start = time.perf_counter()
    try:
        socket.getaddrinfo(name, None, socket.AF_INET)
        return True, (time.perf_counter() - start) * 1000, None
    except Exception as e:
        return False, None, core.short_err(e)


def wan_verdicts(prev, cur):
    """State transitions -> alert texts (plain RU). Pure and known-answer
    testable. prev/cur: {"gw": bool, "inet": bool, "dns": bool} (settled,
    threshold already applied). The blame ladder: no gateway -> nothing behind
    it is a separate problem; gateway ok but no uplink -> ISP; both ok but no
    DNS -> resolver."""
    out = []

    def flipped(leg):
        return prev.get(leg) is not None and prev.get(leg) != cur.get(leg)

    if flipped("gw"):
        if not cur["gw"]:
            out.append("🌐 ЛЁГ ШЛЮЗ — сеть за ним недоступна целиком. "
                       "Это наша железка, провайдер ни при чём.")
        else:
            out.append("🌐 Шлюз снова отвечает.")
    if flipped("inet") and cur.get("gw", True):
        if not cur["inet"]:
            out.append("🌐 ИНТЕРНЕТ УПАЛ: шлюз жив, наружа молчит → проблема у провайдера. "
                       "Локалка работает, можно звонить и ругаться.")
        else:
            out.append("🌐 Интернет вернулся.")
    if flipped("dns") and cur.get("inet", True) and cur.get("gw", True):
        if not cur["dns"]:
            out.append("🌐 СДОХ DNS: пинг наружу ходит, имена не резолвятся. "
                       "«Интернета нет», хотя канал живой.")
        else:
            out.append("🌐 DNS снова резолвит.")
    return out


def wan_cycle(state, wan, threshold=2):
    """One probe round. Mutates `state` (fails/up per leg), records history,
    returns settled {"gw","inet","dns"} booleans (None while still pending)."""
    gw = wan.get("gateway") or detect_gateway()
    timeout = core.cfg("timeout_seconds", 3)
    probes = {
        "gw": (lambda: checks.check_ping(gw, timeout)) if gw else (lambda: (False, None, "шлюз не найден")),
        "inet": lambda: checks.check_ping(wan.get("external") or "8.8.8.8", timeout),
        "dns": lambda: check_dns(wan.get("dns_probe") or "google.com",
                                 (wan.get("dns_server") or "").strip(), timeout),
    }
    settled = {}
    now = time.time()
    for leg, probe in probes.items():
        try:
            up, latency, error = probe()
        except Exception as e:
            up, latency, error = False, None, core.short_err(e)
        st = state.setdefault(leg, {"up": None, "fails": 0, "since": now, "latency": None})
        st["latency"] = round(latency, 1) if latency is not None else None
        st["error"] = error
        storage.db_record(WAN_IDS[leg], now, up, latency, error)
        if up:
            st["fails"] = 0
            if st["up"] is not True:
                st["up"] = True
                st["since"] = now
        else:
            st["fails"] += 1
            if st["fails"] >= threshold and st["up"] is not False:
                st["up"] = False
                st["since"] = now
        settled[leg] = st["up"]
    state["_gateway"] = gw
    return settled


def wan_seed():
    """Starting point for WAN edges: each leg as the event log last saw it,
    assumed up if it never went down. With an empty start, a link already down
    at boot never produced "упал" (no known previous state to flip from), and
    its recovery arrived as "вернулся" out of nowhere."""
    prev, down_since = {}, {}
    for leg, hid in WAN_IDS.items():
        tr = livestate.db_last_transition(hid)
        prev[leg] = not (tr and tr[0] == "down")
        if not prev[leg]:
            down_since[leg] = tr[1]
    return prev, down_since


def wan_loop():
    time.sleep(20)  # let startup settle
    prev, down_since = wan_seed()  # down_since: leg -> ts it settled down
    while True:
        try:
            prev = _wan_step(prev, down_since)
        except Exception as e:
            print(f"[wan] cycle error: {core.short_err(e)}")
            time.sleep(60)


def _wan_step(prev, down_since):
    """One WAN pass; returns the new `prev`. Split out of wan_loop so a raise
    (db locked, disk full) costs one pass, not the thread."""
    wan = core.cfg("wan", {}) or {}
    if not wan.get("enabled", True):
        time.sleep(30)
        return prev
    with _WAN_LOCK:
        cur = wan_cycle(WAN_STATE, wan, core.cfg("fail_threshold", 2))
        errs = {leg: WAN_STATE.get(leg, {}).get("error") for leg in WAN_IDS}
    # a leg still settling (None) keeps its last known state — never a flip
    cur = {leg: (prev.get(leg) if cur.get(leg) is None else cur[leg]) for leg in WAN_IDS}
    # transitions land in the events table -> history UI + morning digest
    now = time.time()
    for leg in WAN_IDS:
        if prev.get(leg) is not None and cur.get(leg) is not None and prev[leg] != cur[leg]:
            if cur[leg]:
                started = down_since.pop(leg, None)
                storage.db_event(WAN_IDS[leg], now, "up", None,
                         (now - started) if started else None)
            else:
                down_since[leg] = now
                storage.db_event(WAN_IDS[leg], now, "down", errs.get(leg))
    # quiet hours hold WAN voice too (it's in the digest); wording is the
    # blame ladder from wan_verdicts
    if not policy.quiet_now():
        for text in wan_verdicts(prev, cur):
            alerting.emit("wan", html.escape(text))
    try:
        interval = max(15, int(wan.get("interval_seconds") or 60))
    except (TypeError, ValueError):
        interval = 60
    time.sleep(interval)
    return cur


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting, livestate, policy  # noqa: E402
