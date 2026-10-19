"""Rogue DHCP watch."""

import ipaddress
import os
import socket
import subprocess
import time

from . import core, checks, netinventory


# ----------------------------------------------------------------------------
# Rogue DHCP watch — somebody plugs a home router into a wall port and half
# the office "strangely stops working". On dumb switches the only way to
# catch it is to ASK: send a DHCPDISCOVER and see who answers. Windows' own
# DHCP client owns UDP :68, so we use the relay trick instead: giaddr = our
# IP, source port 67 -> every server unicasts its OFFER straight back to us.
# Caveat (honest): some devices ignore relayed DISCOVERs; those are caught by
# the network-diff instead (new device with a router vendor).
# ----------------------------------------------------------------------------

_DHCP_COOKIE = b"\x63\x82\x53\x63"


def build_dhcp_discover(xid, mac_bytes, giaddr_ip):
    pkt = bytes([1, 1, 6, 1])                    # op=REQUEST, ethernet, hlen, hops=1 (relay)
    pkt += xid.to_bytes(4, "big")
    pkt += b"\x00\x00" + b"\x00\x00"             # secs, flags (unicast to giaddr)
    pkt += b"\x00" * 12                          # ciaddr, yiaddr, siaddr
    pkt += socket.inet_aton(giaddr_ip)           # giaddr = us, the "relay"
    pkt += mac_bytes + b"\x00" * (16 - len(mac_bytes))
    pkt += b"\x00" * 192                         # sname + file
    pkt += _DHCP_COOKIE
    pkt += b"\x35\x01\x01"                       # option 53: DHCPDISCOVER
    pkt += b"\x37\x02\x01\x03"                   # option 55: want subnet+router
    pkt += b"\xff"
    return pkt


def parse_dhcp_reply(data, xid):
    """OFFER -> {"server", "yiaddr", "type"}; None for anything else."""
    if len(data) < 240 or data[0] != 2:
        return None
    if int.from_bytes(data[4:8], "big") != xid:
        return None
    if data[236:240] != _DHCP_COOKIE:
        return None
    out = {"yiaddr": socket.inet_ntoa(data[16:20]), "server": None, "type": None}
    i = 240
    while i + 1 < len(data):
        opt = data[i]
        if opt == 255:
            break
        if opt == 0:
            i += 1
            continue
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if opt == 53 and ln == 1:
            out["type"] = val[0]
        if opt == 54 and ln == 4:
            out["server"] = socket.inet_ntoa(val)
        i += 2 + ln
    return out


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet actually sent — just picks the route
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


def local_ipv4s():
    """Every LAN IPv4 of this machine. The office PC carries an alias in each of
    five subnets; loopback, link-local and Tailscale (100.64/10) are skipped."""
    out = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        infos = []
    for info in infos:
        ip = info[4][0]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_link_local or a in ipaddress.ip_network("100.64.0.0/10"):
            continue
        if ip not in out:
            out.append(ip)
    primary = local_ip()
    if primary and primary not in out:
        out.insert(0, primary)
    return out


DHCP_LAST = {"ts": 0.0, "tried": [], "found": {}, "error": None, "silent_rounds": 0}


DHCP_BLIND_ROUNDS = 3


def dhcp_probe(wait=3.0):
    """Relay-style discovery from EVERY local address. A Windows DHCP server
    answers a relayed DISCOVER only if it has a scope for giaddr's subnet: from
    the primary 192.168.1.x it heard nothing (10-14), the clients live in
    192.168.100/23. Returns ({server_ip: offered_ip}, error)."""
    mine = local_ipv4s()
    if not mine:
        return {}, "не определить свой IP"
    found, errors = {}, []
    for me in mine:
        f, err = _dhcp_probe_from(me, wait)
        found.update(f)
        if err:
            errors.append(f"{me}: {err}")
    DHCP_LAST.update(ts=time.time(), tried=mine, found=dict(found),
                     error="; ".join(errors) or None)
    if found:
        return found, None
    return {}, ("; ".join(errors) if len(errors) == len(mine) else None)


def _dhcp_probe_from(me, wait):
    xid = int.from_bytes(os.urandom(4), "big")
    mac = b"\x02" + os.urandom(5)  # locally-administered, never a real device
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    found = {}
    try:
        s.bind((me, 67))
        s.settimeout(0.5)
        s.sendto(build_dhcp_discover(xid, mac, me), ("255.255.255.255", 67))
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                continue
            r = parse_dhcp_reply(data, xid)
            if r and r.get("type") == 2:  # OFFER
                found[r.get("server") or addr[0]] = r.get("yiaddr")
    except Exception as e:
        return {}, core.short_err(e)
    finally:
        s.close()
    return found, None


_DHCP_ALERTED = {}  # ip -> ts (rogue), "_missing" -> ts


def evaluate_dhcp(found, expected):
    """Pure verdict: (rogues, missing, learn). learn=True when there is no
    baseline yet — the responders become the trusted set."""
    got = set(found)
    exp = set(expected or [])
    if not exp:
        return [], [], bool(got)
    return sorted(got - exp), sorted(exp - got), False


def dhcp_watch_loop():
    last = 0.0
    while True:
        dw = core.cfg("dhcp_watch", {}) or {}
        try:
            interval = max(5, int(dw.get("interval_minutes") or 30)) * 60
        except (TypeError, ValueError):
            interval = 1800
        if dw.get("enabled") and (time.time() - last) >= interval:
            last = time.time()
            try:
                found, err = dhcp_probe()
                if err:
                    print(f"[dhcp] проба не удалась: {err}")
                # A watch that never hears anyone is not "all clear" — it is blind.
                if found:
                    DHCP_LAST["silent_rounds"] = 0
                else:
                    DHCP_LAST["silent_rounds"] += 1
                    print(f"[dhcp] нет ответов (адреса: {', '.join(DHCP_LAST['tried'])})")
                    if DHCP_LAST["silent_rounds"] == DHCP_BLIND_ROUNDS:
                        exp = dw.get("expected") or []
                        where = ", ".join(f"<code>{ip}</code>" for ip in DHCP_LAST["tried"])
                        if exp:
                            # the "missing" check below needs SOME answer — a dead
                            # sole server used to be exactly as silent as a healthy one
                            alerting.emit("dhcp", "⚠️ DHCP-надзор: штатный сервер "
                                 + ", ".join(f"<code>{ip}</code>" for ip in exp)
                                 + f" не отвечает {DHCP_BLIND_ROUNDS} пробы подряд — "
                                   "новые устройства не получат адреса.")
                        else:
                            alerting.emit("dhcp", "⚠️ DHCP-надзор <b>не слышит ответов</b> — "
                                 f"{DHCP_BLIND_ROUNDS} пробы подряд с адресов {where}. "
                                 "Чужой DHCP-сервер он сейчас не поймает. Подробности — /api/dhcp.")
                if not err:
                    rogues, missing, learn = evaluate_dhcp(found, dw.get("expected"))
                    now = time.time()
                    if learn:
                        with core.CONFIG_LOCK:
                            core.CONFIG.setdefault("dhcp_watch", {})["expected"] = sorted(found)
                            core.save_config()
                        alerting.emit("dhcp", "📋 DHCP-надзор: запомнил штатные серверы — "
                                + ", ".join(f"<code>{ip}</code>" for ip in sorted(found)))
                    for ip in rogues:
                        if now - _DHCP_ALERTED.get(ip, 0) > 3600:
                            _DHCP_ALERTED[ip] = now
                            mac = arp_table().get(ip, "")
                            vend = netinventory.lookup_vendor(mac)
                            who = f" ({vend})" if vend else ""
                            alerting.emit("dhcp", f"🔥 <b>ЛЕВЫЙ DHCP-СЕРВЕР</b>: <code>{ip}</code>{who} "
                                    f"раздаёт адреса (предложил {found.get(ip, '?')}).\n"
                                    f"Классика: кто-то воткнул домашний роутер. Найти по вендору "
                                    f"MAC и выдернуть, пока полофиса не съехало на его адреса.")
                    if missing and found and now - _DHCP_ALERTED.get("_missing", 0) > 3600:
                        _DHCP_ALERTED["_missing"] = now
                        alerting.emit("dhcp", "⚠️ DHCP-надзор: штатный сервер молчит — "
                                + ", ".join(f"<code>{ip}</code>" for ip in missing)
                                + ". Новые устройства не получат адреса.")
            except Exception as e:
                print(f"[dhcp] {core.short_err(e)}")
        time.sleep(30)


def netscan_loop():
    """Scheduled auto-scan: the diff, conflict and new-device machinery work
    without anyone pressing the button. Off by default (D14: sweeps are loud)."""
    last = 0.0
    while True:
        ns = core.cfg("netscan", {}) or {}
        try:
            interval = max(5, int(ns.get("interval_minutes") or 60)) * 60
        except (TypeError, ValueError):
            interval = 3600
        if ns.get("enabled") and (time.time() - last) >= interval:
            last = time.time()
            try:
                res = netinventory.run_network_scan()
                if res:
                    netinventory.alert_network_changes(res["appeared"], res["changed"])
                    print(f"[netscan] авто-скан: живых {res['alive']}, "
                          f"+{len(res['appeared'])} -{len(res['disappeared'])} "
                          f"~{len(res['changed'])}")
            except Exception as e:
                print(f"[netscan] {core.short_err(e)}")
        time.sleep(30)


def _safe_probe(host):
    """One bad device must not kill a whole inventory sweep."""
    try:
        return netinventory.inventory_probe(host)
    except Exception as e:
        print(f"[inventory] {host.get('name')}: {core.short_err(e)}")
        return None


def arp_table():
    """IP -> MAC from the OS ARP cache (populated by the ping sweep just run)."""
    out = {}
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.run(["arp", "-a"], capture_output=True, timeout=10, creationflags=flags)
        text = checks.console_text(proc.stdout)
        for rx in (checks._ARP_WIN, checks._ARP_NIX):
            for ip, mac in rx.findall(text):
                out[ip] = mac.replace("-", ":").lower()
    except Exception as e:
        print(f"[arp] {core.short_err(e)}")
    return out


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting  # noqa: E402
