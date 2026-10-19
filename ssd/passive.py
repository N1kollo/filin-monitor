"""Passive ear: SSDP/mDNS announcements between scans."""

import html
import ipaddress
import select
import socket
import time

from . import core, storage, netinventory, dhcp


# ----------------------------------------------------------------------------
# Passive ear — devices shout SSDP and mDNS announcements into the LAN all day
# (routers, printers, NAS, TVs, phones). Listening costs zero packets and gives
# instant new-device detection between scans, plus names the scans can't get.
# ----------------------------------------------------------------------------

PASSIVE = {}            # ip -> {"name","info","proto","ts"} — heard this run


_PASSIVE_ALERTED = set()  # ips already announced (once per process run)


def _sock_multicast(group, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # coexist with the OS's own SSDP/Bonjour
    s.bind(("", port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 socket.inet_aton(group) + socket.inet_aton("0.0.0.0"))
    s.setblocking(False)
    return s


def parse_ssdp(data):
    """SSDP NOTIFY / M-SEARCH response headers -> dict, or None if not SSDP."""
    text = data.decode("utf-8", errors="ignore")
    if not (text.startswith("NOTIFY") or text.startswith("HTTP/")):
        return None
    out = {}
    for line in text.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k in ("server", "usn", "nt", "location") and v.strip():
            out[k] = v.strip()[:120]
    return out or None


def _dns_name(data, off, depth=0):
    """Decode a DNS name honouring compression pointers. Returns (name, next_off)."""
    labels = []
    while True:
        if off >= len(data) or depth > 10:
            return "", off + 1
        length = data[off]
        if length == 0:
            return ".".join(labels), off + 1
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                return "", off + 2
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            tail, _ = _dns_name(data, ptr, depth + 1)
            if tail:
                labels.append(tail)
            return ".".join(labels), off + 2
        labels.append(data[off + 1:off + 1 + length].decode("utf-8", errors="ignore"))
        off += 1 + length


def parse_mdns_names(data):
    """(hostname, ip) pairs from A records anywhere in an mDNS packet."""
    try:
        if len(data) < 12:
            return []
        qd = int.from_bytes(data[4:6], "big")
        total = (int.from_bytes(data[6:8], "big") + int.from_bytes(data[8:10], "big")
                 + int.from_bytes(data[10:12], "big"))
        off = 12
        for _ in range(min(qd, 50)):          # skip questions: name + type + class
            _, off = _dns_name(data, off)
            off += 4
        out = []
        for _ in range(min(total, 50)):
            name, off = _dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype = int.from_bytes(data[off:off + 2], "big")
            rdlen = int.from_bytes(data[off + 8:off + 10], "big")
            off += 10
            if rtype == 1 and rdlen == 4 and name:
                out.append((name.rstrip(".").replace(".local", ""), socket.inet_ntoa(data[off:off + 4])))
            off += rdlen
        return out
    except Exception:
        return []


def is_device_ip(ip):
    """Could this address be a device on the LAN? 10-14 an mDNS record carrying
    0.0.0.0 (a device without an address yet) was announced as «Новое
    устройство в эфире: 0.0.0.0» — the old prefix list missed it."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.version != 4 or a.is_unspecified or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or str(a) == "255.255.255.255")


def _passive_note(ip, name, info, proto):
    """Register something heard in the air: enrich names, alert on never-seen."""
    if not ip or not is_device_ip(ip):
        return
    now = time.time()
    PASSIVE[ip] = {"name": name or "", "info": info or "", "proto": proto, "ts": now}
    services.group_note_seen(ip, now, proto)
    with storage._db_lock:
        row = storage._db.execute("SELECT hostname FROM arp_seen WHERE ip=?", (ip,)).fetchone()
        if row is not None and name and not (row[0] or ""):
            storage._db.execute("UPDATE arp_seen SET hostname=? WHERE ip=?", (name, ip))
            storage._db.commit()
    if row is None and ip not in _PASSIVE_ALERTED:
        # a device the scans have NEVER seen is talking on the LAN — say so now,
        # not at the next scheduled scan
        _PASSIVE_ALERTED.add(ip)
        mac = dhcp.arp_table().get(ip, "")
        vendor = netinventory.lookup_vendor(mac)
        with storage._db_lock:
            storage._db.execute(
                "INSERT OR REPLACE INTO arp_seen (ip, mac, vendor, first_seen, last_seen, present, hostname) "
                "VALUES (?,?,?,?,?,1,?)", (ip, mac, vendor, now, now, name or ""))
            storage._db.commit()
        if not policy.quiet_now():
            who = " — ".join([x for x in (name, vendor or mac, info) if x][:2]) or "неизвестно"
            alerting.emit("netdiff", f"📡 <b>Новое устройство в эфире</b>: <code>{html.escape(ip)}</code> — {html.escape(who)}\n"
                    f"Услышано пассивно ({proto}), в сканах раньше не встречалось.")


def passive_listen_loop():
    time.sleep(10)  # let the web server and config settle first
    socks, built = {}, 0.0
    while True:
        # Multicast membership is tied to the interface it joined on; after a
        # sleep/adapter change the sockets go deaf without any error. Rebuild.
        if socks and time.time() - built > 1800:
            for s_ in socks.values():
                try:
                    s_.close()
                except Exception:
                    pass
            socks = {}
        al = core.cfg("alerts", {}) or {}
        if not al.get("passive_listen", True):
            for s in socks.values():
                try:
                    s.close()
                except Exception:
                    pass
            socks = {}
            time.sleep(30)
            continue
        if not socks:
            for proto, (group, port) in (("SSDP", ("239.255.255.250", 1900)),
                                         ("mDNS", ("224.0.0.251", 5353))):
                try:
                    socks[proto] = _sock_multicast(group, port)
                except Exception as e:
                    print(f"[passive] {proto} не слушается: {core.short_err(e)}")
            if not socks:
                time.sleep(300)
                continue
            built = time.time()
        try:
            readable, _, _ = select.select(list(socks.values()), [], [], 5.0)
        except (OSError, ValueError) as e:
            # a dead socket used to kill the thread: the passive ear went silent for good
            print(f"[passive] сокеты пересоздаются: {core.short_err(e)}")
            for s_ in socks.values():
                try:
                    s_.close()
                except Exception:
                    pass
            socks = {}
            time.sleep(30)
            continue
        for s in readable:
            try:
                data, addr = s.recvfrom(4096)
            except Exception:
                continue
            proto = next((k for k, v in socks.items() if v is s), "?")
            try:
                if proto == "SSDP":
                    h = parse_ssdp(data)
                    if h:
                        _passive_note(addr[0], "", h.get("server", ""), "SSDP")
                else:
                    for nm, a_ip in parse_mdns_names(data):
                        _passive_note(a_ip, nm, "", "mDNS")
            except Exception as e:
                print(f"[passive] {core.short_err(e)}")


# Common ports across mixed device types (Windows, Linux, web, RDP, printers).
# "host" mode needs only an IP: the machine is UP if it answers on ANY of these,
# including a refused/reset (that still means the host is alive, port just closed).
_HOST_PROBE_PORTS = [445, 135, 3389, 22, 80, 443]


def check_host(host, timeout):
    per = min(0.8, max(0.4, timeout))
    last_err = "нет ответа"
    for port in _HOST_PROBE_PORTS:
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=per):
                return True, (time.perf_counter() - t0) * 1000, None
        except ConnectionError:
            # RST/refused/reset — host responded, it's alive
            return True, (time.perf_counter() - t0) * 1000, None
        except (socket.timeout, TimeoutError):
            last_err = "timeout"
        except OSError as e:
            last_err = core.short_err(e)
    return False, None, last_err


def host_target(h):
    t = h.get("type", "ping")
    if t == "http":
        return h.get("url", "")
    if t == "tcp":
        return f"{h.get('host','')}:{h.get('port','')}"
    return h.get("host", "")


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting, policy, services  # noqa: E402
