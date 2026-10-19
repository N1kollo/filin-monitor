"""Device inventory: OUI vendors, open ports, hostnames, ARP."""

import html
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import core, storage, checks


# ----------------------------------------------------------------------------
# Inventory — turn a soup of IPs into "HP LaserJet · PRINTER-3F · :80,:9100"
# ----------------------------------------------------------------------------

_OUI = {}          # first 3 MAC bytes -> vendor, loaded once from oui.txt


_OUI_LOADED = False


# Ports worth knowing about: identity (what is this box?) more than liveness.
INVENTORY_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (135, "rpc"), (139, "netbios"), (443, "https"), (445, "smb"),
    (1433, "mssql"), (1540, "1c"), (3306, "mysql"), (3389, "rdp"),
    (5432, "postgres"), (5900, "vnc"), (8080, "http-alt"), (9100, "printer"),
]


def load_oui():
    """IEEE OUI registry (via Wireshark's curated 'manuf'), bundled offline."""
    global _OUI_LOADED
    if _OUI_LOADED:
        return
    _OUI_LOADED = True
    path = core.resource_path("oui.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                prefix, _, name = line.partition("\t")
                if name:
                    _OUI[prefix.strip()] = name.strip()
        print(f"[oui] загружено записей: {len(_OUI)}")
    except Exception as e:
        print(f"[oui] база не загружена ({core.short_err(e)}) — вендоры показываться не будут")


def lookup_vendor(mac):
    if not mac:
        return ""
    load_oui()
    key = re.sub(r"[^0-9a-fA-F]", "", mac).lower()[:6]
    return _OUI.get(key, "")


def resolve_hostname(ip):
    """Reverse DNS first; on Windows fall back to the NetBIOS name."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["nbtstat", "-A", ip], capture_output=True, timeout=6,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            text = proc.stdout.decode("cp866", errors="ignore")
            for line in text.split("\n"):
                # "  NAME           <00>  UNIQUE      Registered"
                m = re.match(r"\s+(\S+)\s+<00>\s+UNIQUE", line)
                if m:
                    return m.group(1)
        except Exception:
            pass
    return ""


def scan_ports(ip, timeout=0.5):
    open_ports = []
    lock = threading.Lock()

    def probe(item):
        port, label = item
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                with lock:
                    open_ports.append({"port": port, "label": label})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=len(INVENTORY_PORTS)) as pool:
        list(pool.map(probe, INVENTORY_PORTS))
    return sorted(open_ports, key=lambda p: p["port"])


def inventory_probe(host):
    """Identify one device. Returns a dict ready for the inventory table."""
    ip = host.get("host", "")
    mac = host.get("mac", "")
    if not mac:
        mac = dhcp.arp_table().get(ip, "")
    if ip and ip not in checks._TTL_SEEN:
        checks.check_ping(ip, 1)  # one echo just to harvest the TTL for the OS guess
    return {
        "host_id": host["id"],
        "mac": mac,
        "vendor": lookup_vendor(mac),
        "hostname": resolve_hostname(ip) if ip else "",
        "os": checks.os_from_ttl(checks._TTL_SEEN.get(ip)),
        "ports": scan_ports(ip) if ip else [],
        "updated": time.time(),
    }


def mac_is_random(mac):
    """Locally administered MAC (bit 1 of the first octet): phones' and laptops'
    Wi-Fi privacy addresses. Not a hardware identity — it rotates by design."""
    try:
        return bool(int((mac or "").replace("-", ":").split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def mac_change_verdict(change, alive_map, monitored_ips):
    """Is a new MAC on a known IP worth "possible spoofing"? On a DHCP LAN (a
    mall office) an IP passing from a phone that left to the PC that arrived
    is routine — and rang 🚨 every time. ARP spoofing has a tell a reassignment
    doesn't: the new MAC ALSO answers for some other IP (it's still sitting on
    its own address while claiming yours). A monitored host's IP always rings —
    those are the addresses that matter.
    Returns "spoof", "monitored" (both alert) or "reassigned", "random" (quiet)."""
    ip, new = change["ip"], (change.get("mac") or "").lower()
    if ip in monitored_ips:
        return "monitored"
    others = [i for i, m in alive_map.items() if i != ip and (m or "").lower() == new]
    if others:
        return "spoof"
    if mac_is_random(new) or mac_is_random(change.get("old_mac")):
        return "random"
    return "reassigned"


def network_diff(alive_map):
    """Compare a fresh {ip: mac} scan against the stored snapshot.
    Returns (appeared, disappeared, changed). A changed MAC on the same IP is
    a red flag: device swapped, or ARP spoofing."""
    now = time.time()
    with storage._db_lock:
        rows = storage._db.execute("SELECT ip, mac, vendor, first_seen, present FROM arp_seen").fetchall()
    prev = {r[0]: {"mac": r[1], "vendor": r[2], "first": r[3], "present": r[4]} for r in rows}

    appeared, changed = [], []
    for ip, mac in alive_map.items():
        vendor = lookup_vendor(mac)
        if ip not in prev:
            appeared.append({"ip": ip, "mac": mac, "vendor": vendor, "is_new": True})
        elif not prev[ip]["present"]:
            # known device that was absent and is back — a change since last scan,
            # but not alert-worthy the way a never-seen device is
            appeared.append({"ip": ip, "mac": mac, "vendor": vendor, "is_new": False})
        elif mac and prev[ip]["mac"] and mac.lower() != prev[ip]["mac"].lower():
            changed.append({"ip": ip, "old_mac": prev[ip]["mac"],
                            "old_vendor": prev[ip]["vendor"], "mac": mac, "vendor": vendor})
    monitored = {h.get("host") for h in livestate.enabled_hosts() if h.get("host")}
    for c in changed:
        c["verdict"] = mac_change_verdict(c, alive_map, monitored)
    # disappeared: present LAST scan, gone THIS scan (reported once, not forever)
    disappeared = [{"ip": ip, "mac": v["mac"], "vendor": v["vendor"]}
                   for ip, v in prev.items() if ip not in alive_map and v["present"]]

    with storage._db_lock:
        for ip, mac in alive_map.items():
            vendor = lookup_vendor(mac)
            first = prev[ip]["first"] if ip in prev else now
            storage._db.execute(
                "INSERT OR REPLACE INTO arp_seen (ip, mac, vendor, first_seen, last_seen, present) "
                "VALUES (?,?,?,?,?,1)", (ip, mac, vendor, first, now))
        # anything not alive this scan is now marked absent
        gone = [ip for ip in prev if ip not in alive_map]
        for ip in gone:
            storage._db.execute("UPDATE arp_seen SET present=0 WHERE ip=?", (ip,))
        storage._db.commit()
    return appeared, disappeared, changed


def enrich_hostnames(ips):
    """Resolve device names for scan results (reverse DNS -> NetBIOS) and
    remember them in arp_seen. Only unnamed IPs are queried — nbtstat waits
    ~6s per silent device, so re-resolving the whole LAN every scan would be
    slow for nothing. Returns {ip: hostname} for everything known."""
    with storage._db_lock:
        rows = storage._db.execute("SELECT ip, hostname FROM arp_seen").fetchall()
    known = {r[0]: (r[1] or "") for r in rows}
    todo = [ip for ip in ips if not known.get(ip)]
    if todo:
        with ThreadPoolExecutor(max_workers=16) as pool:
            for ip, name in zip(todo, pool.map(resolve_hostname, todo)):
                if name:
                    known[ip] = name
                    with storage._db_lock:
                        storage._db.execute("UPDATE arp_seen SET hostname=? WHERE ip=?", (name, ip))
                        storage._db.commit()
    return known


def run_network_scan(cidrs=None):
    """Sweep subnets, harvest MACs, diff against the snapshot, resolve names.
    Shared by the dashboard button and the scheduled auto-scan."""
    if cidrs is None:
        with core.CONFIG_LOCK:
            cidrs = [s["cidr"] for s in core.CONFIG.get("subnets", [])]
    if not cidrs:
        return None
    alive_map = {}
    timeout = core.cfg("timeout_seconds", 3)
    for c in cidrs:
        try:
            for ip in status.scan_subnet(c, timeout=timeout):
                alive_map[ip] = ""
        except Exception as e:
            print(f"[netscan] {c}: {core.short_err(e)}")
    arp = dhcp.arp_table()
    for ip in list(alive_map):
        alive_map[ip] = arp.get(ip, "")
    appeared, disappeared, changed = network_diff(alive_map)
    names = enrich_hostnames(list(alive_map))
    for lst in (appeared, disappeared, changed):
        for row in lst:
            row["hostname"] = names.get(row["ip"], "")
    return {"alive": len(alive_map), "appeared": appeared,
            "disappeared": disappeared, "changed": changed}


def _dev_label(row):
    """'Xiaomi (REDMI-NOTE)' / 'REDMI-NOTE' / 'aa:bb:...' — best name we have."""
    vendor, name = row.get("vendor") or "", row.get("hostname") or ""
    if vendor and name:
        return f"{vendor} ({name})"
    return vendor or name or row.get("mac") or "неизвестно"


def alert_network_changes(appeared, changed):
    """Telegram side of a scan. MAC-change (possible spoofing) always rings;
    new devices respect quiet hours — they're visible in the UI anyway."""
    appeared = [a for a in appeared if a.get("is_new")]
    now = time.time()
    # an IP already flagged as a conflict is bouncing by definition — its
    # repeated "MAC changed" alerts are symptoms, the 🔥 alert covers them
    changed = [c for c in changed if now - ipconflict._CONFLICT_ALERTED.get(c["ip"], 0) > 3600]
    # DHCP reassignments and privacy MACs stay in the scan diff (UI), not the phone
    changed = [c for c in changed if c.get("verdict", "spoof") in ("spoof", "monitored")]
    if not telegram.telegram_ready():
        return
    if changed:
        lines = ["🚨 <b>СМЕНА MAC НА ТОМ ЖЕ IP</b> — возможна подмена устройства или ARP-спуфинг", ""]
        for c in changed[:10]:
            why = (" — <b>этот MAC отвечает и за другой адрес</b>" if c.get("verdict") == "spoof"
                   else " — адрес хоста из мониторинга")
            lines.append(f"⚠️ <code>{c['ip']}</code>: было "
                         f"{html.escape(c['old_vendor'] or c['old_mac'])} → стало "
                         f"{html.escape(_dev_label(c))}{why}")
        alerting.emit("netdiff", "\n".join(lines))
    if appeared and not policy.quiet_now():
        lines = [f"📶 <b>Новые устройства в сети</b>: {len(appeared)}", ""]
        for a in appeared[:15]:
            lines.append(f"➕ <code>{a['ip']}</code> — {html.escape(_dev_label(a))}")
        if len(appeared) > 15:
            lines.append(f"… и ещё {len(appeared) - 15}")
        alerting.emit("netdiff", "\n".join(lines))


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import dhcp, ipconflict, telegram, alerting, livestate, policy, status  # noqa: E402
