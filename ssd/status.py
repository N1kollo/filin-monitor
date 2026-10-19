"""Subnet scan, topology, status summary."""

import html
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import core, webauth, storage, checks, passive, services, wanwatch, telegram, alerting, livestate, degradation, policy


# ----------------------------------------------------------------------------
# Subnet scan
# ----------------------------------------------------------------------------


def scan_subnet(cidr, timeout=1.0):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
    hosts = hosts[:1024]  # safety cap
    alive = []
    lock = threading.Lock()

    def probe(ip):
        up, _lat, _err = checks.check_ping(str(ip), timeout)
        if up:
            with lock:
                alive.append(str(ip))

    with ThreadPoolExecutor(max_workers=80) as pool:
        list(pool.map(probe, hosts))
    return sorted(alive, key=lambda x: tuple(int(o) for o in x.split(".")))


# ----------------------------------------------------------------------------
# Web app
# ----------------------------------------------------------------------------


def _net24(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$", (ip or "").strip())
    return "{}.{}.{}.0/24".format(m.group(1), m.group(2), m.group(3)) if m else None


def os_kind(label):
    return {"Windows": "win", "Linux/Unix": "linux",
            "сетевое устройство": "gear"}.get(label or "", "unknown")


def _ip_sort_key(ip):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)", ip or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0, 0)


def build_topology(hosts, states, degraded_ids, inventory, arp_devices, ttl_map, gateway, switches=None, trace_paths=None):
    """Pure: assemble the network map as {gateway, nodes, edges}.

    Deterministic (sorted output) so it is known-answer testable — it touches no
    live STATE, DB or clock; callers pass snapshots in.
      hosts        : enabled host dicts (id, name, host, type, parent, mac...)
      states       : {host_id: {"status": "up|down|pending"}}
      degraded_ids : host_ids currently flagged slow -> rendered as "warn"
      inventory    : {host_id: {"os","vendor","hostname",...}}
      arp_devices  : {"ip","mac","vendor","present","hostname"} — ARP-only finds
      ttl_map      : {ip: ttl} to guess OS when inventory has none
      gateway      : gateway IPv4 (tree root), may be ""
    Node ids: "gw" (root) | "net:<cidr>" (subnet hub) | "host:<id>" (monitored)
    | "ip:<addr>" (ARP-only) | "sw:<id>" (manual dumb-switch marker). Edges are
    [parent_id, child_id]. `switches` are user-placed annotation nodes with no IP
    (dumb L2 switches are invisible to L3 — see decisions): [{id, name, parent}].
    """
    switches = switches or []
    trace_paths = trace_paths or {}  # {ip: [hop_ip_or_None, ...]} from persisted traces
    devices = {}  # dedup key (ip, or node id when no IP) -> node

    for h in hosts:
        hid = h.get("id")
        ip = (h.get("host") or "").strip()
        st = (states.get(hid) or {}).get("status", "pending")
        if st == "up" and hid in degraded_ids:
            st = "warn"
        inv = inventory.get(hid, {})
        node = {
            "id": "host:" + str(hid),
            "kind": "device",
            "monitored": True,
            "host_id": hid,
            "ip": ip,
            "name": h.get("name") or ip or str(hid),
            "status": st,
            "present": st != "down",
            "os": os_kind(inv.get("os") or checks.os_from_ttl(ttl_map.get(ip))),
            "vendor": inv.get("vendor") or h.get("mac", ""),
            "hostname": inv.get("hostname", ""),
            "role": h.get("role", ""),
            "_parent": (h.get("parent") or "").strip(),
        }
        devices[ip or node["id"]] = node

    for d in arp_devices:
        ip = (d.get("ip") or "").strip()
        if not ip or ip in devices:
            continue  # a monitored host on this IP wins the node
        devices[ip] = {
            "id": "ip:" + ip,
            "kind": "device",
            "monitored": False,
            "host_id": None,
            "ip": ip,
            "name": d.get("hostname") or ip,
            "status": "arp",
            "present": bool(d.get("present")),
            "os": os_kind(checks.os_from_ttl(ttl_map.get(ip))),
            "vendor": d.get("vendor") or d.get("mac", ""),
            "hostname": d.get("hostname") or "",
            "_parent": "",
        }

    gw_node = {"id": "gw", "kind": "gateway", "ip": gateway or "",
               "name": "шлюз", "status": "up", "monitored": False,
               "host_id": None, "os": "gw"}
    if gateway and gateway in devices:
        dv = devices.pop(gateway)  # the gateway is the root, not a leaf
        gw_node["host_id"] = dv["host_id"]
        gw_node["monitored"] = dv["monitored"]
        gw_node["status"] = dv["status"]
        gw_node["name"] = "шлюз · " + dv["name"]
        gw_node["vendor"] = dv.get("vendor", "")

    subnets = {}
    for node in devices.values():
        cidr = _net24(node["ip"])
        node["_cidr"] = cidr
        if cidr and cidr not in subnets:
            subnets[cidr] = {"id": "net:" + cidr, "kind": "subnet",
                             "label": cidr, "cidr": cidr}

    sw_nodes = {}
    for s in switches:
        sid = s.get("id")
        if not sid:
            continue
        sw_nodes[sid] = {
            "id": "sw:" + str(sid), "kind": "switch",
            "name": s.get("name") or "свитч", "ip": "",
            "monitored": False, "host_id": None,
            "_parent": (s.get("parent") or "").strip(),
        }
    switch_ids = set(n["id"] for n in sw_nodes.values())
    device_ids = set(n["id"] for n in devices.values())
    gw_hid = gw_node.get("host_id")

    def _resolve_parent(ph, self_id):
        # explicit parent wins: gateway host, another monitored device, or a switch
        if ph:
            if gw_hid and ph == gw_hid:
                return "gw"
            if ("host:" + ph) in device_ids and ("host:" + ph) != self_id:
                return "host:" + ph
            if ("sw:" + ph) in switch_ids and ("sw:" + ph) != self_id:
                return "sw:" + ph
        return None

    routers = {}      # ip -> router node (deduped across subnets)
    sub_chain = {}    # cidr -> [router ip, ...] gateway-side first
    for cidr in subnets:
        rep_path = rep_ip = None
        for node in devices.values():
            if node.get("_cidr") == cidr and node["ip"] in trace_paths:
                rep_path, rep_ip = trace_paths[node["ip"]], node["ip"]
                break
        if not rep_path:
            continue
        chain = []
        for h in rep_path:            # keep transit + subnet-gateway routers only
            if not h or h == gateway or h == rep_ip or h in chain:
                continue
            chain.append(h)
        if chain:
            sub_chain[cidr] = chain
            for ip in chain:
                if ip not in routers:
                    routers[ip] = {"id": "rt:" + ip, "kind": "router", "ip": ip,
                                   "name": ip, "monitored": False, "host_id": None}

    edges = []
    for cidr in subnets:              # gw -> [routers from the trace] -> /24 hub
        prev = "gw"
        for ip in sub_chain.get(cidr, []):
            edges.append([prev, "rt:" + ip])
            prev = "rt:" + ip
        edges.append([prev, "net:" + cidr])
    for node in devices.values():
        tgt = _resolve_parent(node.get("_parent"), node["id"])
        if tgt is None:  # no explicit parent -> its own /24, else the gateway
            tgt = ("net:" + node["_cidr"]) if node.get("_cidr") else "gw"
        edges.append([tgt, node["id"]])
    for sw in sw_nodes.values():
        # a switch has no IP -> no /24; unparented ones hang off the gateway
        edges.append([_resolve_parent(sw.get("_parent"), sw["id"]) or "gw", sw["id"]])

    dev_list = sorted(devices.values(), key=lambda n: _ip_sort_key(n["ip"]))
    for n in dev_list:
        n.pop("_parent", None)
        n.pop("_cidr", None)
    sw_list = sorted(sw_nodes.values(), key=lambda n: n["name"].lower())
    for n in sw_list:
        n.pop("_parent", None)
    hub_list = sorted(subnets.values(), key=lambda n: _ip_sort_key(n["cidr"]))
    rt_list = sorted(routers.values(), key=lambda n: _ip_sort_key(n["ip"]))
    edges = [list(t) for t in sorted(set(tuple(e) for e in edges))]  # dedup shared router edges
    return {"gateway": gateway or "",
            "nodes": [gw_node] + rt_list + hub_list + sw_list + dev_list,
            "edges": edges}


def topology_snapshot():
    """Gather live snapshots under locks, then hand off to the pure builder."""
    hosts = livestate.enabled_hosts()
    with livestate.STATE_LOCK:
        states = {k: {"status": v.get("status", "pending")}
                  for k, v in livestate.STATE.items()}
    degraded_ids = set(degradation.DEGRADED.keys())
    inventory = storage.db_inventory_all()
    with storage._db_lock:
        rows = storage._db.execute(
            "SELECT ip, mac, vendor, present, hostname FROM arp_seen").fetchall()
    arp = [{"ip": r[0], "mac": r[1], "vendor": r[2],
            "present": bool(r[3]), "hostname": r[4]} for r in rows]
    with wanwatch._WAN_LOCK:
        gw = wanwatch.WAN_STATE.get("_gateway", "")
    if not gw:
        gw = (core.cfg("wan", {}) or {}).get("gateway", "") or wanwatch.detect_gateway()
    t = build_topology(hosts, states, degraded_ids, inventory, arp,
                       dict(checks._TTL_SEEN), gw, core.cfg("switches", []), storage.db_trace_paths())
    # Manual node placements, if the operator arranged the map by hand. Auto-layout
    # fills in everything that is not pinned.
    t["layout"] = core.cfg("map_layout", {}) or {}
    return t


def build_status():
    with livestate.STATE_LOCK:
        snap = {k: dict(v) for k, v in livestate.STATE.items()}
    hosts_cfg = {h["id"]: h for h in core.cfg("hosts", [])}
    servers = []
    for hid, st in snap.items():
        h = hosts_cfg.get(hid, {})
        hist = storage.db_history(hid, 40)
        deg = degradation.DEGRADED.get(hid)
        servers.append({
            "id": hid,
            "degraded": bool(deg),
            "deg_ratio": round(deg["ratio"], 1) if deg else None,
            "deg_base": round(deg["base"], 1) if deg else None,
            "name": h.get("name", hid),
            "type": h.get("type", "ping"),
            "role": h.get("role", ""),
            "target": passive.host_target(h),
            "source": h.get("source", "manual"),
            "mac": h.get("mac", ""),
            "status": st["status"],
            "latency": st["latency"],
            "error": st["error"],
            "uptime_24h": storage.db_uptime(hid, 24),
            "since_human": alerting.fmt_duration(time.time() - st["since"]),
            "spark": [{"up": bool(u), "latency": lat} for (_t, u, lat) in hist],
        })
    servers.sort(key=lambda s: (s["status"] != "down", s["name"].lower()))
    up = sum(1 for s in servers if s["status"] == "up")
    down = sum(1 for s in servers if s["status"] == "down")
    pending = sum(1 for s in servers if s["status"] == "pending")
    degraded = sum(1 for s in servers if s["degraded"])
    with wanwatch._WAN_LOCK:
        wan = {leg: {"up": wanwatch.WAN_STATE.get(leg, {}).get("up"),
                     "latency": wanwatch.WAN_STATE.get(leg, {}).get("latency"),
                     "error": wanwatch.WAN_STATE.get(leg, {}).get("error")}
               for leg in ("gw", "inet", "dns")}
        wan["gateway"] = wanwatch.WAN_STATE.get("_gateway", "")
    wan["enabled"] = bool((core.cfg("wan", {}) or {}).get("enabled", True))
    hb_cfg = core.cfg("heartbeat", {}) or {}
    heartbeat = {
        "enabled": bool(hb_cfg.get("enabled")),
        "configured": bool((hb_cfg.get("url") or "").strip()),
        "last_ok_state": degradation.HEARTBEAT_STATE["ok"],
        "last_ok_ago": (alerting.fmt_duration(time.time() - degradation.HEARTBEAT_STATE["last_ok"])
                        if degradation.HEARTBEAT_STATE["last_ok"] else None),
    }
    return {
        "app_name": core.cfg("app_name", "Филин"),
        "version": core.__version__,
        "telegram": telegram.telegram_ready(),
        "auth": webauth.auth_enabled(),
        "interval": core.cfg("check_interval_seconds", 30),
        "generated": time.time(),
        "last_cycle": degradation.LAST_CYCLE["ts"],
        "summary": {"up": up, "down": down, "pending": pending,
                    "degraded": degraded, "total": len(servers)},
        "wan": wan,
        "heartbeat": heartbeat,
        # what the owl in the header shows besides up/down: asleep in quiet
        # hours, amber while the whole network is in maintenance
        "mood": {"quiet": bool(policy.quiet_now()), "maint": bool(policy.maint_until("*"))},
        "servers": servers,
    }


def public_config():
    with core.CONFIG_LOCK:
        tg = core.CONFIG.get("telegram", {})
        return {
            "app_name": core.CONFIG.get("app_name"),
            "check_interval_seconds": core.CONFIG.get("check_interval_seconds"),
            "timeout_seconds": core.CONFIG.get("timeout_seconds"),
            "fail_threshold": core.CONFIG.get("fail_threshold"),
            "hosts": [dict(h) for h in core.CONFIG.get("hosts", [])],
            "subnets": [dict(s) for s in core.CONFIG.get("subnets", [])],
            "switches": [dict(s) for s in core.CONFIG.get("switches", [])],
            "telegram": {
                "has_token": bool(tg.get("bot_token")),
                "chat_id": tg.get("chat_id", ""),
                "ready": telegram.telegram_ready(),
                "poll_updates": tg.get("poll_updates", True),
                "site_prefix": bool(tg.get("site_prefix")),
            },
            "alerts": dict(core.CONFIG.get("alerts", {})),
            "degradation": dict(core.CONFIG.get("degradation", {})),
            "runbook": dict(core.CONFIG.get("runbook", {})),
            "wol_schedule": [dict(r) for r in core.CONFIG.get("wol_schedule", [])],
            "api": {"has_token": bool((core.CONFIG.get("api", {}) or {}).get("token"))},
            # Never the hash or the salt — only whether the gate is up and as whom.
            "auth": {"enabled": webauth.auth_enabled(),
                     "username": (core.CONFIG.get("auth", {}) or {}).get("username", "")},
            "wan": dict(core.CONFIG.get("wan", {})),
            "quiet": dict(core.CONFIG.get("quiet", {})),
            "netscan": dict(core.CONFIG.get("netscan", {})),
            "maintenance": [dict(w) for w in core.CONFIG.get("maintenance", [])],
            "dhcp_watch": dict(core.CONFIG.get("dhcp_watch", {})),
            "heartbeat": dict(core.CONFIG.get("heartbeat", {}), **{
                "last_ok_ago": (alerting.fmt_duration(time.time() - degradation.HEARTBEAT_STATE["last_ok"])
                                if degradation.HEARTBEAT_STATE["last_ok"] else None),
                "last_ok_state": degradation.HEARTBEAT_STATE["ok"],
                "last_detail": degradation.HEARTBEAT_STATE["detail"],
            }),
        }


def format_status_message(down_only=False):
    st = build_status()
    s = st["summary"]
    head = f"📡 <b>{html.escape(st['app_name'])}</b>"
    counts = f"🟢 в строю: {s['up']}   🔴 упало: {s['down']}"
    if s["pending"]:
        counts += f"   🟡 ждём: {s['pending']}"
    if s.get("degraded"):
        counts += f"\n🐢 деградация: {s['degraded']}"
    w = st.get("wan") or {}
    if w.get("enabled"):
        parts = []
        for leg, label in (("inet", "интернет"), ("gw", "шлюз"), ("dns", "DNS")):
            leg_st = w.get(leg) or {}
            if leg_st.get("up") is None:
                continue
            lat = f" {round(leg_st['latency'])}мс" if leg_st.get("latency") is not None else ""
            parts.append(f"{'✅' if leg_st['up'] else '❌'} {label}{lat}")
        if parts:
            counts += "\n🌐 " + " · ".join(parts)
    svcs = services.services_view()
    if svcs:
        mark = {"ok": "✅", "warn": "🟡", "down": "🔴", "unknown": "⚪"}
        counts += "\n" + " · ".join(f"{mark[x['status']]} {html.escape(x['name'])}" for x in svcs)
    lines = [head, counts, ""]
    servers = st["servers"]
    if down_only:
        servers = [x for x in servers if x["status"] == "down"]
        if not servers:
            return f"{head}\n{counts}\n\n✅ Упавших нет — всё в строю."
    shown = 0
    for x in servers:
        ic = "🔴" if x["status"] == "down" else ("🐢" if x.get("degraded") else
                                                ("🟢" if x["status"] == "up" else "🟡"))
        if x["latency"] is not None:
            extra = f"{x['latency']} мс"
            if x.get("degraded"):
                extra += f" (×{x['deg_ratio']} к норме)"
        else:
            extra = html.escape(x["error"] or "")
        lines.append(f"{ic} <b>{html.escape(x['name'])}</b> — <code>{html.escape(x['target'])}</code>  {extra}")
        shown += 1
        if shown >= 40:
            lines.append(f"… и ещё {len(servers) - shown}")
            break
    if not st["servers"]:
        lines.append("Целей нет — добавь в веб-настройках.")
    return "\n".join(lines)
