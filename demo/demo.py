"""Филин on a made-up office — nothing leaves this machine.

    python demo/demo.py            -> http://127.0.0.1:8090

The real monitor runs: its loops, alert logic, services, recovery planner, the
dashboard. Only the lowest layer is simulated — ping / TCP / HTTP / DNS,
Wake-on-LAN, ARP, the subnet sweep and the Dahua recorders — so the demo never
sends a packet to your network. A week of history is seeded, and every five
minutes a Hyper-V host «loses power» and comes back, so there is always
something to look at.

Everything here is fiction: «ООО Ромашка», its addresses and MACs."""
import math
import os
import random
import shutil
import struct
import sys
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "demo", "_run")
PORT = int(os.environ.get("DEMO_PORT", "8090"))

os.makedirs(RUN, exist_ok=True)
os.environ["SSD_APP_DIR"] = RUN                      # config, db, logs live in demo/_run
shutil.copy(os.path.join(ROOT, "dashboard.html"), os.path.join(RUN, "dashboard.html"))
sys.path.insert(0, ROOT)

from ssd import app, core, checks, passive, wanwatch, dhcp, status, video, dahua, unifi  # noqa: E402
from ssd import storage, livestate, services, netinventory  # noqa: E402

random.seed(7)

# ------------------------------------------------------------------ the office
H = lambda hid, name, ip, mac, **kw: dict(id=hid, name=name, host=ip, type="host", mac=mac, **kw)  # noqa: E731
HOSTS = [
    H("gw", "GW-PROXY · шлюз и DHCP", "192.168.10.1", "3c:ec:ef:10:00:01", priority="critical"),
    H("hv1", "HV-01 (Hyper-V)", "192.168.10.21", "3c:ec:ef:10:00:21"),
    H("hv2", "HV-02 (Hyper-V)", "192.168.10.22", "3c:ec:ef:10:00:22"),
    H("acc", "1C-ACC · Бухгалтерия", "192.168.10.31", "00:15:5d:0a:00:31", parent="hv1", priority="critical"),
    H("trd", "1C-TRADE · Торговля", "192.168.10.32", "00:15:5d:0a:00:32", parent="hv2", priority="critical"),
    H("fs", "FILES · файловый сервер", "192.168.10.40", "00:15:5d:0a:00:40", parent="hv2"),
    H("nas", "NAS · бэкапы", "192.168.10.41", "00:11:32:10:00:41"),
    H("pos1", "Касса 1", "192.168.10.71", "70:85:c2:10:00:71", priority="critical"),
    H("pos2", "Касса 2", "192.168.10.72", "70:85:c2:10:00:72", priority="critical"),
    H("prn", "Принтер · бухгалтерия", "192.168.10.60", "a0:8c:fd:10:00:60"),
]
BASE_MS = {"gw": 0.8, "hv1": 0.6, "hv2": 0.7, "acc": 1.4, "trd": 1.6, "fs": 2.2, "nas": 1.1,
           "pos1": 3.5, "pos2": 3.8, "prn": 4.5}
SERVICES = [
    {"id": "acc", "name": "1С Бухгалтерия", "hosts": ["acc"]},
    {"id": "trd", "name": "1С Торговля", "hosts": ["trd"]},
    {"id": "files", "name": "Файлы", "hosts": ["fs"]},
    {"id": "pos", "name": "Кассы", "hosts": ["pos1", "pos2"]},
    {"id": "inet", "name": "Интернет", "wan": True},
    {"id": "wifi", "name": "Wi-Fi", "unifi": True},
    {"id": "cams", "name": "Камеры", "group": {"cidr": "192.168.20.0/24", "min_pct": 90}},
]
NVRS = {"192.168.20.11": ("Склад", 12), "192.168.20.12": ("Торговый зал", 16), "192.168.20.13": ("Парковка", 8)}
CAM_NAMES = ["вход", "касса 1", "касса 2", "зал север", "зал юг", "склад ворота", "склад стеллажи",
             "парковка въезд", "парковка выезд", "двор", "лестница", "офис", "приёмка", "витрина",
             "коридор", "серверная"]

# ------------------------------------------------------------------ scenario
CYCLE = 300          # every 5 min: HV-02 loses power for ~100 s
T0 = time.time()
BOOTING = {}         # ip -> time it comes up (after a magic packet)


def phase(now=None):
    return ((now or time.time()) - T0) % CYCLE


def host_by_ip(ip):
    return next((h for h in HOSTS if h["host"] == ip), None)


def is_up(h, now):
    p = phase(now)
    dark = 70 <= p < 170                       # HV-02 and everything on it
    if h["id"] in ("hv2", "trd", "fs") and dark:
        boot = BOOTING.get(h["host"])
        return bool(boot and now >= boot)
    return True


def latency(h, now):
    base = BASE_MS.get(h["id"], 2.0)
    wave = 1 + 0.35 * math.sin(now / 900 + hash(h["id"]) % 7)
    spike = 6 if h["id"] == "nas" and int(now / 60) % 9 == 0 else 1   # backups chew the NAS
    return round(base * wave * spike * random.uniform(0.85, 1.25), 1)


def sim_ping(host, timeout):
    now = time.time()
    h = host_by_ip(host)
    if h is None:
        if host in CAM_IPS:
            return True, round(random.uniform(0.6, 3), 1), None
        if host.startswith(("8.8.", "1.1.")):
            return True, round(random.uniform(18, 26), 1), None
        return True, 1.0, None
    if not is_up(h, now):
        return False, None, "нет ответа"
    return True, latency(h, now), None


def sim_tcp(host, port, timeout):
    return sim_ping(host, timeout)


def sim_http(url, timeout, expect=None):
    return True, round(random.uniform(40, 90), 1), None


def sim_wol(mac, broadcast=None, port=9):
    h = next((x for x in HOSTS if x["mac"].lower() == (mac or "").lower()), None)
    if h:
        BOOTING[h["host"]] = time.time() + 25            # a server takes a while to boot
        for vm in HOSTS:
            if vm.get("parent") == h["id"]:
                BOOTING[vm["host"]] = time.time() + 45  # VMs autostart with their host
    return True


CAM_IPS = []
CAM_MAC = {}
for n, (ip, (_, count)) in enumerate(NVRS.items()):
    for ch in range(count):
        cip = f"192.168.20.{100 + n * 30 + ch}"
        CAM_IPS.append(cip)
        CAM_MAC[cip] = f"bc:32:5f:20:{n:02x}:{ch:02x}"


def sim_scan(cidr, timeout=1.0):
    if cidr.startswith("192.168.20."):
        alive = list(NVRS) + CAM_IPS
        if int(time.time() / 600) % 3 == 1:             # one camera keeps dropping
            alive.remove(CAM_IPS[7])
        return sorted(alive, key=lambda x: tuple(int(o) for o in x.split(".")))
    return [h["host"] for h in HOSTS if is_up(h, time.time())]


def sim_arp():
    out = {h["host"]: h["mac"] for h in HOSTS}
    out.update(CAM_MAC)
    return out


def sim_nvr_config():
    return ({ip: {"name": name, "user": "demo", "password": "demo", "path": "demo"} for ip, (name, _) in NVRS.items()},
            1.0)


def sim_nvr_probe(ip):
    name, count = NVRS[ip]
    n = list(NVRS).index(ip)
    cams = [{"channel": ch + 1, "name": CAM_NAMES[(ch + n * 5) % len(CAM_NAMES)], "ip": f"192.168.20.{100 + n * 30 + ch}",
             "enabled": True, "state": "", "analog": False} for ch in range(count)]
    return {"ok": True, "model": ["DHI-NVR5216-EI", "DHI-NVR5232-4KS2", "DHI-NVR4108HS"][n], "cameras": cams,
            "disks": [{"Name": "/dev/sda", "State": "Success", "IsError": "false"}]}


# ------------------------------------------------------------------ fake camera frames
FONT = {  # 3x5 digits for the timestamp burned into the picture
    "0": "111101101101111", "1": "010110010010111", "2": "111001111100111", "3": "111001111001111",
    "4": "101101111001001", "5": "111100111001111", "6": "111100111101111", "7": "111001010010010",
    "8": "111101111101111", "9": "111101111001111", "-": "000000111000000", ":": "000010000010000",
    " ": "000000000000000"}


def frame(nvr, ch, w=640, h=360):
    rnd = random.Random(hash((nvr, ch)) & 0xffff)
    hz = rnd.uniform(0.35, 0.55)
    tint = (rnd.randint(70, 110), rnd.randint(75, 115), rnd.randint(80, 120))
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for y in range(h):
        row = bytearray([0])
        horizon = y < h * hz
        for x in range(w):
            if horizon:                                  # wall / sky
                k = 0.55 + 0.35 * y / (h * hz)
                r, g, b = (int(c * k) for c in tint)
            else:                                        # floor with perspective tiles
                d = (y - h * hz) / (h * (1 - hz)) + 0.02
                u = (x - w / 2) / (w * d)
                v = 1 / d
                tile = (int(u * 3) + int(v * 2)) % 2
                k = 0.5 + 0.5 * d
                r, g, b = (int((52 + 18 * tile) * k), int((56 + 18 * tile) * k), int((60 + 18 * tile) * k))
            n = rnd.randint(-6, 6)
            row += bytes((max(0, min(255, r + n)), max(0, min(255, g + n)), max(0, min(255, b + n))))
        rows.append(row)
    sx, sy, sc = w - 4 * 3 * len(stamp) - 12, 12, 3      # timestamp, top right
    for i, chx in enumerate(stamp):
        bits = FONT.get(chx, FONT[" "])
        for py in range(5):
            for px in range(3):
                if bits[py * 3 + px] == "1":
                    for yy in range(sc):
                        for xx in range(sc):
                            X, Y = sx + i * 4 * sc + px * sc + xx, sy + py * sc + yy
                            o = 1 + X * 3
                            rows[Y][o:o + 3] = b"\xee\xee\xee"

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 6)) + chunk(b"IEND", b""))


def sim_snapshot(ip, ch):
    return frame(ip, ch), None


# ------------------------------------------------------------------ history
def seed_history(days=7):
    now = time.time()
    rows = []
    for h in HOSTS:
        t = now - days * 86400
        while t < now - 60:
            rows.append((h["id"], t, 1, latency(h, t), None))
            t += 300
    # last night: HV-02 lost power for 23 minutes
    night = now - (now % 86400) - 86400 + 2 * 3600 + 17 * 60
    with storage._db_lock:
        storage._db.executemany("INSERT INTO checks (host_id, ts, up, latency, error) VALUES (?,?,?,?,?)", rows)
        for hid in ("hv2", "trd", "fs"):
            storage._db.execute("INSERT INTO events (host_id, ts, type, detail, downtime) VALUES (?,?,?,?,?)",
                                (hid, night, "down", "нет ответа", None))
            storage._db.execute("INSERT INTO events (host_id, ts, type, detail, downtime) VALUES (?,?,?,?,?)",
                                (hid, night + 23 * 60, "up", None, 23 * 60))
        storage._db.commit()


def fake_unifi():
    aps = [{"name": n, "ip": f"192.168.10.{150 + i}", "model": "U6-Lite", "online": True, "clients": c,
            "uptime": 86400 * (3 + i), "neighbours": 2 + i, "upgradable": i == 2}
           for i, (n, c) in enumerate([("AP-Зал-1", 14), ("AP-Зал-2", 11), ("AP-Склад", 3), ("AP-Офис", 9)])]
    unifi._UNIFI.update(ok=True, error="", last_poll=time.time(), aps=aps, ssids=["Romashka", "Romashka-Guest"])


# ------------------------------------------------------------------ wire it up
def install():
    checks.check_ping = sim_ping
    checks.check_tcp = sim_tcp
    checks.check_http = sim_http
    checks.send_wol = sim_wol
    passive.check_host = sim_ping
    wanwatch.detect_gateway = lambda: "192.168.10.1"
    wanwatch.check_dns = lambda name, server="", timeout=3.0: (True, round(random.uniform(8, 15), 1), None)
    dhcp.arp_table = sim_arp
    status.scan_subnet = sim_scan
    dahua.nvr_config = sim_nvr_config
    dahua.nvr_probe = sim_nvr_probe
    video.nvr_snapshot = sim_snapshot
    netinventory.scan_ports = lambda ip, timeout=0.5: [p for p in (80, 443, 445, 3389) if host_by_ip(ip)][:2]


def first_run_config():
    if os.path.exists(core.CONFIG_PATH):
        return
    core.load_config()
    c = core.CONFIG
    c.update(app_name="ООО «Ромашка» · Филин", web_host="127.0.0.1", web_port=PORT,
             check_interval_seconds=10, hosts=[dict(h) for h in HOSTS], services=SERVICES)
    c["alerts"].update(passive_listen=False, trace_on_down=False, hold_down_seconds=20)
    c["wan"].update(enabled=True, interval_seconds=20)
    c["groups"] = {"interval_minutes": 1}
    c["telegram"].update(bot_token="", chat_id="")
    # the watchdog pings the demo itself — the real one pings healthchecks.io
    c["heartbeat"].update(enabled=True, url=f"http://127.0.0.1:{PORT}/login", interval_minutes=5)
    core.save_config()


def main():
    install()
    first_run_config()
    core.load_config()
    storage.db_init()
    with storage._db_lock:
        empty = storage._db.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 0
    if empty:
        seed_history()
    fake_unifi()

    def keep_unifi():
        while True:
            fake_unifi()
            time.sleep(30)
    import threading
    threading.Thread(target=keep_unifi, daemon=True).start()
    print(f"demo: http://127.0.0.1:{PORT}  (данные выдуманы, в сеть ничего не уходит)", flush=True)
    app.main()


if __name__ == "__main__":
    main()
