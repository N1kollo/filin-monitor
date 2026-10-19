"""Paths, logging, config — what every other module stands on."""

import json
import logging.handlers
import os
import shutil
import sys
import threading


__version__ = "0.58.1"


# ----------------------------------------------------------------------------
# Paths — work whether run as a .py or bundled into a PyInstaller .exe
# ----------------------------------------------------------------------------


def app_dir() -> str:
    # the update helper runs from backup\ but works on the real install
    if os.environ.get("SSD_APP_DIR"):
        return os.environ["SSD_APP_DIR"]
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # source run: next to monitor.py, one level above this package
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------------
# Logging. The service runs as SYSTEM with no console, so stdout went nowhere:
# every "[wifi] eval error" and dead-thread traceback vanished. print() stays the
# idiom in the code; setup_logging() routes stdout/stderr into a rotating file.
# ----------------------------------------------------------------------------

LOG_DIR = os.path.join(app_dir(), "logs")


class _LogStream:
    """File-like stdout/stderr replacement: whole lines -> logger, console kept."""

    def __init__(self, logger, level, console):
        self.logger, self.level, self.console = logger, level, console
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, s):
        if self.console is not None:
            try:
                self.console.write(s)
            except Exception:
                pass
        with self._lock:
            self._buf += s
            *lines, self._buf = self._buf.split("\n")
        for line in lines:
            if line.strip():
                self.logger.log(self.level, line.rstrip())
        return len(s)

    def flush(self):
        if self.console is not None:
            try:
                self.console.flush()
            except Exception:
                pass


def setup_logging(path=None, max_bytes=1_000_000, backups=5):
    path = path or os.path.join(LOG_DIR, "monitor.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    log = logging.getLogger("ssd")
    log.setLevel(logging.INFO)
    log.propagate = False
    h = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes,
                                             backupCount=backups, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.handlers[:] = [h]
    sys.stdout = _LogStream(log, logging.INFO, sys.__stdout__)
    sys.stderr = _LogStream(log, logging.ERROR, sys.__stderr__)

    # A thread that dies used to die silently — the WAN loop could stop alerting
    # forever with nothing anywhere saying so.
    def _thread_hook(args):
        log.error("поток %s умер", getattr(args.thread, "name", "?"),
                  exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
    threading.excepthook = _thread_hook
    return log


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base and os.path.exists(os.path.join(base, name)):
        return os.path.join(base, name)
    return os.path.join(app_dir(), name)


CONFIG_PATH = os.path.join(app_dir(), "config.json")


DB_PATH = os.path.join(app_dir(), "monitor.db")


DEFAULT_CONFIG = {
    "app_name": "Филин",
    "check_interval_seconds": 30,
    "timeout_seconds": 3,
    "fail_threshold": 2,
    "web_host": "0.0.0.0",
    "web_port": 8081,
    "history_retention_hours": 168,
    # poll_updates: only ONE instance may long-poll getUpdates (Telegram 409s a
    # second poller) — the secondary site sets this false and only sends alerts.
    # site_prefix: prefix broadcast alerts with [app_name] so two sites sharing one
    # chat stay legible. Both off/true = single-site default.
    "telegram": {"bot_token": "", "chat_id": "", "poll_updates": True, "site_prefix": False},
    # session_epoch: sessions minted before this unix ts are dead. Bumped on
    # password change and on "выйти на всех устройствах".
    "auth": {"enabled": False, "username": "", "password_hash": "", "salt": "",
             "secret": "", "session_epoch": 0},
    # REST API token: lets scripts hit /api/* with "Authorization: Bearer <token>"
    # when the password gate is on. Empty = no token access. See API.md.
    "api": {"token": ""},
    # Dead man's switch: who watches the watchman. If this monitor dies, the
    # pings stop and the external service alerts you.
    "heartbeat": {"enabled": False, "url": "", "interval_minutes": 5},
    # Alert storm control: one switch dying must not mean 40 Telegram messages.
    "alerts": {"storm_threshold": 5, "parent_suppression": True, "trace_on_down": True,
               "ip_conflict": True,
               # Escalation: a CRITICAL host still down after N min with nobody
               # having tapped "✅ Принял" / "🔇" -> repeat louder, optionally to
               # a second chat (the backup human). 0 = off.
               "escalate_after_minutes": 0, "escalate_chat_id": "",
               # Passive ear: listen to SSDP/mDNS announcements devices shout
               # into the LAN anyway — instant new-device detect between scans.
               "passive_listen": True,
               # Hold-down: a host that blinks for 25 seconds is not an outage.
               # The alert waits this long; if the host comes back first, the
               # phone never learns about it. 0 = ring immediately (old behaviour).
               "hold_down_seconds": 90, "hold_down_skip_critical": True},
    # Auto-runbook: try the obvious fix before waking a human at 3am.
    "runbook": {
        "enabled": False,           # off by default — it takes action on its own
        "auto_wake": True,          # host with a MAC goes down -> send WoL
        "recheck_after_seconds": 120,
    },
    # WoL schedule: "wake the shop at 08:30 on weekdays".
    # Rule: {id, name, time "HH:MM", days [0=Mon..6=Sun] ([]=every day),
    #        hosts [ids] ([]=all with MAC), verify, enabled}
    "wol_schedule": [],
    # Quiet hours: normal-priority alerts are held at night and summarized in
    # a morning digest; critical hosts always ring; watch-class never rings.
    "quiet": {"enabled": False, "from": "22:00", "to": "08:00", "digest": True},
    # Scheduled network scan: sweep + diff without pressing the button.
    # Off by default — a periodic ping sweep is loud on the wire (D14).
    "netscan": {"enabled": False, "interval_minutes": 60},
    # Maintenance windows: planned work must not ring — false alerts teach
    # people to ignore the real ones. Window: {id, name, from, to,
    # days [0=Mon..6=Sun] ([]=every day), hosts [ids] ([]=all), enabled}
    "maintenance": [],
    # Rogue DHCP watch: somebody plugs a home router in -> a second DHCP
    # server quietly breaks half the office. expected=[] means "learn the
    # legitimate servers on the first probe".
    "dhcp_watch": {"enabled": False, "interval_minutes": 30, "expected": []},
    # WAN watch: who is to blame when "the internet is down" —
    # the gateway (our problem), the uplink (ISP) or DNS.
    "wan": {
        "enabled": True,
        "gateway": "",              # empty = autodetect from the route table
        "external": "8.8.8.8",      # pinged to prove the uplink
        "dns_probe": "google.com",  # name resolved to prove DNS
        "dns_server": "",           # empty = system resolver
        "interval_seconds": 60,
    },
    # Degradation: warn BEFORE a host dies. Compares a recent median latency
    # against a long rolling baseline — dying disks and saturated links show up
    # here hours before they show up as "down".
    "degradation": {
        "enabled": True,
        "ratio_threshold": 3.0,     # current median >= 3x baseline -> degraded
        "sustain_minutes": 10,      # window for "current"; also kills flapping
        "baseline_hours": 168,      # 7 days of normal
        "min_samples": 60,          # refuse to judge without enough history
        "min_latency_ms": 5.0,      # 1ms -> 4ms is 4x but meaningless; floor it
    },
    # Wi-Fi / rogue-AP watch. RF is scanned by sensor instances (one per floor):
    # `monitor.py --wifi-sensor <brain-url> <token>`. The brain learns a baseline
    # of trusted BSSIDs for `learn_hours`, then flags evil-twins, rogue APs and
    # nodes whose radio dropped off the air. watch_ssids=[] guards all learned SSIDs.
    "wifi": {
        "enabled": False,
        "watch_ssids": [],
        "learn_hours": 24,
        "radio_gone_minutes": 10,
        "rogue_min_signal": 40,
        "sensor_stale_minutes": 15,
    },
    # UniFi controller as an RF source. Every adopted AP already listens to the
    # air, so each one is modelled as a Wi-Fi sensor and feeds the same pipeline
    # the netsh sensors do — no extra boxes needed.
    # own_other_ssids: our own SSIDs broadcast from OTHER hardware. The controller
    # can only report them as foreign, so without this they read as rogue.
    # Credentials are NOT here — read-only Viewer account in
    # ~/.config/signal-desk/unifi.json (outside the repo, never in git).
    "unifi": {
        "enabled": False,
        "url": "https://127.0.0.1:8443",
        "site": "default",
        "interval_seconds": 60,
        "own_other_ssids": [],
        "alert_ap_offline": True,
        # Neighbours are listed, not shouted about: in a mall every customer's
        # phone hotspot is a "new AP". Evil-twin still alerts — that one matters.
        "alert_rogue": False,
    },
    # Hand-placed map nodes: {node_id: [x, y]}. Anything absent is auto-laid-out.
    "map_layout": {},
    "hosts": [],
    "subnets": [],
}


# ----------------------------------------------------------------------------
# Config — loaded once, mutated by the web UI, persisted to config.json
# ----------------------------------------------------------------------------

CONFIG_LOCK = threading.RLock()


CONFIG: dict = {}


def load_config():
    global CONFIG
    if not os.path.exists(CONFIG_PATH):
        CONFIG = json.loads(json.dumps(DEFAULT_CONFIG))
        save_config()
        return
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update(data)
    if merged.get("app_name") == "Server Signal Desk":     # 0.58: the product is «Филин» now;
        merged["app_name"] = "Филин"                         # a name somebody typed in stays
    merged.setdefault("telegram", {}).setdefault("bot_token", "")
    merged["telegram"].setdefault("chat_id", "")
    merged.setdefault("auth", {})
    for k, v in DEFAULT_CONFIG["auth"].items():
        merged["auth"].setdefault(k, v)
    merged.setdefault("heartbeat", {})
    for k, v in DEFAULT_CONFIG["heartbeat"].items():
        merged["heartbeat"].setdefault(k, v)
    merged.setdefault("alerts", {})
    for k, v in DEFAULT_CONFIG["alerts"].items():
        merged["alerts"].setdefault(k, v)
    merged.setdefault("degradation", {})
    for k, v in DEFAULT_CONFIG["degradation"].items():
        merged["degradation"].setdefault(k, v)
    merged.setdefault("runbook", {})
    for k, v in DEFAULT_CONFIG["runbook"].items():
        merged["runbook"].setdefault(k, v)
    merged.setdefault("wan", {})
    for k, v in DEFAULT_CONFIG["wan"].items():
        merged["wan"].setdefault(k, v)
    merged.setdefault("quiet", {})
    for k, v in DEFAULT_CONFIG["quiet"].items():
        merged["quiet"].setdefault(k, v)
    merged.setdefault("api", {}).setdefault("token", "")
    merged.setdefault("netscan", {})
    for k, v in DEFAULT_CONFIG["netscan"].items():
        merged["netscan"].setdefault(k, v)
    merged.setdefault("dhcp_watch", {})
    for k, v in DEFAULT_CONFIG["dhcp_watch"].items():
        merged["dhcp_watch"].setdefault(k, v)
    CONFIG = merged


def save_config():
    with CONFIG_LOCK:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, ensure_ascii=False, indent=2)
        # The previous version survives one write: config.json holds 9 hand-set
        # hosts, the password and the bot token, and has no copy anywhere else
        # (the 07-21 deploy footgun shipped a stub over it).
        if os.path.exists(CONFIG_PATH):
            try:
                shutil.copy2(CONFIG_PATH, CONFIG_PATH + ".bak")
            except OSError as e:
                print(f"[config] .bak не записан: {short_err(e)}")
        os.replace(tmp, CONFIG_PATH)


def cfg(key, default=None):
    with CONFIG_LOCK:
        return CONFIG.get(key, default)


def short_err(e):
    return (str(e) or e.__class__.__name__)[:120]
