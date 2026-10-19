"""IP conflict and MAC change detection."""

import html
import time

from . import core, storage, netinventory, dhcp


# ----------------------------------------------------------------------------
# IP conflict detection — two devices fighting over one address show up as the
# ARP entry flip-flopping between MACs. The monitor's own checks keep the OS
# ARP cache warm every cycle, so watching it is one `arp -a` read — zero
# extra packets on the wire. A one-time MAC change is a device swap (v0.10
# already alerts on that); a conflict is the address BOUNCING:
#   flip-back  A→B→A within 24h, or
#   churn      3+ changes within one hour.
# ----------------------------------------------------------------------------

_ARP_LAST = {}          # ip -> last mac seen (in-memory; rebuilt after restart)


_CONFLICT_ALERTED = {}  # ip -> ts of last conflict alert (one per ip per hour)


_IGNORED_MAC_PREFIXES = ("01:00:5e", "01:80:c2", "33:33", "ff:ff:ff")


def _arp_entry_relevant(ip, mac):
    """Multicast/broadcast ARP entries change 'MACs' by design — not devices."""
    if not mac or mac.startswith(_IGNORED_MAC_PREFIXES):
        return False
    if ip.startswith(("224.", "225.", "239.", "255.")) or ip.endswith(".255"):
        return False
    return True


def db_mac_change(ip, mac, ts):
    with storage._db_lock:
        storage._db.execute("INSERT INTO mac_history (ip, mac, ts) VALUES (?,?,?)", (ip, mac, ts))
        storage._db.execute("DELETE FROM mac_history WHERE ts < ?", (ts - 7 * 86400,))
        storage._db.commit()


def db_mac_history(ip, since):
    with storage._db_lock:
        rows = storage._db.execute(
            "SELECT mac, ts FROM mac_history WHERE ip=? AND ts>=? ORDER BY ts",
            (ip, since)).fetchall()
    return [(r[0], r[1]) for r in rows]


CONFLICT_FLIP_WINDOW = 3600


def classify_conflict(seq):
    """seq = chronological (mac, ts) change records for one IP (24h window).
    Consecutive entries always differ — only changes are recorded — so a mac
    appearing twice in the list means it CAME BACK: that's the conflict tell.
    Returns {"macs", "changes", "flip", "churn"} or None (mere swap)."""
    if len(seq) < 2:
        return None
    macs = [m for m, _ in seq]
    ts = [t for _, t in seq]
    # A flip-back counts only if fast: two devices holding the address AT THE
    # SAME TIME make ARP bounce within minutes. A→B→A over hours is DHCP handing
    # a freed address around (9-hour leases, phones coming and going) — 10-15
    # fired «КОНФЛИКТ IP» twice in a morning for exactly that.
    flip = any(macs[j] == macs[i] and ts[j] - ts[i] <= CONFLICT_FLIP_WINDOW
               for i in range(len(macs)) for j in range(i + 2, len(macs)))
    churn = any(ts[i + 2] - ts[i] <= 3600 for i in range(len(ts) - 2))
    if not (flip or churn):
        return None
    uniq = []
    for m in macs:
        if m not in uniq:
            uniq.append(m)
    return {"macs": uniq, "changes": len(seq), "flip": flip, "churn": churn}


def _alert_ip_conflict(ip, v):
    who = " ↔ ".join(f"{m} ({netinventory.lookup_vendor(m) or '?'})" for m in v["macs"][:4])
    text = (f"IP {ip} мечется между устройствами: {who}. Смен за 24ч: {v['changes']}. "
            f"Два устройства с одним адресом → случайные обрывы у обоих.")
    for h in livestate.enabled_hosts():
        if h.get("host") == ip:
            storage.db_event(h["id"], time.time(), "conflict", text)
            break
    alerting.emit("ipconflict", f"🔥 <b>КОНФЛИКТ IP</b>\n{html.escape(text)}\n"
            f"Лечится: найти второе устройство (по вендору MAC) и развести адреса.")


def watch_arp_conflicts(arp=None):
    """Called once per monitor cycle. Reads the OS ARP cache, logs MAC changes,
    raises a conflict alert when an address is bouncing between devices."""
    al = core.cfg("alerts", {}) or {}
    if not al.get("ip_conflict", True):
        return
    now = time.time()
    for ip, mac in (arp if arp is not None else dhcp.arp_table()).items():
        if not _arp_entry_relevant(ip, mac):
            continue
        last = _ARP_LAST.get(ip)
        _ARP_LAST[ip] = mac
        if last is None or last == mac:
            continue
        # keep the sequence complete: baseline the old mac if history missed it
        hist = db_mac_history(ip, now - 86400)
        if not hist or hist[-1][0] != last:
            db_mac_change(ip, last, now - 0.001)
        db_mac_change(ip, mac, now)
        verdict = classify_conflict(db_mac_history(ip, now - 86400))
        # A phone flipping between its real and its privacy MAC (or rotating
        # privacy MACs) "bounces" one IP all by itself. Kept in mac_history and
        # the UI, not alerted: a two-device conflict needs two real identities.
        if verdict and sum(1 for m in verdict["macs"] if not netinventory.mac_is_random(m)) < 2:
            verdict = None
        if verdict and now - _CONFLICT_ALERTED.get(ip, 0) > 3600:
            _CONFLICT_ALERTED[ip] = now
            _alert_ip_conflict(ip, verdict)


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import alerting, livestate  # noqa: E402
