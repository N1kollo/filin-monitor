"""Host checks (ping, TCP, HTTP, multi-port) and Wake-on-LAN."""

import os
import re
import socket
import subprocess
import time
from urllib import error as urlerror
from urllib import request as urlrequest

from . import core


# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------


def check_tcp(host, port, timeout):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, (time.perf_counter() - start) * 1000, None
    except Exception as e:
        return False, None, core.short_err(e)


def _body_matches(body, expect):
    """True if `expect` is in the body literally OR as a regex (case-insensitive).
    Literal first: «цена (опт)» is a valid regex that silently eats the parens —
    an operator typing plain text must never be burned by accidental regex syntax."""
    if expect.lower() in body.lower():
        return True
    try:
        return re.search(expect, body, re.IGNORECASE) is not None
    except re.error:
        return False


def check_http(url, timeout, expect=None):
    """UP = status < 400 AND (if `expect` set) the body contains it.
    Content validation catches the lying-200 case: 1C says «идёт обновление»
    with a perfectly healthy status code."""
    start = time.perf_counter()
    req = urlrequest.Request(url, headers={"User-Agent": "ServerSignalDesk/1.0"})
    try:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # internal servers often self-signed
        with urlrequest.urlopen(req, timeout=timeout, context=ctx) as r:
            code = r.status
            body = r.read(262144).decode("utf-8", errors="ignore") if expect else ""
        latency = (time.perf_counter() - start) * 1000
        if code >= 400:
            return False, latency, f"HTTP {code}"
        if expect and not _body_matches(body, expect):
            return False, latency, f"HTTP {code}, но нет ожидаемого текста «{expect[:40]}»"
        return True, latency, None
    except urlerror.HTTPError as e:
        latency = (time.perf_counter() - start) * 1000
        e.close()   # the error carries the open response — a 503 per cycle leaked one each time
        if e.code < 400:
            return True, latency, None
        return False, latency, f"HTTP {e.code}"
    except Exception as e:
        return False, None, core.short_err(e)


# «время<1мс» on Russian Windows, «time=3ms» on English: the unit must be
# matched in both scripts. With "m" only, every Russian reply missed and the
# latency silently became the ping PROCESS runtime (APP_SRV «85 ms», gateway
# «54 ms» — found 10-14 by the first ping test).
_PING_LAT = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)")


def console_text(raw):
    """Decode a Windows console tool's stdout. Pipes carry the OEM code page
    (cp866 on Russian Windows), not UTF-8 — decoding as UTF-8 shredded every
    Cyrillic word. Elsewhere (and on failure) UTF-8 with replacement."""
    if os.name == "nt":
        try:
            import ctypes
            return raw.decode(f"cp{ctypes.windll.kernel32.GetOEMCP()}", errors="replace")
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


_PING_TTL = re.compile(r"ttl[=:]\s*(\d+)", re.IGNORECASE)


# Free OS intel: every ping reply carries a TTL, and OS families start from
# different defaults (Linux/mac 64, Windows 128, network gear 255). We were
# throwing it away. Reliable on a LAN (0-3 hops barely decrement it).
_TTL_SEEN = {}  # ip/hostname -> last TTL from a ping reply


def os_from_ttl(ttl):
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "сетевое устройство"


def check_ping(host, timeout):
    is_win = os.name == "nt"
    count = "-n" if is_win else "-c"
    wait = "-w" if is_win else "-W"
    wait_val = str(int(timeout * 1000)) if is_win else str(max(1, int(timeout)))
    start = time.perf_counter()
    try:
        flags = subprocess.CREATE_NO_WINDOW if is_win else 0
        proc = subprocess.run(
            ["ping", count, "1", wait, wait_val, host],
            capture_output=True, timeout=timeout + 3, creationflags=flags,
        )
        latency = (time.perf_counter() - start) * 1000
        text = console_text(proc.stdout).lower()
        up = proc.returncode == 0 and "ttl" in text
        if up:
            m = _PING_LAT.search(text)
            if m:
                latency = float(m.group(1).replace(",", "."))
            t = _PING_TTL.search(text)
            if t:
                _TTL_SEEN[host] = int(t.group(1))
            return True, latency, None
        return False, None, "unreachable"
    except FileNotFoundError:
        return False, None, "ping not found"
    except Exception as e:
        return False, None, core.short_err(e)


# ----------------------------------------------------------------------------
# Wake-on-LAN — the monitor sits inside the LAN, so it can broadcast the magic
# packet that wakes a sleeping machine. Works as a remote "power button".
# ----------------------------------------------------------------------------


def normalize_mac(mac):
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(clean) != 12:
        raise ValueError("MAC должен быть из 12 hex-символов (напр. AA:BB:CC:DD:EE:FF)")
    return clean.lower()


def send_wol(mac, broadcast=None, port=9):
    clean = normalize_mac(mac)
    packet = bytes.fromhex("ff" * 6 + clean * 16)
    target = broadcast or "255.255.255.255"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Port 9 is the usual WoL port; 7 is a legacy fallback. Send both.
        s.sendto(packet, (target, port))
        s.sendto(packet, (target, 7))
    finally:
        s.close()
    return target


_ARP_WIN = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")


_ARP_NIX = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def run_check(host, timeout):
    t = host.get("type", "ping")
    if t == "tcp":
        return check_tcp(host.get("host", ""), host.get("port", 0), timeout)
    if t == "http":
        return check_http(host.get("url", ""), timeout, (host.get("expect") or "").strip() or None)
    if t == "host":
        return passive.check_host(host.get("host", ""), timeout)
    return check_ping(host.get("host", ""), timeout)


# Imported last: these modules call back into this one, and Python
# resolves `module.name` at call time — by then both are loaded.
from . import passive  # noqa: E402
