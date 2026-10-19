"""Network diagnosis from the monitor's own seat: who it runs as, which source
address the stack picks for a target, and raw ping / route / arp output.

10-15: the monitor (SYSTEM, from the task) saw 9 of 97 cameras while a ping
from a user session on the same PC answered. Guessing from outside got
nowhere; this shows what the monitor itself sees."""

import os
import socket
import subprocess

from . import checks, core


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return checks.console_text(r.stdout + r.stderr).strip()
    except Exception as e:
        return "ошибка: " + core.short_err(e)


def source_ip(ip):
    """The address the stack would send from — a UDP connect sends nothing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 9))
        return s.getsockname()[0]
    except OSError as e:
        return "ошибка: " + core.short_err(e)
    finally:
        s.close()


def tcp_probe(ip, port=80, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return {"ok": True, "port": port, "from": s.getsockname()[0]}
    except OSError as e:
        return {"ok": False, "port": port, "error": core.short_err(e)}


def diagnose(ip, run=None):
    run = run or _run
    if os.name == "nt":
        cmds = [["whoami"], ["ipconfig"], ["route", "print", "-4"],
                ["ping", "-n", "2", "-w", "1000", ip], ["arp", "-a"]]
    else:
        cmds = [["id"], ["ip", "addr"], ["ip", "route"], ["ping", "-c", "2", "-W", "1", ip], ["ip", "neigh"]]
    return {"ip": ip, "source_ip": source_ip(ip), "tcp80": tcp_probe(ip),
            "outputs": [{"cmd": " ".join(c), "text": run(c)} for c in cmds]}
