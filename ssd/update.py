"""Self-update with rollback."""

import html
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from urllib import request as urlrequest

from . import core, storage, telegram, alerting


# ----------------------------------------------------------------------------
# Self-update with rollback. Until 0.55 every release was: Taildrop the exe,
# rename it by hand, restart the task, hope. Now: the exe lands in Downloads,
# a button (bot or dashboard) smoke-tests it, keeps the running one in backup\,
# swaps and restarts. A helper — a copy of the CURRENT exe, so it always speaks
# this protocol — watches the new one; no first check cycle in time -> the old
# exe goes back and Telegram is told.
# ----------------------------------------------------------------------------

EXE_RE = re.compile(r"^ServerSignalDesk-v(\d+\.\d+\.\d+)\.exe$", re.I)


UPDATE_LOCK = threading.Lock()


UPDATE_HEALTH_SEC = 150


_UPDATE_MARKED = {"done": False}


def _vt(v):
    return tuple(int(x) for x in str(v).split("."))


def update_paths():
    base = core.app_dir()
    return {"file": os.path.join(base, "update.json"), "backup": os.path.join(base, "backup"),
            "downloads": (core.cfg("update", {}) or {}).get("downloads")
            or os.path.join(os.path.expanduser("~"), "Downloads")}


def _exe_list(folder):
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for n in names:
        mm = EXE_RE.match(n)
        if mm:
            path = os.path.join(folder, n)
            try:
                out.append({"path": path, "version": mm.group(1), "size": os.path.getsize(path),
                            "mtime": os.path.getmtime(path)})
            except OSError:
                pass
    return sorted(out, key=lambda x: _vt(x["version"]), reverse=True)


def update_download_dirs(home=None, users_root="C:\\Users"):
    """Where Taildrop puts files: the logged-in user's Downloads. Run by the
    scheduled task as SYSTEM, ~ is systemprofile — Taildrop never lands there,
    so look in every profile's Downloads (one-user office PC; the smoke test
    still has to print the right version)."""
    first = update_paths()["downloads"]
    home = home or os.path.expanduser("~")
    out = [first]
    if "systemprofile" in home.lower() and not (core.cfg("update", {}) or {}).get("downloads"):
        try:
            for name in sorted(os.listdir(users_root)):
                d = os.path.join(users_root, name, "Downloads")
                if os.path.isdir(d) and d not in out:
                    out.append(d)
        except OSError:
            pass
    return out


def update_candidates():
    """Newer exes in Downloads (where Taildrop drops) or next to the running one."""
    seen = {}
    for folder in update_download_dirs() + [core.app_dir()]:
        for x in _exe_list(folder):
            if _vt(x["version"]) > _vt(core.__version__):
                seen.setdefault(x["version"], x)
    return sorted(seen.values(), key=lambda x: _vt(x["version"]), reverse=True)


def update_backups():
    """Rollback targets: every kept copy except the version running now."""
    return [x for x in _exe_list(update_paths()["backup"]) if x["version"] != core.__version__]


def update_state():
    try:
        with open(update_paths()["file"], encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _update_write(st):
    path = update_paths()["file"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(tmp, path)


def _task_name():
    return (core.cfg("update", {}) or {}).get("task") or "ServerSignalDesk"


def exe_smoke(path, expect):
    """Run the candidate with --version: a truncated download or a wrong file
    fails here, while the old monitor is still running."""
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=90,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:
        return False, "пробный запуск не прошёл: " + core.short_err(e)
    lines = (r.stdout or "").strip().splitlines()
    got = lines[-1].strip() if lines else ""
    if r.returncode != 0 or got != expect:
        return False, f"пробный запуск: код {r.returncode}, версия «{got or '—'}» вместо {expect}"
    return True, ""


# Owner of the file and the members of local Administrators, as SIDs (names are
# localized). The path comes in through the environment, never through the script.
_OWNER_PS = ("$o=(Get-Acl -LiteralPath $env:SSD_CHECK).GetOwner([Security.Principal.SecurityIdentifier]).Value;"
             "$a=@(Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | ForEach-Object { $_.SID.Value });"
             "Write-Output $o; Write-Output ($a -join ',')")
_ADMIN_SIDS = {"S-1-5-18", "S-1-5-32-544"}                   # SYSTEM, BUILTIN\Administrators


def exe_trusted(path, run=None):
    """The monitor runs as SYSTEM and looks in every profile's Downloads, so any
    local account could drop a «newer version» there and have it started as SYSTEM
    by the smoke test. Only a file owned by an administrator goes further."""
    if os.name != "nt" and run is None:
        return True, ""
    try:
        r = (run or subprocess.run)(["powershell", "-NoProfile", "-NonInteractive", "-Command", _OWNER_PS],
                                    capture_output=True, text=True, timeout=30,
                                    env=dict(os.environ, SSD_CHECK=path),
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:
        return False, "не смог проверить владельца файла: " + core.short_err(e)
    lines = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
    owner = lines[0] if lines else ""
    admins = _ADMIN_SIDS | set(x for x in (lines[1].split(",") if len(lines) > 1 else []) if x)
    if owner and owner in admins:
        return True, ""
    return False, (f"файл {os.path.basename(path)} положил не администратор этого ПК — не запускаю. "
                   "Скопируй exe в «Загрузки» из-под администратора.")


def _prune_backups(keep, protect):
    items = _exe_list(update_paths()["backup"])
    for x in items[keep:]:
        if x["path"] not in protect:
            try:
                os.remove(x["path"])
            except OSError:
                pass


def _spawn_helper(exe, state_file):
    env = dict(os.environ, SSD_APP_DIR=core.app_dir())
    flags = 0x00000008 | 0x00000200          # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    for extra in (0x01000000, 0):            # leave the scheduled task's job if it lets us
        try:
            subprocess.Popen([exe, "--update-swap", state_file], env=env, cwd=core.app_dir(),
                             creationflags=flags | extra, close_fds=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except OSError:
            if not extra:
                raise


def _exit_soon():
    def bye():
        try:
            storage.runtime_save()
        finally:
            os._exit(0)
    threading.Timer(2.0, bye).start()


def update_start(action, by="", spawn=None, smoke=None, exit_after=None, trust=None):
    """action 'update' -> newest candidate, 'rollback' -> newest backup.
    Returns (ok, message); on ok this process exits ~2 s later."""
    if not getattr(sys, "frozen", False) and spawn is None:
        return False, "обновление работает только у exe"
    with UPDATE_LOCK:
        st = update_state()
        if st.get("state") in ("swapping", "starting") and time.time() - st.get("ts", 0) < 600:
            return False, "обновление уже идёт"
        if action == "update":
            c = update_candidates()
            if not c:
                return False, "новой версии нет — пришли ServerSignalDesk-vX.exe в «Загрузки»"
            target = c[0]
            ok, err = (trust or exe_trusted)(target["path"])
            if not ok:
                return False, err
            ok, err = (smoke or exe_smoke)(target["path"], target["version"])
            if not ok:
                return False, err
        else:
            b = update_backups()
            if not b:
                return False, "резервных копий нет"
            target = b[0]
        bdir = update_paths()["backup"]
        os.makedirs(bdir, exist_ok=True)
        mine = os.path.join(bdir, f"ServerSignalDesk-v{core.__version__}.exe")
        if not os.path.exists(mine):
            shutil.copy2(sys.executable, mine)
        _prune_backups(keep=3, protect={mine, target["path"]})
        _update_write({"state": "swapping", "kind": action, "from": core.__version__, "to": target["version"],
                       "src": target["path"], "exe": sys.executable, "backup": mine, "pid_old": os.getpid(),
                       "port": int(core.cfg("web_port", 8081)), "task": _task_name(), "ts": time.time(), "by": by})
        (spawn or _spawn_helper)(mine, update_paths()["file"])
    word = "Обновляюсь" if action == "update" else "Откатываюсь"
    alerting.emit("system", f"⏳ {word}: v{core.__version__} → v{target['version']}"
                   + (f" ({html.escape(by)})" if by else "") + ". Перезапуск, итог пришлю.", queue=False)
    (exit_after or _exit_soon)()
    return True, f"v{core.__version__} → v{target['version']}"


def update_note_start():
    """Called once in main(): tell the helper which process is the new one."""
    st = update_state()
    if st.get("state") == "starting" and st.get("to") == core.__version__:
        st["pid_new"] = os.getpid()
        _update_write(st)


def update_mark_healthy():
    """After the first completed check cycle — the helper's success signal."""
    if _UPDATE_MARKED["done"]:
        return
    _UPDATE_MARKED["done"] = True
    st = update_state()
    if st.get("state") != "starting" or st.get("to") != core.__version__:
        return
    st.update(state="healthy", ts_done=time.time())
    _update_write(st)
    word = "Обновлено" if st.get("kind") == "update" else "Откат выполнен"
    alerting.emit("system", f"✅ {word}: v{st.get('from')} → v{core.__version__}. Прошлая версия — в backup\\.", queue=False)


def update_view():
    return {"version": core.__version__, "frozen": bool(getattr(sys, "frozen", False)),
            "candidates": update_candidates(), "backups": update_backups(),
            "state": {k: v for k, v in update_state().items() if k in ("state", "kind", "from", "to", "ts", "ts_done", "by", "error")},
            "task": _task_name()}


# -- the helper side (runs as `<backup copy> --update-swap update.json`) --------

def _ulog(msg):
    try:
        os.makedirs(os.path.join(core.app_dir(), "logs"), exist_ok=True)
        with open(os.path.join(core.app_dir(), "logs", "update.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def _wait_pid(pid, timeout):
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x00100000, False, int(pid))        # SYNCHRONIZE
        if not h:
            return True                                          # already gone
        try:
            return k32.WaitForSingleObject(h, int(timeout * 1000)) == 0
        finally:
            k32.CloseHandle(h)
    end = time.time() + timeout
    while time.time() < end:
        try:
            os.kill(int(pid), 0)
        except OSError:
            return True
        time.sleep(0.5)
    return False


def _swap_file(src, dst, tries=30, sleep=time.sleep):
    for _ in range(tries):
        try:
            shutil.copy2(src, dst + ".new")
            os.replace(dst + ".new", dst)
            return True
        except OSError as e:
            _ulog(f"swap {src} -> {dst}: {core.short_err(e)}")
            sleep(1)
    return False


def _task_runs(task, exe, run=None):
    """Does the scheduled task start THIS exe? A task pointing at a missing or
    other file "runs" fine and starts nothing (10-15: the office monitor was
    started by hand, the task still named ServerSignalDesk.exe, which wasn't
    there) — the update would end with no monitor at all."""
    run = run or subprocess.run
    try:
        r = run(["schtasks", "/Query", "/TN", task, "/XML"], capture_output=True, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return False
    return r.returncode == 0 and os.path.normcase(exe) in os.path.normcase(r.stdout or "")


def _task_start(st, run=None, popen=None):
    run, popen = run or subprocess.run, popen or subprocess.Popen
    if _task_runs(st["task"], st["exe"], run):
        r = run(["schtasks", "/Run", "/TN", st["task"]], capture_output=True, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode == 0:
            return "task"
    popen([st["exe"]], cwd=os.path.dirname(st["exe"]), creationflags=0x00000008,
          close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "direct"


def _task_kill(st):
    if st.get("pid_new"):
        subprocess.run(["taskkill", "/F", "/PID", str(st["pid_new"])], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    subprocess.run(["schtasks", "/End", "/TN", st["task"]], capture_output=True,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _http_up(port):
    try:
        with urlrequest.urlopen(f"http://127.0.0.1:{port}/login", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def _helper_notify(text):
    try:
        core.load_config()
        tg = core.cfg("telegram", {}) or {}
        if tg.get("bot_token") and tg.get("chat_id"):
            telegram._tg_call("sendMessage", {"chat_id": tg["chat_id"], "text": text, "parse_mode": "HTML"}, 15)
    except Exception as e:
        _ulog("notify: " + core.short_err(e))


def update_swap_main(state_file, wait=None, swap=None, start=None, kill=None, http_up=None,
                     notify=None, sleep=time.sleep, now=time.time):
    wait, swap, start = wait or _wait_pid, swap or _swap_file, start or _task_start
    kill, http_up, notify = kill or _task_kill, http_up or _http_up, notify or _helper_notify
    with open(state_file, encoding="utf-8") as f:
        st = json.load(f)

    def write(**kw):
        st.update(kw)
        tmp = state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
        os.replace(tmp, state_file)

    def reread():
        try:
            with open(state_file, encoding="utf-8") as f:
                st.update(json.load(f))
        except (OSError, ValueError):
            pass

    _ulog(f"{st['kind']} v{st['from']} -> v{st['to']}: waiting for pid {st['pid_old']}")
    if not wait(st["pid_old"], 60):
        write(state="failed", error="старый процесс не завершился")
        notify(f"⚠️ Обновление до v{st['to']} не начато: старый монитор не завершился за минуту.")
        return 1
    if not swap(st["src"], st["exe"]):
        write(state="failed", error="не удалось заменить exe")
        start(st)
        notify(f"⚠️ Обновление до v{st['to']} не удалось: exe не заменился. Запустил v{st['from']} обратно.")
        return 1
    write(state="starting", ts=now())
    _ulog("swapped, starting via " + start(st))
    deadline = now() + UPDATE_HEALTH_SEC
    while now() < deadline:
        sleep(3)
        reread()
        if st.get("state") == "healthy":
            _ulog("healthy")
            return 0
        if st["kind"] == "rollback" and http_up(st["port"]) and now() > deadline - UPDATE_HEALTH_SEC + 60:
            # an older build may predate the health mark — a live web server is enough
            write(state="healthy", ts_done=now())
            notify(f"↩️ Откат выполнен: v{st['from']} → v{st['to']}.")
            return 0
    _ulog("no health signal — rolling back")
    kill(st)
    sleep(2)
    if swap(st["backup"], st["exe"]):
        write(state="rolled_back", error=f"v{st['to']} не прошла первый цикл за {UPDATE_HEALTH_SEC} с")
        start(st)
        notify(f"⚠️ v{st['to']} не поднялась за {UPDATE_HEALTH_SEC // 60} мин — вернул v{st['from']}. "
               f"Подробности — logs\\update.log.")
    else:
        write(state="broken", error="откат не удался")
        notify(f"🔴 v{st['to']} не поднялась, и вернуть v{st['from']} не удалось. Нужны руки: "
               f"скопируй {html.escape(st['backup'])} на место {html.escape(st['exe'])}.")
    return 1
