"""v0.55: self-update with rollback. The real exe swap and schtasks only exist on
mon-pc; here every OS touch is a stub and the protocol between the old monitor,
the helper and the new monitor is what's under test."""
import json
import os
import subprocess
import sys
import unittest

from harness import cleanup, load_monitor, stub_telegram

HERE = os.path.dirname(os.path.abspath(__file__))


def touch(path, data=b"MZ"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


class UpdateTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        self.calls = stub_telegram(m)
        self.dl = os.path.join(self.tmp, "Downloads")
        self.paths = {"file": os.path.join(self.tmp, "update.json"), "backup": os.path.join(self.tmp, "backup"),
                      "downloads": self.dl}
        m.update_paths = lambda: self.paths
        m.__version__ = "0.55.0"
        self.exe = touch(os.path.join(self.tmp, "ServerSignalDesk.exe"), b"MZ-current")
        self.real_exe = sys.executable
        sys.executable = self.exe
        self.spawned, self.exited = [], []

    def tearDown(self):
        sys.executable = self.real_exe
        cleanup(self.m, self.tmp)

    def texts(self):
        return [c[1]["text"] for c in self.calls if c[0] == "sendMessage"]

    def start(self, action, smoke=lambda p, v: (True, "")):
        return self.m.update_start(action, by="тест", spawn=lambda exe, f: self.spawned.append((exe, f)),
                                   smoke=smoke, exit_after=lambda: self.exited.append(1),
                                   trust=lambda p: (True, ""))

    # ------------------------------------------------------------ finding exes
    def test_candidates_newest_first_and_only_newer(self):
        for v in ("0.54.1", "0.55.1", "0.56.0", "0.55.0"):
            touch(os.path.join(self.dl, f"ServerSignalDesk-v{v}.exe"))
        touch(os.path.join(self.dl, "ServerSignalDesk-v0.57.0.exe.part"))
        touch(os.path.join(self.dl, "ServerSignalDesk (1).exe"))
        self.assertEqual([x["version"] for x in self.m.update_candidates()], ["0.56.0", "0.55.1"])
        self.assertEqual(self.m._vt("0.10.0") > self.m._vt("0.9.9"), True, "numeric, not string compare")

    # ------------------------------------------------------------ old monitor
    def test_update_start(self):
        src = touch(os.path.join(self.dl, "ServerSignalDesk-v0.55.1.exe"), b"MZ-new")
        ok, msg = self.start("update")
        self.assertTrue(ok, msg)
        st = json.load(open(self.paths["file"], encoding="utf-8"))
        bak = os.path.join(self.paths["backup"], "ServerSignalDesk-v0.55.0.exe")
        self.assertEqual((st["state"], st["kind"], st["from"], st["to"], st["src"], st["exe"], st["backup"]),
                         ("swapping", "update", "0.55.0", "0.55.1", src, self.exe, bak))
        self.assertEqual(open(bak, "rb").read(), b"MZ-current", "the running exe is kept in backup\\")
        self.assertEqual(self.spawned, [(bak, self.paths["file"])], "helper = copy of the CURRENT exe")
        self.assertEqual(self.exited, [1])
        self.assertIn("Обновляюсь: v0.55.0 → v0.55.1", self.texts()[-1])
        self.assertIn("уже идёт", self.start("update")[1], "no second update while one is running")

    def test_smoke_failure_touches_nothing(self):
        touch(os.path.join(self.dl, "ServerSignalDesk-v0.55.1.exe"))
        ok, msg = self.start("update", smoke=lambda p, v: (False, "пробный запуск: код 1"))
        self.assertEqual((ok, msg), (False, "пробный запуск: код 1"))
        self.assertFalse(os.path.exists(self.paths["file"]))
        self.assertEqual((self.spawned, self.exited), ([], []))

    def test_nothing_to_do(self):
        self.assertIn("новой версии нет", self.start("update")[1])
        self.assertIn("резервных копий нет", self.start("rollback")[1])

    def test_rollback_picks_newest_other_backup_and_prunes(self):
        for v in ("0.50.0", "0.52.0", "0.53.0", "0.54.1"):
            touch(os.path.join(self.paths["backup"], f"ServerSignalDesk-v{v}.exe"))
        ok, msg = self.start("rollback")
        self.assertEqual((ok, msg), (True, "v0.55.0 → v0.54.1"))
        left = sorted(x["version"] for x in self.m._exe_list(self.paths["backup"]))
        self.assertEqual(left, ["0.53.0", "0.54.1", "0.55.0"], "keep 3 newest")

    def test_smoke_runs_version_flag(self):
        """The real smoke: this very monitor.py answers --version with its version."""
        src = os.path.join(os.path.dirname(HERE), "monitor.py")
        r = subprocess.run([sys.executable if sys.executable != self.exe else self.real_exe, src, "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout.strip(), r"^\d+\.\d+\.\d+$")

    # ------------------------------------------------------------ new monitor
    def test_new_monitor_marks_healthy(self):
        m = self.m
        m._update_write({"state": "starting", "kind": "update", "from": "0.54.1", "to": "0.55.0", "ts": 1})
        m.update_note_start()
        self.assertEqual(m.update_state()["pid_new"], os.getpid())
        m.update_mark_healthy()
        self.assertEqual(m.update_state()["state"], "healthy")
        self.assertIn("✅ Обновлено: v0.54.1 → v0.55.0", self.texts()[-1])
        m.update_mark_healthy()
        self.assertEqual(len(self.texts()), 1, "once")

    def test_unrelated_state_untouched(self):
        m = self.m
        m._update_write({"state": "healthy", "kind": "update", "from": "0.53.0", "to": "0.54.1"})
        m.update_note_start()
        m.update_mark_healthy()
        self.assertEqual(m.update_state(), {"state": "healthy", "kind": "update", "from": "0.53.0", "to": "0.54.1"})
        self.assertEqual(self.texts(), [])


class TaskStartTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.ran, self.popened = [], []

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def go(self, xml, query_rc=0):
        class R:
            def __init__(s, rc, out=""):
                s.returncode, s.stdout = rc, out

        def run(cmd, **kw):
            self.ran.append(cmd[:2])
            return R(query_rc, xml) if "/Query" in cmd else R(0)
        st = {"task": "ServerSignalDesk", "exe": r"C:\Users\MON-PC\Desktop\signaldesk\ServerSignalDesk.exe"}
        return self.m._task_start(st, run=run, popen=lambda *a, **k: self.popened.append(a[0]))

    def test_task_points_here(self):
        xml = r'<Command>"C:\Users\MON-PC\Desktop\signaldesk\ServerSignalDesk.exe"</Command>'
        self.assertEqual(self.go(xml), "task")
        self.assertEqual(self.popened, [])

    def test_task_points_elsewhere_or_missing(self):
        """10-15 office: monitor started by hand, task named a file that wasn't there."""
        self.assertEqual(self.go(r'<Command>"C:\old\ServerSignalDesk.exe"</Command>'), "direct")
        self.assertEqual(self.go("", query_rc=1), "direct")
        self.assertEqual(len(self.popened), 2)
        self.assertNotIn(["schtasks", "/Run"], self.ran, "never /Run a task that starts something else")

    def test_download_dirs_under_system(self):
        users = os.path.join(self.tmp, "Users")
        for u in ("MON-PC", "Public"):
            os.makedirs(os.path.join(users, u, "Downloads"))
        dirs = self.m.update_download_dirs(home=r"C:\Windows\system32\config\systemprofile", users_root=users)
        self.assertIn(os.path.join(users, "MON-PC", "Downloads"), dirs)
        self.assertEqual(self.m.update_download_dirs(home=r"C:\Users\MON-PC", users_root=users)[1:], [],
                         "a normal user looks only in its own Downloads")


class HelperTest(unittest.TestCase):
    """update_swap_main with a fake clock and fake OS."""

    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.file = os.path.join(self.tmp, "update.json")
        self.st = {"state": "swapping", "kind": "update", "from": "0.55.0", "to": "0.55.1",
                   "src": "DL\\new.exe", "exe": "APP\\ServerSignalDesk.exe", "backup": "APP\\backup\\v0.55.0.exe",
                   "pid_old": 111, "port": 8081, "task": "ServerSignalDesk", "ts": 0}
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.st, f)
        self.t = [1000.0]
        self.log = []

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def run_helper(self, on_start=None, wait_ok=True, swap_ok=True, http=False):
        def start(st):
            self.log.append(("start",))
            if on_start:
                on_start()
            return "task"

        def sleep(s):
            self.t[0] += s
        return self.m.update_swap_main(
            self.file, wait=lambda pid, to: (self.log.append(("wait", pid)), wait_ok)[1],
            swap=lambda a, b: (self.log.append(("swap", a, b)), swap_ok)[1], start=start,
            kill=lambda st: self.log.append(("kill",)), http_up=lambda port: http,
            notify=lambda t: self.log.append(("tg", t)), sleep=sleep, now=lambda: self.t[0])

    def state(self):
        return json.load(open(self.file, encoding="utf-8"))

    def mark_healthy_later(self):
        st = self.state()
        st["state"] = "healthy"
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(st, f)

    def test_success(self):
        rc = self.run_helper(on_start=self.mark_healthy_later)
        self.assertEqual(rc, 0)
        self.assertEqual(self.log[:3], [("wait", 111), ("swap", "DL\\new.exe", "APP\\ServerSignalDesk.exe"), ("start",)])
        self.assertNotIn(("kill",), self.log)
        self.assertFalse([x for x in self.log if x[0] == "tg"], "the NEW monitor reports success itself")

    def test_no_health_rolls_back(self):
        rc = self.run_helper()
        self.assertEqual(rc, 1)
        self.assertIn(("kill",), self.log)
        self.assertIn(("swap", "APP\\backup\\v0.55.0.exe", "APP\\ServerSignalDesk.exe"), self.log)
        self.assertEqual([x[0] for x in self.log].count("start"), 2, "new started, then old started again")
        self.assertEqual(self.state()["state"], "rolled_back")
        self.assertIn("вернул v0.55.0", self.log[-1][1] if self.log[-1][0] == "tg" else
                      next(x[1] for x in self.log if x[0] == "tg"))
        self.assertGreaterEqual(self.t[0] - 1000, self.m.UPDATE_HEALTH_SEC)

    def test_old_process_never_exits(self):
        self.assertEqual(self.run_helper(wait_ok=False), 1)
        self.assertFalse([x for x in self.log if x[0] in ("swap", "start")], "nothing touched")
        self.assertEqual(self.state()["state"], "failed")

    def test_swap_fails_restarts_old(self):
        self.assertEqual(self.run_helper(swap_ok=False), 1)
        self.assertEqual([x[0] for x in self.log], ["wait", "swap", "start", "tg"])
        self.assertIn("не заменился", self.log[-1][1])

    def test_rollback_to_build_without_health_mark(self):
        st = dict(self.st, kind="rollback", to="0.54.1")
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(st, f)
        self.assertEqual(self.run_helper(http=True), 0)
        self.assertEqual(self.state()["state"], "healthy")
        self.assertIn("↩️ Откат выполнен: v0.55.0 → v0.54.1", self.log[-1][1])
        self.assertNotIn(("kill",), self.log)


class UpdateBotTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.calls = stub_telegram(self.m)
        self.m.update_view = lambda: {"version": "0.55.0", "frozen": True, "task": "ServerSignalDesk",
                                      "state": {"state": "healthy", "from": "0.54.1", "to": "0.55.0", "ts": 1},
                                      "candidates": [{"version": "0.55.1", "size": 11 * 1048576, "path": "x"}],
                                      "backups": [{"version": "0.54.1", "size": 1, "path": "y"}]}
        self.started = []
        self.m.update_start = lambda a, by="": (self.started.append((a, by)), (True, "v0.55.0 → v0.55.1"))[1]

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def tap(self, data):
        n = len(self.calls)
        self.m.handle_update({"update_id": 1, "callback_query": {
            "id": "c", "data": data, "message": {"chat": {"id": 42}, "message_id": 5, "text": ""}}})
        return self.calls[n:]

    def kb(self, calls):
        c = [c for c in calls if c[0] in ("editMessageText", "sendMessage")][-1][1]
        return c["text"], [b["callback_data"] for row in json.loads(c["reply_markup"])["inline_keyboard"] for b in row]

    def test_flow(self):
        _, menu = self.kb(self.tap("m:menu"))
        self.assertIn("m:ud", menu)
        text, b = self.kb(self.tap("m:ud"))
        self.assertIn("v0.55.1", text)
        self.assertIn("m:uq:u", b)
        self.assertIn("m:uq:r", b)
        self.assertIn("m:menu", b)
        text, b = self.kb(self.tap("m:uq:u"))
        self.assertIn("v0.55.0 → v0.55.1", text)
        self.assertEqual(b, ["m:ug:u", "m:ud"], "confirm or back — nothing else")
        self.assertEqual(self.started, [], "a confirm screen starts nothing")
        out = self.tap("m:ug:u")
        self.assertEqual(self.started, [("update", "Telegram")])
        note = [c[1] for c in out if c[0] == "answerCallbackQuery"][-1]
        self.assertIn("итог пришлю", note["text"])


if __name__ == "__main__":
    unittest.main()
