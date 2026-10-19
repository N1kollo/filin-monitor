"""Load the monitor in isolation for known-answer tests.

The monitor opens monitor.db and config.json next to monitor.py at import
time, so each test gets its own copy (monitor.py + ssd/) in a temp dir — the
developer's local config and DB are never touched. Telegram is stubbed at the
HTTP layer (_tg_call).

Tests talk to one object `m`, as they did when the monitor was one file. `m` is
a facade over the ssd package: reading `m.name` finds the module that defines
it, and `m.name = stub` patches it THERE — every caller writes
`owner.name(...)`, so the stub is what they all get."""
import ast
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import time
import types

# Captured before any test can monkeypatch them: tests patch m.time.sleep /
# m.threading.Thread, which ARE the global modules — restoring from
# "import time" afterwards just re-installs the patch for every later test.
REAL_SLEEP = time.sleep
REAL_THREAD = threading.Thread

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.join(ROOT, "ssd")


def _definitions():
    """name -> module that binds it at top level (parsed once per run)."""
    out = {}
    for f in sorted(os.listdir(PKG_DIR)):
        if not f.endswith(".py") or f == "__init__.py":
            continue
        mod = f[:-3]
        with open(os.path.join(PKG_DIR, f), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out[n.name] = mod
            elif isinstance(n, (ast.Assign, ast.AnnAssign)):
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    for x in ast.walk(t):
                        if isinstance(x, ast.Name):
                            out[x.id] = mod
    return out


DEFS = _definitions()


class Facade:
    def __init__(self, pkg):
        mods = {k: v for k, v in vars(pkg).items() if isinstance(v, types.ModuleType)
                and v.__name__.startswith(pkg.__name__ + ".")}
        object.__setattr__(self, "_pkg", pkg)
        object.__setattr__(self, "_mods", mods)
        object.__setattr__(self, "_extra", {})

    def _owner(self, name):
        mod = DEFS.get(name)
        return self._mods.get(mod) if mod else None

    def __getattr__(self, name):
        o = self._owner(name)
        if o is not None:
            return getattr(o, name)
        if name in self._extra:
            return self._extra[name]
        for mod in self._mods.values():          # stdlib modules: m.time, m.urlrequest, ...
            if name in vars(mod):
                return vars(mod)[name]
        raise AttributeError(name)

    def __setattr__(self, name, value):
        o = self._owner(name)
        if o is not None:
            setattr(o, name, value)
        else:
            self._extra[name] = value


def load_monitor(tmp=None, name="monitor_under_test"):
    tmp = tmp or tempfile.mkdtemp(prefix="ssd-test-")
    if not os.path.exists(os.path.join(tmp, "monitor.py")):
        shutil.copy(os.path.join(ROOT, "monitor.py"), os.path.join(tmp, "monitor.py"))
    if not os.path.exists(os.path.join(tmp, "ssd")):
        shutil.copytree(PKG_DIR, os.path.join(tmp, "ssd"),
                        ignore=shutil.ignore_patterns("__pycache__"))
    for k in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
        del sys.modules[k]
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(tmp, "ssd", "__init__.py"),
        submodule_search_locations=[os.path.join(tmp, "ssd")])
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[name] = pkg
    argv, sys.argv = sys.argv, ["monitor.py"]
    try:
        spec.loader.exec_module(pkg)
        importlib.import_module(name + ".app")      # loads every module in order
    finally:
        sys.argv = argv
    m = Facade(pkg)
    m.load_config()
    m.db_init()
    return m, tmp


def stub_telegram(m, fail_when=lambda method, params: False):
    """Record every Bot API call; fail the ones `fail_when` picks. It may return
    True (-> transient 502) or an HTTP status code to fail with."""
    calls = []

    def fake(method, params, timeout):
        calls.append((method, params))
        code = fail_when(method, params)
        if code:
            return None, f"Telegram API {502 if code is True else code}: test"
        return {"ok": True}, None
    m._tg_call = fake
    m.CONFIG["telegram"].update(bot_token="x", chat_id="42")
    return calls


def cleanup(m, tmp):
    time.sleep = REAL_SLEEP
    threading.Thread = REAL_THREAD
    try:
        m._db.close()
    except Exception:
        pass
    shutil.rmtree(tmp, ignore_errors=True)
