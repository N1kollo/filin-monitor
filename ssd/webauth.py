"""Dashboard password gate: PBKDF2 hashes, signed sessions, login throttle."""

import base64
import hashlib
import hmac
import secrets
import threading
import time

from . import core


# ----------------------------------------------------------------------------
# Authentication — optional password gate. All stdlib: PBKDF2 password hashing
# + HMAC-signed stateless session cookie. Enable via:  python monitor.py --set-password
# ----------------------------------------------------------------------------

_PBKDF_ROUNDS = 200_000


def auth_enabled():
    a = core.cfg("auth", {}) or {}
    return bool(a.get("enabled")) and bool(a.get("password_hash"))


def hash_password(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), _PBKDF_ROUNDS).hex()


def verify_password(pw):
    a = core.cfg("auth", {}) or {}
    salt, stored = a.get("salt", ""), a.get("password_hash", "")
    if not salt or not stored:
        return False
    return hmac.compare_digest(hash_password(pw, salt), stored)


def make_session(username, days=7):
    a = core.cfg("auth", {}) or {}
    secret = a.get("secret", "")
    # iat travels inside the payload so `session_epoch` can invalidate every
    # token issued before a given moment — that's what logout-everywhere is.
    # Clamping to the epoch matters: a password change bumps the epoch and then
    # immediately mints a cookie for the caller, and an iat below the epoch
    # would make that brand-new cookie dead on arrival.
    now = max(int(time.time()), int(a.get("session_epoch", 0)))
    payload = f"{username}|{now}|{now + days * 86400}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def check_session(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, iat, exp, sig = raw.rsplit("|", 3)
        a = core.cfg("auth", {}) or {}
        secret = a.get("secret", "")
        if not secret:
            return False
        good = hmac.new(secret.encode(), f"{username}|{iat}|{exp}".encode(),
                        hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig):
            return False
        return int(exp) > time.time() and int(iat) >= int(a.get("session_epoch", 0))
    except Exception:
        return False


def _bump_epoch(a):
    """Next session epoch — strictly above the previous one.

    Not just `now + 1`: make_session clamps a fresh token's iat up to the
    current epoch, so two bumps inside the same second would land on the same
    value and the older token would still validate. Monotonic by construction.
    """
    a["session_epoch"] = max(int(time.time()), int(a.get("session_epoch", 0))) + 1
    return a["session_epoch"]


def revoke_all_sessions():
    """Logout everywhere: every token minted up to now stops validating."""
    with core.CONFIG_LOCK:
        _bump_epoch(core.CONFIG.setdefault("auth", {}))
        core.save_config()


def set_password(user, pw):
    """Shared by the CLI and POST /api/auth/set.

    Rotating `secret` on every password change is the point: without it a
    leaked cookie outlives the password it was issued against for a full week.
    """
    salt = secrets.token_hex(16)
    with core.CONFIG_LOCK:
        a = core.CONFIG.setdefault("auth", {})
        a["enabled"] = True
        a["username"] = user
        a["salt"] = salt
        a["password_hash"] = hash_password(pw, salt)
        a["secret"] = secrets.token_hex(32)
        _bump_epoch(a)
        core.save_config()


# Login throttle: without it the gate is a free brute-force target for anyone
# on the LAN or the tailnet. Per-IP, in memory — a restart clears it, which is
# fine (a restart needs physical or admin access anyway).
_LOGIN_FAILS: dict = {}


_LOGIN_LOCK = threading.Lock()


_LOGIN_MAX_FAILS = 5


_LOGIN_WINDOW = 900  # 15 min


def login_blocked(ip):
    with _LOGIN_LOCK:
        fails, first = _LOGIN_FAILS.get(ip, (0, 0))
        if fails and time.time() - first > _LOGIN_WINDOW:
            _LOGIN_FAILS.pop(ip, None)
            return 0
        if fails >= _LOGIN_MAX_FAILS:
            return int(_LOGIN_WINDOW - (time.time() - first))
        return 0


def login_note_fail(ip):
    with _LOGIN_LOCK:
        fails, first = _LOGIN_FAILS.get(ip, (0, 0))
        if not fails or time.time() - first > _LOGIN_WINDOW:
            _LOGIN_FAILS[ip] = (1, time.time())
        else:
            _LOGIN_FAILS[ip] = (fails + 1, first)


def login_note_ok(ip):
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(ip, None)


def set_password_cli():
    import getpass

    core.load_config()
    print("== Настройка пароля для дашборда ==")
    user = input("Логин [admin]: ").strip() or "admin"
    pw = getpass.getpass("Пароль: ")
    pw2 = getpass.getpass("Повтори пароль: ")
    if not pw or pw != pw2:
        print("Пароли пусты или не совпадают. Отмена.")
        return
    set_password(user, pw)
    print(f"Готово. Авторизация включена (логин: {user}). Перезапусти монитор.")
