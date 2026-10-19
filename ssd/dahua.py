"""Dahua NVRs, read-only."""

import base64
import hashlib
import json
import os
import re
import secrets
from urllib import error as urlerror
from urllib import request as urlrequest

from . import core


# ----------------------------------------------------------------------------
# Dahua NVRs — read-only. Which camera sits on which recorder, channel state,
# disks. Credentials live in nvr.json next to the exe (never in config, never
# in the repo). Two hard rules:
#   * ONE authenticated attempt per request: urllib's digest handler silently
#     retries up to 5 times on a wrong password — exactly Dahua's lockout limit.
#   * a refused login parks that NVR until nvr.json changes — no hammering.
# Camera passwords are present in the NVR's RemoteDevice config; they are
# redacted before anything leaves this function.
# ----------------------------------------------------------------------------

NVR_AUTH_FAIL = {}   # ip -> mtime of nvr.json when the login was refused


def nvr_creds_paths():
    out = [os.path.join(core.app_dir(), "nvr.json"),
           os.path.join(os.path.expanduser("~"), ".config", "signal-desk", "nvr.json")]
    return [x for i, x in enumerate(out) if x not in out[:i]]


def _read_json_any(path):
    """Notepad on Russian Windows saves as ANSI (cp1251) or UTF-8 with BOM; a
    strict utf-8 read failed on both and the file looked "empty" (10-15)."""
    with open(path, "rb") as f:
        data = f.read()
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return json.loads(data.decode(enc))
        except (UnicodeDecodeError, ValueError):
            continue
    return json.loads(data.decode("utf-8"))     # raise the real JSON error


def _cred(x, *names):
    for n in names:
        if (x or {}).get(n):
            return str(x[n])
    return ""


def nvr_config_check():
    """What the monitor sees in each candidate nvr.json — booleans only, never
    the values. Answers «ты где ищешь и что видишь» without a screenshot."""
    out = []
    for path in nvr_creds_paths():
        row = {"path": path, "exists": os.path.exists(path)}
        if row["exists"]:
            try:
                raw = _read_json_any(path)
                d = raw.get("default") or {}
                row["default"] = {"user": bool(_cred(d, "user", "username", "login")),
                                  "password": bool(_cred(d, "password", "pass"))}
                row["nvrs"] = {ip: {"user": bool(_cred(x, "user", "username", "login") or row["default"]["user"]),
                                    "password": bool(_cred(x, "password", "pass") or row["default"]["password"])}
                               for ip, x in (raw.get("nvrs") or {}).items()}
                row["keys"] = sorted(raw.keys())
            except Exception as e:
                row["error"] = core.short_err(e)
        out.append(row)
    return out


def nvr_config():
    """{ip: {"name", "user", "password"}} from the first readable nvr.json, and its mtime."""
    for path in nvr_creds_paths():
        try:
            raw = _read_json_any(path)
            mtime = os.path.getmtime(path)
        except (OSError, ValueError):
            continue
        d = raw.get("default") or {}
        out = {}
        for ip, x in (raw.get("nvrs") or {}).items():
            out[ip] = {"name": (x or {}).get("name") or ip,
                       "user": _cred(x, "user", "username", "login") or _cred(d, "user", "username", "login"),
                       "password": _cred(x, "password", "pass") or _cred(d, "password", "pass"),
                       "path": path}
        return out, mtime
    return {}, 0.0


def _digest_header(www, user, pw, method, uri):
    p = dict(re.findall(r'(\w+)="?([^",]+)"?', www))
    realm, nonce, qop = p.get("realm", ""), p.get("nonce", ""), p.get("qop", "")
    md5 = lambda x: hashlib.md5(x.encode("utf-8")).hexdigest()
    ha1, ha2 = md5(f"{user}:{realm}:{pw}"), md5(f"{method}:{uri}")
    cnonce, nc = secrets.token_hex(8), "00000001"
    if "auth" in qop.split(","):
        resp = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        h = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
             f'qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp}"')
    else:
        resp = md5(f"{ha1}:{nonce}:{ha2}")
        h = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"'
    if p.get("opaque"):
        h += f', opaque="{p["opaque"]}"'
    return h


def dahua_get(ip, uri, user, pw, timeout=8, raw=False):
    """GET with exactly one authenticated attempt. -> (status, text, sent_creds).
    Old firmware (the kind that wants an IE plugin) speaks Basic, not Digest:
    10-15 .135 was «refused» twice without a single password ever sent."""
    url = f"http://{ip}{uri}"
    try:
        with urlrequest.urlopen(urlrequest.Request(url), timeout=timeout) as r:
            body = r.read()
            return r.status, body if raw else body.decode("utf-8", "replace"), False   # no auth required
    except urlerror.HTTPError as e:
        www = e.headers.get("WWW-Authenticate", "")
        e.close()
        if e.code != 401:
            return e.code, "", False
    if "digest" in www.lower():
        auth = _digest_header(www, user, pw, "GET", uri)
    elif "basic" in www.lower():
        auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
    else:
        return 401, www[:60], False                  # unknown scheme: nothing sent
    req = urlrequest.Request(url, headers={"Authorization": auth})
    try:
        with urlrequest.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, body if raw else body.decode("utf-8", "replace"), True
    except urlerror.HTTPError as e:
        e.close()
        return e.code, "", True


def _kv(text):
    out = {}
    for line in text.splitlines():
        k, sep, v = line.strip().partition("=")
        if sep:
            out[k.strip()] = "***" if "password" in k.lower() else v.strip()
    return out


NVR_ENDPOINTS = {
    "type": "/cgi-bin/magicBox.cgi?action=getDeviceType",
    "remote": "/cgi-bin/configManager.cgi?action=getConfig&name=RemoteDevice",
    "titles": "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle",
    "state": "/cgi-bin/LogicDeviceManager.cgi?action=getCameraState&uniqueChannels[0]=-1",
    "disks": "/cgi-bin/storageDevice.cgi?action=getDeviceAllInfo",
}


def parse_nvr(raw):
    """Pure: {endpoint: kv} -> model, cameras by channel, disks. Firmware differs
    in key shape, so matching is by suffix, not by full path."""
    model = (raw.get("type") or {}).get("type", "")
    cams = {}
    for k, v in (raw.get("remote") or {}).items():
        m = re.match(r"table\.RemoteDevice\.(.+)\.(Address|Name|Enable|Port|DeviceType)$", k)
        if not m:
            continue
        dev = m.group(1)
        ch = re.search(r"(\d+)$", dev)
        key = int(ch.group(1)) if ch else dev
        cams.setdefault(key, {})[m.group(2)] = v
    titles = {}
    for k, v in (raw.get("titles") or {}).items():
        m = re.match(r"table\.ChannelTitle\[(\d+)\]\.Name$", k)
        if m:
            titles[int(m.group(1))] = v
    states = {}
    st = raw.get("state") or {}
    for k, v in st.items():
        m = re.match(r"states\[(\d+)\]\.connectionState$", k)
        if m:
            chan = st.get(f"states[{m.group(1)}].channel", m.group(1))
            try:
                states[int(chan)] = v
            except ValueError:
                pass
    cameras = []
    real = set()
    for key, c in sorted(cams.items(), key=lambda kv: (isinstance(kv[0], str), kv[0])):
        addr = c.get("Address", "")
        if not addr or addr in ("0.0.0.0", "192.168.0.0"):
            continue
        chn = key if isinstance(key, int) else None
        if chn is not None:
            real.add(chn)
        cameras.append({"channel": (chn + 1) if chn is not None else None,
                        "name": titles.get(chn, "") if chn is not None else "",
                        "ip": addr, "enabled": c.get("Enable", "true").lower() != "false",
                        "state": states.get(chn, "") if chn is not None else "", "analog": False})
    # An XVR's analog inputs come first and have no RemoteDevice entry — only a
    # title. Titles past the first IP channel are empty IP slots, not cameras.
    if "XVR" in model.upper():
        first_ip = min(real) if real else None
        for i, t in titles.items():
            if i in real or (first_ip is not None and i >= first_ip):
                continue
            cameras.append({"channel": i + 1, "name": t, "ip": "", "enabled": True, "state": "", "analog": True})
    cameras.sort(key=lambda c: (c["channel"] is None, c["channel"] or 0))
    disks = {}
    for k, v in (raw.get("disks") or {}).items():
        m = re.match(r"list\.info\[(\d+)\]\.(?:Detail\[\d+\]\.)?(Name|State|TotalBytes|UsedBytes|IsError)$", k)
        if m:
            d = disks.setdefault(int(m.group(1)), {})
            f = m.group(2)
            if f in ("TotalBytes", "UsedBytes"):
                try:
                    d[f] = d.get(f, 0) + float(v)
                except ValueError:
                    pass
            else:
                d.setdefault(f, v)
    return {"model": model, "cameras": cameras, "disks": [disks[i] for i in sorted(disks)]}


def nvr_probe(ip):
    """One NVR, every endpoint once; stops at the first refused login."""
    conf, mtime = nvr_config()
    c = conf.get(ip)
    if not c:
        return {"ok": False, "error": f"{ip} нет в nvr.json (искал: {', '.join(nvr_creds_paths())})"}
    if not c["user"] or not c["password"]:
        miss = " и ".join(x for x, v in (("user", c["user"]), ("password", c["password"])) if not v)
        return {"ok": False, "error": f"в {c['path']} для {ip} пусто: {miss}", "check": nvr_config_check()}
    if NVR_AUTH_FAIL.get(ip) == mtime:
        return {"ok": False, "error": "логин уже отклонён — исправь nvr.json (новая попытка только после правки файла)"}
    raw, errors, keys = {}, {}, {}
    for name, uri in NVR_ENDPOINTS.items():
        try:
            code, text, sent = dahua_get(ip, uri, c["user"], c["password"])
        except Exception as e:
            errors[name] = core.short_err(e)
            continue
        if code == 401 and not sent:
            return {"ok": False, "error": f"регистратор просит неизвестную авторизацию ({text or 'без заголовка'}) — пароль не отправлял"}
        if code == 401:
            NVR_AUTH_FAIL[ip] = mtime
            return {"ok": False, "error": "логин отклонён регистратором — дальше не пробую (защита от блокировки)"}
        if code != 200:
            errors[name] = f"HTTP {code}"
            continue
        raw[name] = _kv(text)
        keys[name] = list(raw[name].items())[:25]   # for checking the parser on this firmware
    if not raw:
        # nothing answered: not "a recorder with 0 cameras" (10-15 19:11 the
        # camera segment lost power and the video tab wiped its inventory)
        first = next(iter(errors.values()), "нет ответа")
        return {"ok": False, "error": f"регистратор не отвечает ({first})", "errors": errors}
    NVR_AUTH_FAIL.pop(ip, None)
    out = parse_nvr(raw)
    out.update(ok=True, ip=ip, name=c["name"], errors=errors, sample=keys)
    return out
