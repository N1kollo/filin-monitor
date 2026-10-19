"""v0.54: «Видео» — which camera sits on which recorder, is it answering, a still
frame on demand. Office facts behind the cases (10-15): XVRs have analog inputs
with no IP; one camera (.241) was found on three recorders at once."""
import json
import threading
import unittest
import urllib.error
import urllib.request

from harness import cleanup, load_monitor

JPEG = b"\xff\xd8\xff\xe0frame"


def cam(ch, ip, name=""):
    return {"channel": ch, "name": name, "ip": ip, "enabled": True, "state": "", "analog": False}


class VideoTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        self.m.nvr_config = lambda: ({
            "10.0.2.11": {"name": "Объект 1", "user": "v", "password": "p", "path": "x"},
            "10.0.2.12": {"name": "Объект 6", "user": "v", "password": "p", "path": "x"},
        }, 1.0)

    def tearDown(self):
        cleanup(self.m, self.tmp)

    def test_xvr_analog_channels(self):
        raw = {"type": {"type": "XVR"},
               "remote": {"table.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_4.Address": "10.0.2.50"},
               "titles": {f"table.ChannelTitle[{i}].Name": t for i, t in
                          enumerate(["CAM 1", "hol", "CAM 3", "CAM 4", "ipcam", "Кан 6", "Кан 7"])}}
        cams = self.m.parse_nvr(raw)["cameras"]
        self.assertEqual([(c["channel"], c["analog"]) for c in cams],
                         [(1, True), (2, True), (3, True), (4, True), (5, False)],
                         "titles past the first IP channel are empty slots, not cameras")
        self.assertEqual(cams[1]["name"], "hol")
        only_analog = self.m.parse_nvr({"type": {"type": "DHI-XVR5216AN-S2"},
                                        "titles": {"table.ChannelTitle[0].Name": "a", "table.ChannelTitle[1].Name": "b"}})
        self.assertEqual(len(only_analog["cameras"]), 2)
        nvr = self.m.parse_nvr({"type": {"type": "NVR"}, "titles": {"table.ChannelTitle[0].Name": "a"}})
        self.assertEqual(nvr["cameras"], [], "a plain NVR has no analog inputs")

    def test_view_dups_alive_orphans(self):
        m = self.m
        inv = {"10.0.2.11": {"ok": True, "model": "XVR", "disks": [{"Name": "/dev/sda", "State": "Success", "IsError": "false"}],
                             "cameras": [cam(17, "10.0.2.241"), {**cam(1, ""), "analog": True}]},
               "10.0.2.12": {"ok": True, "model": "NVR", "disks": [], "cameras": [cam(30, "10.0.2.241"), cam(1, "10.0.2.147")]}}
        m.video_refresh(probe=lambda ip: dict(inv[ip], sample={"x": 1}))
        m.video_ping(ping=lambda ip: ip != "10.0.2.147")
        m.GROUPS["cams"] = {"alive": ["10.0.2.11", "10.0.2.147", "10.0.2.241", "10.0.2.99"]}
        v = m.video_view()
        self.assertEqual([n["name"] for n in v["nvrs"]], ["Объект 1", "Объект 6"])
        o1 = v["nvrs"][0]
        self.assertEqual(o1["cameras"][0]["also"], ["Объект 6 · канал 30"])
        self.assertIsNone(o1["cameras"][1]["alive"], "analog: no IP, no ping verdict")
        self.assertFalse(v["nvrs"][1]["cameras"][1]["alive"])
        self.assertEqual(o1["disks"], [{"name": "/dev/sda", "state": "Success", "error": False}])
        self.assertEqual(v["orphans"], ["10.0.2.99"])
        self.assertNotIn("sample", json.dumps(v))

    def test_no_orphans_before_inventory(self):
        self.m.GROUPS["cams"] = {"alive": ["10.0.2.5", "10.0.2.6"]}
        self.assertEqual(self.m.video_view()["orphans"], [], "nothing polled yet")
        self.m.video_refresh(probe=lambda ip: {"ok": True, "cameras": [cam(1, "10.0.2.5")]} if ip.endswith(".11")
                             else {"ok": False, "error": "timed out"})
        self.assertEqual(self.m.video_view()["orphans"], [], "Объект 6 never answered — its cameras would look orphaned")

    def test_silent_probe_keeps_inventory_end_to_end(self):
        m = self.m
        m.video_refresh(probe=lambda ip: {"ok": True, "cameras": [cam(1, "10.0.2.5")]})
        m.dahua_get = lambda *a, **k: (_ for _ in ()).throw(OSError("timed out"))
        m.video_refresh()
        n = m.video_view()["nvrs"][0]
        self.assertEqual((n["ok"], len(n["cameras"])), (False, 1), "last known cameras stay, marked stale")

    def test_unreachable_nvr_keeps_last_inventory(self):
        m = self.m
        m.video_refresh(probe=lambda ip: {"ok": True, "cameras": [cam(1, "10.0.2.5")]})
        m.video_refresh(probe=lambda ip: {"ok": False, "error": "timed out"})
        n = m.video_view()["nvrs"][0]
        self.assertEqual((n["ok"], n["error"], len(n["cameras"])), (False, "timed out", 1))

    def test_snapshot_cached_and_auth_parks(self):
        m = self.m
        calls = []

        def get(ip, uri, u, p, timeout=8, raw=False):
            calls.append(uri)
            return 200, JPEG, True
        m.dahua_get = get
        self.assertEqual(m.nvr_snapshot("10.0.2.11", 3), (JPEG, None))
        self.assertEqual(calls, ["/cgi-bin/snapshot.cgi?channel=3"])
        m.nvr_snapshot("10.0.2.11", 3)
        self.assertEqual(len(calls), 1, "a frame younger than 1.5 s is reused")
        m.dahua_get = lambda *a, **k: (200, b"<html>", True)
        self.assertIn("кадра нет", m.nvr_snapshot("10.0.2.12", 1)[1])
        m.dahua_get = lambda *a, **k: (401, b"", True)
        self.assertIn("отклонён", m.nvr_snapshot("10.0.2.12", 2)[1])
        m.dahua_get = get
        self.assertIn("исправь nvr.json", m.nvr_snapshot("10.0.2.12", 3)[1], "parked until the file changes")
        self.assertEqual(len(calls), 1)


class VideoApiTest(unittest.TestCase):
    def setUp(self):
        self.m, self.tmp = load_monitor()
        m = self.m
        m.nvr_config = lambda: ({"10.0.2.11": {"name": "Объект 1", "user": "v", "password": "p", "path": "x"}}, 1.0)
        m.dahua_get = lambda *a, **k: (200, JPEG, True)
        self.srv = m.MonitorHTTPServer(("127.0.0.1", 0), m.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        cleanup(self.m, self.tmp)

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, r.headers.get("Content-Type"), r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers.get("Content-Type"), e.read()

    def test_snap_endpoint(self):
        code, ctype, body = self.get("/api/video/snap?nvr=10.0.2.11&ch=2")
        self.assertEqual((code, ctype, body), (200, "image/jpeg", JPEG))
        self.assertEqual(self.get("/api/video/snap?nvr=10.0.2.99&ch=2")[0], 400, "only recorders from nvr.json")
        self.assertEqual(self.get("/api/video/snap?nvr=10.0.2.11&ch=x")[0], 400)

    def test_video_endpoint(self):
        code, _, body = self.get("/api/video")
        d = json.loads(body)
        self.assertEqual((code, d["configured"], d["nvrs"]), (200, True, []))


if __name__ == "__main__":
    unittest.main()
