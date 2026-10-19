"""Core pure logic: WAN blame ladder, IP-conflict classifier, time windows,
DHCP codec, SSDP/mDNS parsers, default gateway, durations, network map."""
import socket
import struct
import time
import unittest

from harness import cleanup, load_monitor


def lt(hh, mm, wday=0):
    """struct_time at hh:mm; wday 0=Mon."""
    return time.struct_time((2026, 10, 12 + wday, hh, mm, 0, wday, 285 + wday, 0))


class LogicTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m, cls.tmp = load_monitor()

    @classmethod
    def tearDownClass(cls):
        cleanup(cls.m, cls.tmp)

    # ------------------------------------------------------------ WAN ladder (D27)
    def test_wan_ladder(self):
        v = self.m.wan_verdicts
        up = {"gw": True, "inet": True, "dns": True}
        cases = [
            (up, dict(up, inet=False), ["ИНТЕРНЕТ УПАЛ", "провайдер"]),
            (up, dict(up, dns=False), ["СДОХ DNS"]),
            (up, dict(up, gw=False, inet=False, dns=False), ["ЛЁГ ШЛЮЗ"]),
        ]
        for prev, cur, needles in cases:
            out = v(prev, cur)
            self.assertEqual(len(out), 1, f"one cause, one message: {out}")
            for n in needles:
                self.assertIn(n, out[0])
        # the dead gateway explains everything behind it — no ISP/DNS blame
        out = " ".join(v(up, dict(up, gw=False, inet=False, dns=False)))
        self.assertNotIn("ИНТЕРНЕТ УПАЛ", out)
        self.assertNotIn("СДОХ DNS", out)
        # nothing flipped / unknown previous state
        self.assertEqual(v(up, up), [])
        self.assertEqual(v({}, dict(up, inet=False)), [], "no known previous state, no flip")
        # recoveries
        self.assertEqual(v(dict(up, inet=False), up), ["🌐 Интернет вернулся."])

    # ------------------------------------------------------------ conflict classifier (D25)
    def test_conflict_classifier(self):
        c = self.m.classify_conflict
        h = 3600
        self.assertIsNone(c([("aa", 0), ("bb", 5 * h)]), "one swap is a replacement, not a conflict")
        self.assertIsNone(c([("aa", 0), ("bb", 2 * h), ("aa", 9 * h)]),
                          "A→B→A over hours = DHCP reusing a freed address (10-15), not a conflict")
        flip = c([("aa", 0), ("bb", 900), ("aa", 1800)])
        self.assertTrue(flip["flip"], "back within the hour = both hold it at once")
        self.assertEqual(flip["macs"], ["aa", "bb"])
        churn = c([("aa", 0), ("bb", 600), ("cc", 1200)])
        self.assertTrue(churn["churn"])
        self.assertIsNone(c([("aa", 0)]))
        self.assertIsNone(c([("aa", 0), ("bb", 2 * h), ("cc", 5 * h)]), "slow distinct changes")

    # ------------------------------------------------------------ time windows (D29)
    def test_in_window(self):
        w = self.m.in_window
        self.assertTrue(w(lt(23, 0), "22:00", "08:00"))
        self.assertTrue(w(lt(7, 59), "22:00", "08:00"))
        self.assertFalse(w(lt(8, 0), "22:00", "08:00"), "end is exclusive")
        self.assertTrue(w(lt(22, 0), "22:00", "08:00"), "start is inclusive")
        self.assertFalse(w(lt(12, 0), "22:00", "08:00"))
        self.assertTrue(w(lt(13, 0), "12:00", "14:00"))
        self.assertFalse(w(lt(13, 0), "12:00", "12:00"), "empty window, not 24h")
        self.assertFalse(w(lt(13, 0), "25:00", "x"), "garbage = never")

    def test_maintenance_window_belongs_to_start_day(self):
        aw = self.m.window_active
        fri = {"from": "22:00", "to": "02:00", "days": [4]}
        self.assertTrue(aw(fri, lt(23, 0, wday=4)), "Friday evening")
        self.assertTrue(aw(fri, lt(1, 0, wday=5)), "01:00 Saturday is still Friday's window")
        self.assertFalse(aw(fri, lt(1, 0, wday=4)), "01:00 Friday belongs to Thursday")
        self.assertFalse(aw(dict(fri, enabled=False), lt(23, 0, wday=4)))
        self.assertTrue(aw({"from": "09:00", "to": "10:00", "days": []}, lt(9, 30, wday=6)), "[] = every day")

    # ------------------------------------------------------------ DHCP codec
    def test_dhcp_discover_shape(self):
        pkt = self.m.build_dhcp_discover(0x11223344, b"\x02\xaa\xbb\xcc\xdd\xee", "10.10.1.50")
        self.assertEqual(pkt[0], 1, "BOOTREQUEST")
        self.assertEqual(pkt[3], 1, "hops=1: we pose as a relay")
        self.assertEqual(pkt[4:8], b"\x11\x22\x33\x44")
        self.assertEqual(socket.inet_ntoa(pkt[24:28]), "10.10.1.50", "giaddr = us")
        self.assertEqual(pkt[236:240], b"\x63\x82\x53\x63")
        self.assertIn(b"\x35\x01\x01", pkt[240:], "DHCPDISCOVER")

    def offer(self, xid, server="10.10.1.1", yiaddr="10.10.1.77", mtype=2):
        p = bytearray(240)
        p[0] = 2
        p[4:8] = xid.to_bytes(4, "big")
        p[16:20] = socket.inet_aton(yiaddr)
        p[236:240] = b"\x63\x82\x53\x63"
        opts = b"\x00" + bytes([53, 1, mtype]) + bytes([54, 4]) + socket.inet_aton(server) + b"\xff"
        return bytes(p) + opts

    def test_dhcp_offer_parse(self):
        r = self.m.parse_dhcp_reply(self.offer(7), 7)
        self.assertEqual(r, {"yiaddr": "10.10.1.77", "server": "10.10.1.1", "type": 2})
        self.assertIsNone(self.m.parse_dhcp_reply(self.offer(7), 8), "someone else's transaction")
        self.assertIsNone(self.m.parse_dhcp_reply(b"\x02" + b"\x00" * 100, 7), "truncated")
        bad = bytearray(self.offer(7))
        bad[236] = 0
        self.assertIsNone(self.m.parse_dhcp_reply(bytes(bad), 7), "no magic cookie")
        self.assertEqual(self.m.parse_dhcp_reply(self.offer(7, mtype=5), 7)["type"], 5, "ACK typed, not OFFER")

    def test_dhcp_verdict(self):
        e = self.m.evaluate_dhcp
        self.assertEqual(e({"10.10.1.1": "x"}, []), ([], [], True), "first answer is learned")
        self.assertEqual(e({}, []), ([], [], False), "nothing to learn from silence")
        self.assertEqual(e({"10.10.1.1": "x", "10.10.1.66": "y"}, ["10.10.1.1"]), (["10.10.1.66"], [], False))
        self.assertEqual(e({}, ["10.10.1.1"]), ([], ["10.10.1.1"], False))

    # ------------------------------------------------------------ SSDP / mDNS
    def test_ssdp(self):
        notify = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                  b"SERVER: Linux/3.10 UPnP/1.0 HIKVISION/1.0\r\nNT: upnp:rootdevice\r\n"
                  b"LOCATION: http://10.10.1.64:80/desc.xml\r\n\r\n")
        r = self.m.parse_ssdp(notify)
        self.assertIn("HIKVISION", r["server"])
        self.assertEqual(r["location"], "http://10.10.1.64:80/desc.xml")
        self.assertIsNone(self.m.parse_ssdp(b"GARBAGE"))
        self.assertIsNone(self.m.parse_ssdp(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"),
                          "a search from someone else is not a device announcing itself")

    def test_mdns_a_record_with_compression(self):
        name = b"\x07printer\x05local\x00"
        hdr = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
        rr1 = name + struct.pack(">HHIH", 1, 0x8001, 120, 4) + socket.inet_aton("10.10.1.40")
        ptr = b"\xc0\x0c"                       # compression pointer back to "printer.local"
        rr2 = ptr + struct.pack(">HHIH", 16, 1, 120, 3) + b"\x02ok"   # TXT, ignored
        out = self.m.parse_mdns_names(hdr + rr1 + rr2)
        self.assertEqual(out, [("printer", "10.10.1.40")])
        self.assertEqual(self.m.parse_mdns_names(b"\x00" * 5), [])
        loop = hdr[:6] + b"\x00\x01\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00" * 10
        self.assertEqual(self.m.parse_mdns_names(loop), [], "self-pointing name doesn't hang")

    # ------------------------------------------------------------ misc
    def test_default_gateway(self):
        win = ("IPv4 таблица маршрута\n=====\nАктивные маршруты:\n"
               "Сетевой адрес           Маска сети      Адрес шлюза       Интерфейс  Метрика\n"
               "          0.0.0.0          0.0.0.0     10.10.1.1     10.10.1.50     25\n")
        self.assertEqual(self.m.parse_gateway(win), "10.10.1.1")
        self.assertEqual(self.m.parse_gateway("default via 10.10.1.1 dev eth0\n"), "10.10.1.1")
        self.assertEqual(self.m.parse_gateway("nothing here"), "")

    def test_fmt_duration(self):
        f = self.m.fmt_duration
        self.assertEqual([f(5), f(125), f(3 * 3600 + 120), f(2 * 86400 + 3600)],
                         ["5с", "2м 5с", "3ч 2м", "2д 1ч"])

    def test_os_and_vendor(self):
        self.assertEqual(self.m.lookup_vendor(""), "")
        self.assertEqual(self.m.mac_is_random("02:00:00:00:00:01"), True)

    # ------------------------------------------------------------ network map (D32-D34)
    def test_topology_tree(self):
        hosts = [{"id": "s09", "name": "S09", "host": "10.10.1.27", "type": "host"},
                 {"id": "vm", "name": "S08", "host": "10.10.1.24", "type": "host", "parent": "s09"},
                 {"id": "cam", "name": "cam", "host": "10.10.2.64", "type": "ping", "parent": "sw1"}]
        states = {"s09": {"status": "up"}, "vm": {"status": "down"}, "cam": {"status": "up"}}
        topo = self.m.build_topology(hosts, states, {"cam"}, {}, [], {}, "10.10.1.1",
                                     switches=[{"id": "sw1", "name": "Свитч-2", "parent": ""}])
        nodes = {n["id"]: n for n in topo["nodes"]}
        edges = {tuple(e) for e in topo["edges"]}
        self.assertEqual(nodes["gw"]["kind"], "gateway")
        self.assertIn(("host:s09", "host:vm"), edges, "VM hangs under its Hyper-V host")
        self.assertIn(("sw:sw1", "host:cam"), edges, "camera under the manual switch")
        self.assertTrue(any(n["kind"] == "subnet" for n in topo["nodes"]))
        again = self.m.build_topology(hosts, states, {"cam"}, {}, [], {}, "10.10.1.1",
                                      switches=[{"id": "sw1", "name": "Свитч-2", "parent": ""}])
        self.assertEqual(topo, again, "deterministic")


if __name__ == "__main__":
    unittest.main()


class RenameTest(unittest.TestCase):
    """0.58: «Server Signal Desk» -> «Филин» on update, a custom name survives."""

    def test_old_default_renamed_custom_kept(self):
        import json
        import os
        m, tmp = load_monitor()
        try:
            for before, after in (("Server Signal Desk", "Филин"), ("Офис на Абая", "Офис на Абая")):
                with open(m.CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump({"app_name": before}, f, ensure_ascii=False)
                m.load_config()
                self.assertEqual(m.cfg("app_name"), after)
        finally:
            cleanup(m, tmp)
