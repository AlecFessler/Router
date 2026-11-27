"""End-to-end matcher tests with a real router-shadow binary and synthetic Ethernet."""

from collections import defaultdict
from ipaddress import ip_address
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from readiness_feed import MAGIC, relay, timed_frames
from readiness_match import Decision, Matcher, Packet

ROOT = Path(__file__).resolve().parents[1]
CLIENT_MAC, LAN_MAC, WAN_MAC, GATEWAY_MAC = (bytes((2, 0, 0, 0, 0, n)) for n in (1, 2, 3, 4))
CLIENT, LAN, WAN, PEER = "192.168.86.123", "192.168.86.1", "198.51.100.4", "203.0.113.5"


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(word for word, in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def ethernet(dst, src, kind, body):
    return (dst + src + struct.pack("!H", kind) + body).ljust(60, b"\0")


def ip_frame(dst_mac, src_mac, src, dst, protocol, body, ttl):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 17, 0, ttl, protocol, 0,
                         ip_address(src).packed, ip_address(dst).packed)
    return ethernet(dst_mac, src_mac, 0x0800, header[:10] + struct.pack("!H", checksum(header))
                    + header[12:] + body)


def transport(proto, src, dst, sp, dp, payload, reply):
    addresses = ip_address(src).packed + ip_address(dst).packed
    if proto == 17:
        body = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
        offset = 6
    elif proto == 6:
        flags = 0x12 if reply else 0x02
        body = struct.pack("!HHIIBBHHH", sp, dp, 100 if reply else 500, 501 if reply else 0,
                           0x50, flags, 16384, 0, 0) + payload
        offset = 16
    else:
        body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, dp if reply else sp, 23) + payload
        offset = 2
    pseudo = addresses + struct.pack("!BBH", 0, proto, len(body)) if proto != 1 else b""
    value = checksum(pseudo + body) or (0xffff if proto == 17 else 0)
    return body[:offset] + struct.pack("!H", value) + body[offset+2:]


def pcap(path, records):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for millis, frame in sorted(records, key=lambda row: row[0]):
            out.write(struct.pack("<IIII", 1000 + millis // 1000, millis % 1000 * 1000, len(frame), len(frame)))
            out.write(frame)


class ReadinessTests(unittest.TestCase):
    def run_oracle(self, records):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text(json.dumps({
                "lan_ip": LAN, "lan_mac": LAN_MAC.hex(), "wan_ip": WAN, "wan_mask": "255.255.255.0",
                "wan_gateway": "198.51.100.1", "wan_gateway_mac": GATEWAY_MAC.hex(),
                "wan_mac": WAN_MAC.hex(), "clients": {CLIENT: CLIENT_MAC.hex()},
            }))
            run = root / "run"
            cmd = [sys.executable, ROOT / "tools/readiness_oracle.py", "--config", config, "--output", run,
                   "--engine", ROOT / "zig-out/bin/router-shadow", "--infer-google-drops"]
            for label in ("lan", "wan-in", "wan-out"):
                path = root / (label + ".pcap")
                pcap(path, records[label])
                cmd.extend(("--" + label + "-pcap", path))
            subprocess.run(cmd, check=True, timeout=10)
            return (json.loads((run / "summary.json").read_text())["counts"],
                    (run / "unhandled.log").read_text(), (run / "service.log").read_text())

    def test_tcp_udp_and_icmp_through_distinct_nat_ports(self):
        records = defaultdict(list)
        for index, proto in enumerate((6, 17, 1)):
            base = 100 * index
            inside, outside, remote = 21234 + index, 45000 + index, 5399
            for label, at, macs, ips, ports, reply, ttl in (
                ("lan", 0, (LAN_MAC, CLIENT_MAC), (CLIENT, PEER), (inside, remote), False, 64),
                ("wan-out", 2, (GATEWAY_MAC, WAN_MAC), (WAN, PEER), (outside, remote), False, 63),
                ("wan-in", 4, (WAN_MAC, GATEWAY_MAC), (PEER, WAN), (remote, outside), True, 51),
                ("lan", 6, (CLIENT_MAC, LAN_MAC), (PEER, CLIENT), (remote, inside), True, 50),
            ):
                payload = b"" if proto == 6 else b"readiness fixture"
                body = transport(proto, *ips, *ports, payload, reply)
                frame = ip_frame(*macs, *ips, proto, body, ttl)
                records[label].append((base + at, frame))
        local_body = transport(1, CLIENT, LAN, 21333, 0, b"local echo", False)
        records["lan"].append((400, ip_frame(LAN_MAC, CLIENT_MAC, CLIENT, LAN, 1, local_body, 64)))
        local_reply = transport(1, LAN, CLIENT, 0, 21333, b"local echo", True)
        records["lan"].append((402, ip_frame(CLIENT_MAC, LAN_MAC, LAN, CLIENT, 1, local_reply, 64)))
        counts, unhandled, _ = self.run_oracle(records)
        self.assertEqual(counts.get("both_forwarded"), 6, counts)
        self.assertEqual(counts.get("both_answered"), 1, counts)
        self.assertEqual(unhandled, "")

    def test_unhandled_drop_difference_ambiguity_and_unknown_state(self):
        records = defaultdict(list)

        def udp(label, at, addresses, ports, data, ttl):
            macs = {"wan-out": (GATEWAY_MAC, WAN_MAC), "wan-in": (WAN_MAC, GATEWAY_MAC)}
            macs["lan"] = ((LAN_MAC, CLIENT_MAC) if addresses[0] == CLIENT else (CLIENT_MAC, LAN_MAC))
            body = transport(17, *addresses, *ports, data, label == "wan-in")
            records[label].append((at, ip_frame(*macs[label], *addresses, 17, body, ttl)))

        records["lan"].append((10, ip_frame(LAN_MAC, CLIENT_MAC, CLIENT, PEER, 99, b"fixture", 64)))
        records["wan-out"].append((12, ip_frame(GATEWAY_MAC, WAN_MAC, WAN, PEER, 99, b"fixture", 63)))
        udp("lan", 20, (CLIENT, PEER), (25000, 5555), b"unobserved", 64)
        udp("lan", 30, (CLIENT, PEER), (25000, 5555), b"different ttl", 64)
        udp("wan-out", 34, (WAN, PEER), (45000, 5555), b"different ttl", 62)
        udp("wan-in", 40, (PEER, WAN), (5555, 49000), b"previous flow", 64)
        udp("lan", 42, (PEER, CLIENT), (5555, 26000), b"previous flow", 63)
        for at, port in ((50, 26001), (51, 26002)):
            udp("lan", at, (CLIENT, PEER), (port, 5555), b"ambiguous", 64)
        udp("wan-out", 52, (WAN, PEER), (49001, 5555), b"ambiguous", 63)
        udp("wan-out", 350, (WAN, PEER), (49002, 5555), b"coverage", 63)
        udp("wan-out", 5000, (WAN, PEER), (49002, 5555), b"after match window", 63)
        counts, unhandled, service = self.run_oracle(records)
        self.assertEqual(counts.get("google_forwarded_shadow_dropped"), 1, counts)
        self.assertEqual(counts.get("forwarded_differently"), 1, counts)
        self.assertEqual(counts.get("inconclusive_ambiguous"), 2, counts)
        self.assertEqual(counts.get("google_forwarded_nat_state_unknown"), 1, counts)
        self.assertEqual(counts.get("shadow_forwarded_google_likely_dropped"), 1, counts)
        self.assertIn("packet=1 ingress=lan IPv4", unhandled)
        self.assertIn("packet=1 ingress=lan IPv4", service)

    def test_reference_mapping_survives_a_shadow_drop(self):
        records = defaultdict(list)
        outside, inside, remote = 45001, 25001, 53
        for label, at, macs, ips, ports, reply, ttl in (
            ("lan", 0, (LAN_MAC, CLIENT_MAC), (CLIENT, PEER), (inside, remote), False, 1),
            ("wan-out", 2, (GATEWAY_MAC, WAN_MAC), (WAN, PEER), (outside, remote), False, 63),
            ("wan-in", 4, (WAN_MAC, GATEWAY_MAC), (PEER, WAN), (remote, outside), True, 51),
            ("lan", 6, (CLIENT_MAC, LAN_MAC), (PEER, CLIENT), (remote, inside), True, 50),
            ("wan-in", 10, (WAN_MAC, GATEWAY_MAC), (PEER, WAN), (remote, 65000), True, 51),
        ):
            body = transport(17, *ips, *ports, b"forwarding fixture", reply)
            records[label].append((at, ip_frame(*macs, *ips, 17, body, ttl)))
        counts, _, _ = self.run_oracle(records)
        self.assertEqual(counts.get("google_forwarded_shadow_answered"), 1, counts)
        self.assertEqual(counts.get("google_forwarded_shadow_no_mapping"), 1, counts)
        self.assertEqual(counts.get("unscoped_wan"), 1, counts)

    def test_peer_policy_only_counts_when_observed_on_both_sides(self):
        records = defaultdict(list)
        other_peer = "203.0.113.6"
        for label, at, macs, ips, ports, reply, ttl in (
            ("lan", 0, (LAN_MAC, CLIENT_MAC), (CLIENT, PEER), (25001, 53), False, 64),
            ("wan-out", 2, (GATEWAY_MAC, WAN_MAC), (WAN, PEER), (45001, 53), False, 63),
            ("wan-in", 4, (WAN_MAC, GATEWAY_MAC), (other_peer, WAN), (53, 45001), True, 51),
            ("lan", 6, (CLIENT_MAC, LAN_MAC), (other_peer, CLIENT), (53, 25001), True, 50),
        ):
            body = transport(17, *ips, *ports, b"peer filter fixture", reply)
            records[label].append((at, ip_frame(*macs, *ips, 17, body, ttl)))
        counts, _, _ = self.run_oracle(records)
        self.assertEqual(counts.get("lan_both_forwarded"), 1, counts)
        self.assertEqual(counts.get("google_forwarded_shadow_dropped"), 1, counts)
        self.assertEqual(counts.get("wan_forwarding_disagreements"), 1, counts)

    def test_ipv6_forwarding_is_observed_even_if_shadow_lacks_a_handler(self):
        records = defaultdict(list)
        src, dst = (ip_address(addr).packed for addr in ("2001:4860::1", "2606:4700::1111"))
        for label, at, macs, ttl in (
            ("lan", 0, (LAN_MAC, CLIENT_MAC), 64),
            ("wan-out", 2, (GATEWAY_MAC, WAN_MAC), 63),
        ):
            header = struct.pack("!IHBB16s16s", 0x60000000, 8, 58, ttl, src, dst)
            records[label].append((at, ethernet(*macs, 0x86dd, header + b"v6 test!")))
        counts, unhandled, _ = self.run_oracle(records)
        self.assertEqual(counts.get("google_forwarded_shadow_dropped"), 1, counts)
        self.assertEqual(counts.get("unhandled"), 1, counts)
        self.assertIn("ingress=lan Ethernet", unhandled)

    def test_gro_detection_uses_declared_ip_size(self):
        # An untagged 1515-byte frame exceeds an MTU of 1500. Comparing
        # Ethernet length against a double-tagged limit would miss it.
        packet = ip_frame(WAN_MAC, GATEWAY_MAC, PEER, WAN, 6, bytes(1481), 64)
        self.assertEqual(len(packet), 1515)
        self.assertEqual(Packet.parse(packet).network_length, 1501)

    def test_live_wan_drop_requires_loss_free_capture_window(self):
        packet = Packet.parse(ip_frame(LAN_MAC, CLIENT_MAC, CLIENT, PEER, 99, b"case", 64))
        for end_drops, expected in ((0, "shadow_forwarded_google_likely_dropped"),
                                    (1, "shadow_forwarded_google_unobserved")):
            with self.subTest(kernel_drops=end_drops):
                matcher = Matcher(3, 16, lambda *_: None, True, live=True)
                matcher.output(None, 1, packet, "wan")
                matcher.output(None, 3, packet, "wan")
                matcher.capture_stats(1, 0)
                matcher.capture_stats(3, end_drops)
                decision = Decision(1, 2, "lan", packet, ("transit", "lan", packet.key("lan")),
                                    "transit", outcome="forwarded")
                matcher.input(decision)
                matcher.advance(5)
                self.assertEqual(matcher.counts[expected], 1)

    def test_lan_relay_calibrates_and_returns_pcap_frame(self):
        actual_frame = ethernet(LAN_MAC, CLIENT_MAC, 0x0800, b"feed fixture")
        results = []
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "lan.pcap"
            pcap(path, [(123, actual_frame)])
            client, server = socket.socketpair()
            with client, server:
                client.settimeout(3)
                server.settimeout(3)

                def receive():
                    with server.makefile("rb") as stream:
                        self.assertEqual(stream.read(4), MAGIC)
                        results.extend(timed_frames(server, stream))

                worker = Thread(target=receive)
                worker.start()
                with path.open("rb") as stream:
                    relay(client, stream)
                client.shutdown(socket.SHUT_WR)
                worker.join(3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(results[0][0], "clock")
        self.assertLess(results[0][1][1], 25_000_000)
        self.assertEqual(results[1][0], "frame")
        self.assertAlmostEqual(results[1][1][0], 1000.123, places=2)
        self.assertEqual(results[1][1][1], actual_frame)

    def test_udp_translation_keeps_checksum_valid(self):
        body = transport(17, PEER, WAN, 123, 44999, b"under test", True)
        original = Packet.parse(ip_frame(WAN_MAC, GATEWAY_MAC, PEER, WAN, 17, body, 63))
        translated = Packet.parse(original.translate(6432))
        pseudo = translated.src + translated.dst + struct.pack("!BBH", 0, 17, len(body))
        self.assertEqual(translated.dport, 6432)
        self.assertEqual(checksum(pseudo + translated.frame[translated.transport:translated.transport+len(body)]), 0)


if __name__ == "__main__":
    unittest.main()
