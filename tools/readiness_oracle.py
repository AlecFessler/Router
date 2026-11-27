#!/usr/bin/env python3
"""Run a read-only router shadow against Ethernet captures or live inputs."""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
import heapq
from ipaddress import IPv4Address, IPv4Network, ip_address
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import pwd
import re
from pathlib import Path
from queue import Empty, Full, Queue
import signal
import socket
import struct
import subprocess
import threading
import time

from packet_sampler import PCAP_MAGIC, read_exact
from readiness_feed import MAGIC, MAX_UNCERTAINTY_NS, timed_frames
from readiness_match import ARP, ICMP, IPV4, TCP, UDP, Decision, Matcher, Packet, digest

LAN = "lan"
WAN_IN = "wan-in"
WAN_OUT = "wan-out"
MAX_FRAME = 16384


def mac(value):
    result = bytes.fromhex(value.replace(":", ""))
    if len(result) != 6:
        raise ValueError(f"invalid MAC: {value}")
    return result


@dataclass
class Config:
    lan_ip: IPv4Address
    lan_mac: bytes
    wan_ip: IPv4Address
    wan_mask: IPv4Address
    wan_gateway: IPv4Address
    wan_gateway_mac: bytes
    wan_mac: bytes
    clients: dict

    @classmethod
    def load(cls, path):
        data = json.loads(path.read_text())
        config = cls(
            IPv4Address(data["lan_ip"]), mac(data["lan_mac"]), IPv4Address(data["wan_ip"]),
            IPv4Address(data["wan_mask"]), IPv4Address(data["wan_gateway"]),
            mac(data["wan_gateway_mac"]), mac(data["wan_mac"]),
            {mac(addr): IPv4Address(ip).packed for ip, addr in data["clients"].items()},
        )
        lan = IPv4Network((config.lan_ip, 24), strict=False)
        wan = IPv4Network((config.wan_ip, str(config.wan_mask)), strict=False)
        if (not config.clients or any(IPv4Address(ip) not in lan or ip == config.lan_ip.packed
                                      for ip in config.clients.values())):
            raise ValueError("provide at least one client on the router's LAN /24")
        if config.wan_gateway not in wan or config.wan_gateway == config.wan_ip:
            raise ValueError("WAN gateway must be a distinct address on the WAN subnet")
        return config


def pcap_packets(stream, prefix=b""):
    rest = read_exact(stream, 24 - len(prefix))
    header = prefix + rest if rest is not None else None
    if header is None or header[:4] not in PCAP_MAGIC:
        raise ValueError("expected classic Ethernet pcap")
    endian = PCAP_MAGIC[header[:4]]
    if struct.unpack_from(endian + "I", header, 20)[0] & 0xffff != 1:
        raise ValueError("expected Ethernet link type")
    scale = 1e-9 if header[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
    while (record := read_exact(stream, 16)) is not None:
        seconds, subsecond, size, original = struct.unpack(endian + "IIII", record)
        if size > 1024 * 1024:
            raise ValueError("pcap frame exceeds 1 MiB")
        if size != original or size > MAX_FRAME:
            if read_exact(stream, size) is None:
                raise ValueError("truncated pcap packet")
            yield seconds + subsecond * scale, None
            continue
        frame = read_exact(stream, size)
        if frame is None:
            raise ValueError("truncated pcap packet")
        yield seconds + subsecond * scale, frame


class Engine:
    def __init__(self, path, config, out, log):
        self.proc = subprocess.Popen(
            [path, out, str(config.lan_ip), str(config.wan_ip), str(config.wan_mask),
             str(config.wan_gateway), config.lan_mac.hex(), config.wan_mac.hex()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.log_thread = stderr_thread(self.proc, log, "shadow")

    def exchange(self, command):
        try:
            self.proc.stdin.write(command)
            self.proc.stdin.flush()
            while (tag := self.proc.stdout.read(1)) != b"D":
                if tag not in (b"F", b"R", b"S", b"X", b"U", b"E", b"N"):
                    raise RuntimeError("shadow stopped or returned an invalid event")
                header = read_exact(self.proc.stdout, 10)
                if header is None:
                    raise RuntimeError("shadow ended in an event header")
                packet_id, length = struct.unpack("!QH", header)
                payload = read_exact(self.proc.stdout, length)
                if payload is None:
                    raise RuntimeError("shadow ended in an event payload")
                yield tag, packet_id, payload
        except BrokenPipeError as exc:
            raise RuntimeError("shadow stopped") from exc

    def close(self):
        try:
            self.proc.stdin.close()
            stop_process(self.proc, interrupt=False)
        finally:
            self.proc.stdout.close()
            self.log_thread.join(timeout=3)
            self.proc.stderr.close()


class Oracle:
    def __init__(self, config, engine, matcher):
        self.cfg = config
        self.engine = engine
        self.matcher = matcher
        self.packet_id = 0
        self.arp_refreshed = {}
        self.replay_arp("wan", config.wan_gateway.packed, config.wan_gateway_mac, float("-inf"))

    def command(self, command):
        for kind, packet_id, payload in self.engine.exchange(command):
            self.matcher.result(kind, packet_id, payload)

    def replay_arp(self, side, ip, addr, at):
        key = side, ip, addr
        if key not in self.arp_refreshed or at - self.arp_refreshed[key] >= 30:
            self.command(b"A" + side[0].upper().encode() + ip + addr)
            self.arp_refreshed[key] = at

    def shadow_port(self, packet_id, protocol, binding):
        inside, port = binding
        result = None
        for kind, event_id, body in self.engine.exchange(struct.pack("!cQB4sH", b"N", packet_id, protocol, inside, port)):
            if kind == b"N":
                result = struct.unpack("!H", body)[0]
            else:
                self.matcher.result(kind, event_id, body)
        return result

    def tick(self):
        self.command(b"T")

    def process(self, source, at, frame, mtu=None):
        self.matcher.advance(at)
        if frame is None:
            self.matcher.gap(at, f"{source}_truncated")
            return
        self.matcher.counts[f"{source}_frames"] += 1
        dst, src = frame[:6], frame[6:12]
        packet = Packet.parse(frame)
        if mtu is not None and packet.network_length > mtu:
            # GRO packets can exceed the MTU even when the Ethernet frame is
            # below the maximum for a double-tagged frame.
            self.matcher.gap(at, f"{source}_offload")
            return
        if source == LAN:
            if src in self.cfg.clients and (dst == self.cfg.lan_mac or dst[:1] and dst[0] & 1):
                self.receive("lan", at, packet)
            elif dst in self.cfg.clients and src == self.cfg.lan_mac:
                self.google_output("lan", at, packet)
        elif source == WAN_IN:
            if dst == self.cfg.wan_mac or dst == b"\xff" * 6:
                self.receive("wan", at, packet)
        elif src == self.cfg.wan_mac:
            self.google_output("wan", at, packet)

    @staticmethod
    def local_key(side, packet, reply=False):
        src, dst = (packet.dst, packet.src) if reply else (packet.src, packet.dst)
        if packet.arp_op == (2 if reply else 1):
            return "local", side, ARP, src, dst
        if packet.echo_type == (0 if reply else 8):
            return "local", side, ICMP, src, dst, packet.sport, packet.token[1:]
        return None

    def google_output(self, side, at, packet):
        cfg = self.cfg
        if side == "wan" and packet.ethertype == IPV4 and packet.src != cfg.wan_ip.packed:
            if packet.src and packet.src != b"\0" * 4:
                self.matcher.gap(at, "wan_address_changed")
            return
        router_ip = cfg.lan_ip if side == "lan" else cfg.wan_ip
        local = self.local_key(side, packet, reply=True) if packet.src == router_ip.packed else None
        if local is not None:
            self.matcher.output(local, at, packet, side)
        # An outbound echo reply can be either local or translated from the LAN.
        direction = "wan" if side == "lan" else "lan"
        self.matcher.output(("transit", direction, key) if (key := packet.key(direction)) else None,
                            at, packet, side)

    def receive(self, side, at, packet):
        cfg = self.cfg
        dst_mac, src_mac = packet.frame[:6], packet.frame[6:12]
        router_ip = cfg.lan_ip if side == "lan" else cfg.wan_ip
        mode = "transit"
        key = None
        binding = binding_source = shadow_port = None
        exact = True
        self.packet_id += 1
        state_known = True
        frame = packet.frame

        if side == "lan":
            self.replay_arp("lan", cfg.clients[src_mac], src_mac, at)
        self.replay_arp("wan", cfg.wan_gateway.packed, cfg.wan_gateway_mac, at)

        if packet.dst == router_ip.packed:
            key = self.local_key(side, packet)
            if key is not None:
                mode = "local"
        if packet.arp_op or (side == "lan" and (dst_mac != cfg.lan_mac or packet.dst == router_ip.packed)):
            if mode != "local":
                mode = "control"

        if side == "wan" and packet.ethertype == IPV4 and mode == "transit":
            if packet.dst != cfg.wan_ip.packed:
                mode = "control"
                if dst_mac == cfg.wan_mac and packet.dst:
                    self.matcher.gap(at, "wan_address_changed")
            elif packet.token is not None and packet.protocol in (TCP, UDP, ICMP):
                binding, binding_source, exact = self.matcher.lookup(packet, at)
                state_known = binding is not None
                if binding is not None:
                    shadow_port = self.shadow_port(self.packet_id, packet.protocol, binding)
                    if shadow_port is not None:
                        frame = packet.translate(shadow_port)

        if mode == "transit" and packet.key(side) is not None:
            key = "transit", side, packet.key(side)
        decision = Decision(self.packet_id, at, side, packet, key, mode, state_known,
                            binding=binding, binding_source=binding_source, shadow_port=shadow_port,
                            reference_mapping_exact=exact)
        self.matcher.input(decision)
        self.command(struct.pack("!cQH", side[0].upper().encode(), decision.id, len(frame)) + frame)


def stderr_thread(proc, log, label, receive_line=None):
    def drain():
        for entry in proc.stderr:
            line = entry.decode("utf-8", "replace").rstrip()
            log.info("%s %s", label, line)
            if receive_line is not None:
                receive_line(line)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def stop_process(proc, interrupt=True):
    if interrupt and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def offline(args, oracle):
    with ExitStack() as stack:
        def records(label, path):
            stream = stack.enter_context(path.open("rb"))
            offset = args.lan_clock_offset_ms / 1000 if label == LAN else 0
            return ((at + offset, label, frame) for at, frame in pcap_packets(stream))

        streams = [records(label, path) for label, path in
                   ((LAN, args.lan_pcap), (WAN_IN, args.wan_in_pcap), (WAN_OUT, args.wan_out_pcap))]
        for at, label, frame in heapq.merge(*streams, key=lambda event: event[0]):
            oracle.process(label, at, frame)


TCPDUMP_DROPS = re.compile(r"tcpdump: .*?, (\d+) packets? dropped by kernel")


def request_capture_stats(parent):
    # sudo may add a monitor process. Only signal our own tcpdump descendant
    # after it has installed its handlers and dropped privilege via -Z.
    pids = [parent]
    while pids:
        pid = pids.pop()
        proc = Path("/proc") / str(pid)
        try:
            pids.extend(map(int, (proc / "task" / str(pid) / "children").read_text().split()))
            if (proc / "comm").read_text().strip() == "tcpdump":
                uid = re.search(r"^Uid:\s+(\d+)", (proc / "status").read_text(), re.MULTILINE)
                if uid is not None and int(uid[1]) == os.getuid():
                    os.kill(pid, signal.SIGUSR1)
                    return
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def live(args, oracle, log, checkpoint, stop, lan_connected, stack):
    queue = Queue(maxsize=args.max_pending)
    interfaces = {WAN_IN: args.fiber, WAN_OUT: args.google}
    mtus = {label: int((Path("/sys/class/net") / name / "mtu").read_text())
            for label, name in interfaces.items()}
    mtus[LAN] = args.lan_mtu
    overflows = Counter()
    overflows_lock = threading.Lock()

    def enqueue(label, at, frame):
        try:
            queue.put_nowait((label, at, frame))
        except Full:
            with overflows_lock:
                overflows[label] += 1

    def reader(label, stream, prefix=b""):
        offset = args.lan_clock_offset_ms / 1000 if label == LAN else 0
        for at, frame in pcap_packets(stream, prefix):
            if stop.is_set():
                return
            enqueue(label, at + offset, frame)

    stats = Queue()
    capture_ready = threading.Event()
    google_capture = None

    def receive_wired_stats(line):
        if "listening on " in line:
            capture_ready.set()
        match = TCPDUMP_DROPS.search(line)
        if match is not None:
            stats.put((time.time(), int(match[1])))

    def wired(label, interface):
        user = pwd.getpwuid(os.getuid()).pw_name
        cmd = ["sudo", "-n", "--", "/usr/bin/tcpdump", "--immediate-mode", "-p", "-U",
               "-Z", user, "-i", interface, "-Q", "in", "-s", "0", "-w", "-",
               f"ether host {args.wan_mac} or ether broadcast"]
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))
        stack.callback(proc.stdout.close)
        stack.callback(proc.stderr.close)
        callback = receive_wired_stats if label == WAN_OUT and args.infer_google_drops else None
        log_thread = stderr_thread(proc, log, label, callback)
        stack.callback(log_thread.join, 3)
        stack.callback(stop_process, proc)

        def run():
            try:
                reader(label, proc.stdout)
                detail = f"capture ended with status {proc.wait(timeout=3)}"
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                detail = str(exc)
            if not stop.is_set():
                log.error("%s %s", label, detail)
                failures.put(label)
                stop.set()

        threading.Thread(target=run, daemon=True).start()
        return proc

    def wifi(listener):
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            lan_connected.set()
            log.info("LAN feed connected")
            try:
                with conn, conn.makefile("rb") as stream:
                    prefix = read_exact(stream, 4)
                    if prefix == MAGIC:
                        last_offset = None
                        for tag, values in timed_frames(conn, stream):
                            if stop.is_set():
                                return
                            if tag == "frame":
                                enqueue(LAN, *values)
                            else:
                                offset, uncertainty = values
                                reason = None
                                if uncertainty > MAX_UNCERTAINTY_NS:
                                    reason = "lan_clock_uncertain"
                                elif last_offset is not None and abs(offset - last_offset) > 50_000_000:
                                    reason = "lan_clock_step"
                                if reason is not None:
                                    with overflows_lock:
                                        overflows[reason] += 1
                                if reason is not None or last_offset is None:
                                    log.info("LAN clock offset %.3f ms, uncertainty %.3f ms",
                                             offset / 1e6, uncertainty / 1e6)
                                last_offset = offset
                    elif prefix is not None:
                        log.info("LAN feed uses configured fixed clock offset")
                        reader(LAN, stream, prefix)
            except (OSError, ValueError) as exc:
                log.error("LAN feed %s", exc)
            finally:
                lan_connected.clear()
            if not stop.is_set():
                log.warning("LAN feed disconnected")
                with overflows_lock:
                    overflows["lan_feed_disconnected"] += 1

    failures = Queue()
    listener = stack.enter_context(socket.socket())
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.lan_listen))
    listener.listen(1)
    listener.settimeout(1)
    threading.Thread(target=wifi, args=(listener,), daemon=True).start()
    for label, interface in interfaces.items():
        capture = wired(label, interface)
        if label == WAN_OUT:
            google_capture = capture
    log.info("listening for LAN pcap on 127.0.0.1:%d", args.lan_listen)
    print(f"Readiness capture started in {args.output}. Waiting for LAN pcap on port {args.lan_listen}.",
          flush=True)

    buffered = []
    sequence = 0
    next_tick = next_checkpoint = next_stats = time.monotonic()
    while not stop.is_set():
        while not stats.empty():
            oracle.matcher.capture_stats(*stats.get_nowait())
        try:
            label, at, frame = queue.get(timeout=0.05)
        except Empty:
            pass
        else:
            wall = time.time()
            if at < oracle.matcher.now or at > wall + args.reorder_seconds:
                oracle.matcher.gap(wall, f"{label}_clock_or_lag")
            else:
                heapq.heappush(buffered, (at, sequence, label, frame))
                sequence += 1
        watermark = time.time() - args.reorder_seconds
        while buffered and (buffered[0][0] <= watermark or len(buffered) > args.max_pending):
            at, _, label, frame = heapq.heappop(buffered)
            if at > watermark:
                oracle.matcher.gap(at, "reorder_limit")
            oracle.process(label, at, frame, mtus.get(label))
        now = time.monotonic()
        if now >= next_tick:
            with overflows_lock:
                for label, count in overflows.items():
                    reason = f"{label}_queue_drops" if label in (LAN, WAN_IN, WAN_OUT) else label
                    oracle.matcher.gap(time.time(), reason)
                    oracle.matcher.counts[reason] += count - 1
                overflows.clear()
            oracle.tick()
            if queue.empty():
                oracle.matcher.advance(watermark)
            next_tick = now + 0.2
        if args.infer_google_drops and capture_ready.is_set() and now >= next_stats:
            request_capture_stats(google_capture.pid)
            next_stats = now + 1
        if now >= next_checkpoint:
            checkpoint()
            next_checkpoint = now + 2
    if not failures.empty():
        raise RuntimeError(f"{failures.get()} capture failed; see service.log")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private run directory")
    parser.add_argument("--engine", type=Path, default=Path("zig-out/bin/router-shadow"))
    parser.add_argument("--lan-pcap", type=Path)
    parser.add_argument("--wan-in-pcap", type=Path)
    parser.add_argument("--wan-out-pcap", type=Path)
    parser.add_argument("--lan-listen", type=int, help="live LAN pcap over a localhost SSH tunnel")
    parser.add_argument("--lan-mtu", type=int, default=1500,
                        help="IP MTU of the LAN capture interface")
    parser.add_argument("--fiber", default="enp1s0f0")
    parser.add_argument("--google", default="enp1s0f1")
    parser.add_argument("--match-seconds", type=float, default=3)
    parser.add_argument("--transit-ms", type=float, default=250,
                        help="maximum delay for pairing a reference packet across the bridge")
    parser.add_argument("--reorder-seconds", type=float, default=1.5)
    parser.add_argument("--lan-clock-offset-ms", type=float, default=0)
    parser.add_argument("--max-pending", type=int, default=16384)
    parser.add_argument("--examples-per-result", type=int, default=20)
    parser.add_argument("--infer-google-drops", action="store_true",
                        help="report likely Google drops for clean WAN egress coverage")
    parser.add_argument("--retain-frames", action="store_true",
                        help="include full frames in bounded disagreement examples")
    args = parser.parse_args()
    files = (args.lan_pcap, args.wan_in_pcap, args.wan_out_pcap)
    if (args.lan_listen is None and not all(files)) or (args.lan_listen is not None and any(files)):
        parser.error("supply all three pcap paths or --lan-listen")
    if args.lan_listen is not None and not 1 <= args.lan_listen <= 65535:
        parser.error("invalid LAN listen port")
    if min(args.lan_mtu, args.match_seconds, args.transit_ms, args.reorder_seconds, args.max_pending,
           args.examples_per_result) <= 0 or args.transit_ms / 1000 >= args.match_seconds:
        parser.error("limits must be positive")
    if args.fiber == args.google or any(name != Path(name).name for name in (args.fiber, args.google)):
        parser.error("capture requires separate physical bridge interface names")
    return args



def packet_evidence(packet, include_frame):
    if packet is None:
        return None
    result = dict(frame_bytes=len(packet.frame), frame_hash=digest(packet.frame).hex(),
                  ethertype=f"0x{packet.ethertype:04x}", protocol=packet.protocol,
                  src=str(ip_address(packet.src)) if packet.src else None,
                  dst=str(ip_address(packet.dst)) if packet.dst else None,
                  sport=packet.sport, dport=packet.dport, hop_limit=packet.ttl)
    if include_frame:
        result["frame_hex"] = packet.frame.hex()
    return result


def main():
    args = parse_args()
    os.umask(0o077)
    cfg = Config.load(args.config)
    args.wan_mac = cfg.wan_mac.hex(":")
    args.output.mkdir(mode=0o700, parents=True)
    output = args.output.resolve()
    log = logging.getLogger("readiness")
    log.setLevel(logging.INFO)
    handler = RotatingFileHandler(output / "service.log", maxBytes=2 * 1024 * 1024, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    stop = threading.Event()
    lan_connected = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    samples = Counter()
    sample_groups = Counter()
    status = "running"

    with ExitStack() as stack:
        examples = stack.enter_context((output / "examples.jsonl").open("w", buffering=1))
        engine = Engine(args.engine.resolve(), cfg, output, log)
        stack.callback(engine.close)

        def report(decision, kind):
            if decision.error:
                scope = "unscoped_wan" if not decision.state_known and decision.google is None else "scoped"
                matcher.counts[f"handler_error_{scope}"] += 1
            if kind in ("unscoped_wan", "control") and not decision.unhandled and not decision.error:
                return
            if kind.startswith("both_") and not decision.unhandled and not decision.error:
                return
            if decision.coverage:
                category = "evidence", kind
            elif decision.unhandled:
                category = "unhandled", decision.packet.ethertype, decision.packet.protocol
            elif decision.error:
                category = "handler_error", scope, decision.error
            else:
                category = kind,
            # Keep separate quotas so unrelated background errors cannot hide
            # confirmed disagreements or uncommon unhandled protocols.
            group = category[0]
            if samples[category] >= args.examples_per_result or sample_groups[group] >= 200:
                return
            samples[category] += 1
            sample_groups[group] += 1
            include_frame = args.retain_frames and bool(decision.coverage or decision.unhandled)
            input_evidence = packet_evidence(decision.packet, include_frame)
            row = dict(id=decision.id, at=decision.at, ingress=decision.direction, comparison=kind,
                       shadow=decision.outcome, unhandled=decision.unhandled, error=decision.error,
                       coverage=decision.coverage, difference=decision.difference,
                       google_at=decision.google_at,
                       google=packet_evidence(decision.google, include_frame),
                       shadow_output=packet_evidence(decision.shadow or decision.shadow_reply, include_frame),
                       binding_packet_id=decision.binding_source.id if decision.binding_source else None,
                       shadow_nat_port=decision.shadow_port, **input_evidence)
            print(json.dumps(row), file=examples)

        matcher = Matcher(args.match_seconds, args.max_pending, report, args.infer_google_drops,
                          args.transit_ms / 1000, live=args.lan_listen is not None)

        def checkpoint():
            tmp = output / "summary.tmp"
            tmp.write_text(json.dumps(dict(status=status, updated_at=time.time(), pending=len(matcher.pending),
                                           lan_feed=("connected" if lan_connected.is_set() else "waiting")
                                           if args.lan_listen is not None else "offline",
                                           configured_clients=len(cfg.clients),
                                           counts=matcher.counts), indent=2) + "\n")
            tmp.replace(output / "summary.json")

        checkpoint()
        try:
            oracle = Oracle(cfg, engine, matcher)
            if args.lan_listen is None:
                offline(args, oracle)
            else:
                live(args, oracle, log, checkpoint, stop, lan_connected, stack)
            status = "stopped" if stop.is_set() else "finished"
        except KeyboardInterrupt:
            status = "stopped"
        except (OSError, RuntimeError, ValueError) as exc:
            status = "failed"
            log.error("%s", exc)
            raise SystemExit(f"readiness oracle: {exc}") from exc
        finally:
            stop.set()
            matcher.close()
            checkpoint()


if __name__ == "__main__":
    main()
