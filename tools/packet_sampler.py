#!/usr/bin/env python3
"""Collect bounded, TShark-classified pcap examples from the mini router.

Live: python tools/packet_sampler.py --capture-filter icmp
All traffic: python tools/packet_sampler.py
Offline: python tools/packet_sampler.py --pcap capture.pcap

Each run creates a private output directory containing one append-only
samples.pcap and a manifest.json mapping classes to output packet numbers.
Ctrl+C stops capture and writes a final checkpoint.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import getpass
import json
import os
import shlex
import signal
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

FIELDS = (
    "frame.number",
    "frame.protocols",
    "icmp.type",
    "icmp.code",
    "arp.opcode",
    "dhcp.option.dhcp",
    "dns.flags.response",
    "ip.proto",
    "eth.type",
    "tcp.flags",
    "vrrp.version",
    "vrrp.type",
    "ip.flags.mf",
    "ip.frag_offset",
)
GENERIC_LEAVES = {"data", "ethertype", "frame", "tcp.segments"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


@dataclass
class Bucket:
    seen: int = 0
    source_frames: list[int] = field(default_factory=list)
    output_frames: list[int] = field(default_factory=list)

    @property
    def kept(self) -> int:
        return len(self.output_frames)


def classify(values: dict[str, str]) -> str:
    path = values["frame.protocols"].split(":")
    vlan_depth = path.count("vlan")
    prefix = f"vlan{vlan_depth}/" if vlan_depth else ""
    leaf = next((p for p in reversed(path) if p and p not in GENERIC_LEAVES), "unknown")

    if "icmp" in path:
        return f"{prefix}icmpv4/type-{values['icmp.type'] or 'unknown'}/code-{values['icmp.code'] or 'unknown'}"
    if "dhcp" in path or "bootp" in path:
        return f"{prefix}dhcpv4/message-{values['dhcp.option.dhcp'] or 'unknown'}"
    if leaf == "arp":
        return f"{prefix}arp/opcode-{values['arp.opcode'] or 'unknown'}"
    if leaf == "dns":
        response = values["dns.flags.response"]
        return f"{prefix}dns/{'response' if response == 'True' else 'query' if response == 'False' else 'unknown'}"
    if leaf == "vrrp":
        return f"{prefix}vrrp/version-{values['vrrp.version'] or 'unknown'}/type-{values['vrrp.type'] or 'unknown'}"
    if values["ip.frag_offset"] not in ("", "0") or values["ip.flags.mf"] == "True":
        return f"{prefix}ipv4/fragment/proto-{values['ip.proto'] or 'unknown'}"
    if leaf == "tcp":
        flags = int(values["tcp.flags"] or "0", 0)
        if flags & 0x02:
            return f"{prefix}tcp/{'syn-ack' if flags & 0x10 else 'syn'}"
        if flags & 0x04:
            return f"{prefix}tcp/rst"
        if flags & 0x01:
            return f"{prefix}tcp/fin"
    if leaf in {"ip", "ipv6"}:
        return f"{prefix}{leaf}/proto-{values['ip.proto'] or 'unknown'}"
    if leaf == "eth":
        return f"{prefix}ether/type-{values['eth.type'] or 'unknown'}"
    return prefix + leaf


def read_exact(stream, length: int) -> bytes | None:
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if remaining == length:
                return None
            raise ValueError("pcap stream ended in the middle of a record")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Collector:
    def __init__(self, args, global_header: bytes):
        self.args = args
        self.global_header = global_header
        self.buckets: dict[str, Bucket] = {}
        self.total_seen = 0
        self.total_kept = 0
        self.bytes_retained = 0
        self.suppressed_classes = 0
        self.last_checkpoint = time.monotonic()
        self.last_refresh = 0.0
        self.output_file = (args.output / "samples.pcap").open("wb")
        self.output_file.write(global_header)

    def add(self, key: str, number: int, record: bytes) -> None:
        self.total_seen += 1
        bucket = self.buckets.get(key)
        if bucket is None:
            if len(self.buckets) >= self.args.max_classes:
                self.suppressed_classes += 1
            else:
                bucket = self.buckets[key] = Bucket()

        if bucket is not None:
            bucket.seen += 1
            if (
                bucket.kept < self.args.limit
                and self.bytes_retained + len(record) <= self.args.max_total_mib * 1048576
            ):
                self.output_file.write(record)
                self.total_kept += 1
                self.bytes_retained += len(record)
                bucket.source_frames.append(number)
                bucket.output_frames.append(self.total_kept)

        now = time.monotonic()
        if now - self.last_checkpoint >= self.args.checkpoint_seconds:
            self.checkpoint()
        if now - self.last_refresh >= self.args.refresh_seconds:
            self.render()

    def render(self, final: bool = False) -> None:
        if not sys.stderr.isatty():
            return
        width, height = shutil.get_terminal_size((80, 24))
        rows = [
            f"Packet sampler{' — stopped' if final else ''}",
            f"Seen {self.total_seen} | kept {self.total_kept} | "
            f"classes {len(self.buckets)} | pcap {self.bytes_retained / 1048576:.1f} MiB",
            f"Output: {self.args.output / 'samples.pcap'}",
        ]
        if getattr(self, "status_line", None):
            rows.append(self.status_line)
        rows.append("Class                                      seen    kept")
        extra_rows = 1 + bool(self.suppressed_classes)
        capacity = max(0, height - len(rows) - extra_rows - 1)
        classes = sorted(self.buckets.items(), key=lambda item: (item[1].seen, item[0]))
        for key, bucket in classes[:capacity]:
            rows.append(f"{key:<42} {bucket.seen:>8} {bucket.kept:>7}")
        hidden = max(0, len(classes) - capacity)
        if hidden > 0:
            rows.append(f"... {hidden} more classes in manifest.json")
        if self.suppressed_classes:
            rows.append(f"Packets beyond --max-classes: {self.suppressed_classes}")
        rows.append("Ctrl+C to stop and save" if not final else "Saved")
        sys.stderr.write("\x1b[H\x1b[J" + "\n".join(row[:width] for row in rows) + "\n")
        sys.stderr.flush()
        self.last_refresh = time.monotonic()

    def checkpoint(self) -> None:
        self.output_file.flush()
        os.fsync(self.output_file.fileno())
        manifest = {
            "source": str(self.args.pcap) if self.args.pcap else self.args.host,
            "interface": None if self.args.pcap else self.args.interface,
            "pcap": "samples.pcap",
            "total_seen": self.total_seen,
            "total_kept": self.total_kept,
            "bytes_retained": self.bytes_retained,
            "suppressed_class_packets": self.suppressed_classes,
            "classes": {
                key: {
                    "seen": bucket.seen,
                    "kept": bucket.kept,
                    "source_frame_numbers": bucket.source_frames,
                    "output_frame_numbers": bucket.output_frames,
                }
                for key, bucket in sorted(self.buckets.items())
            },
        }
        manifest.update(getattr(self, "extra_manifest", {}))
        target = self.args.output / "manifest.json"
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(manifest, indent=2) + "\n")
        os.replace(temporary, target)
        self.last_checkpoint = time.monotonic()

    def close(self) -> None:
        try:
            self.checkpoint()
        finally:
            self.output_file.close()
        self.render(final=True)


def process(stream, args) -> Collector:
    header = read_exact(stream, 24)
    if header is None or header[:4] not in PCAP_MAGIC:
        raise ValueError("source did not provide a classic pcap header")
    endian = PCAP_MAGIC[header[:4]]
    if struct.unpack_from(endian + "I", header, 20)[0] & 0xFFFF != 1:
        raise ValueError("only Ethernet pcaps are supported")

    collector = Collector(args, header)
    command = ["tshark", "-n", "-l", "-r", "-", "-T", "fields"]
    for name in FIELDS:
        command.extend(("-e", name))
    tshark_log = (args.output / "tshark.log").open("wb")
    tshark = None
    batch_count = 0

    def stop_tshark(graceful: bool) -> None:
        nonlocal tshark, batch_count
        if tshark is None:
            return
        proc = tshark
        tshark = None
        batch_count = 0
        if graceful:
            proc.stdin.close()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        if graceful and proc.returncode != 0:
            raise RuntimeError(f"TShark exited with status {proc.returncode}; see {args.output / 'tshark.log'}")

    completed = False
    try:
        while True:
            record_header = read_exact(stream, 16)
            if record_header is None:
                break
            included_len = struct.unpack_from(endian + "I", record_header, 8)[0]
            if included_len > args.max_packet_bytes:
                raise ValueError(f"packet exceeds --max-packet-bytes: {included_len}")
            payload = read_exact(stream, included_len)
            if payload is None:
                raise ValueError("pcap stream ended before packet data")
            record = record_header + payload
            if tshark is None:
                tshark = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=tshark_log, bufsize=0,
                )
            try:
                tshark.stdin.write(record if batch_count else header + record)
                tshark.stdin.flush()
            except BrokenPipeError as exc:
                raise RuntimeError("TShark stopped reading the pcap stream") from exc
            line = tshark.stdout.readline()
            if not line:
                raise RuntimeError("TShark stopped producing classification records")
            parts = line.decode("utf-8", "replace").rstrip("\r\n").split("\t")
            if len(parts) != len(FIELDS):
                raise ValueError(f"unexpected TShark field count: {len(parts)}")
            values = dict(zip(FIELDS, parts))
            collector.add(classify(values), collector.total_seen + 1, record)
            batch_count += 1
            if batch_count >= args.decoder_batch_packets:
                stop_tshark(graceful=True)
        stop_tshark(graceful=True)
        completed = True
    finally:
        try:
            if not completed:
                stop_tshark(graceful=False)
        finally:
            tshark_log.close()
            collector.close()
    return collector


@contextmanager
def live_stream(args):
    remote = [
        "sudo",
        "-S",
        "-k",
        "-p",
        "",
        "--",
        "/usr/bin/tcpdump",
        "-U",
        "-i",
        args.interface,
    ]
    if args.direction:
        remote.extend(("-Q", args.direction))
    remote.extend(("-s", "0", "-w", "-"))
    if args.capture_filter:
        remote.append(args.capture_filter)
    command = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-J",
        args.jump,
        args.host,
        shlex.join(remote),
    ]
    with (args.output / "capture.log").open("wb") as capture_log:
        ssh = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=capture_log, bufsize=0
        )
        terminated_by_us = False
        interrupted = False
        try:
            password = getpass.getpass(f"{args.host} sudo password: ")
            ssh.stdin.write((password + "\n").encode())
            ssh.stdin.close()
            del password
            yield ssh.stdout
        except KeyboardInterrupt:
            interrupted = True
            raise
        finally:
            if ssh.poll() is None:
                terminated_by_us = True
                ssh.terminate()
            try:
                ssh.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ssh.kill()
                ssh.wait()
        if ssh.returncode != 0 and not (terminated_by_us or interrupted):
            raise RuntimeError(
                f"SSH/capture exited with status {ssh.returncode}; "
                f"see {args.output / 'capture.log'}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pcap", type=Path, help="read a local classic pcap instead of capturing live"
    )
    parser.add_argument("--host", default="alec@192.168.1.104")
    parser.add_argument("--jump", default="alecfessler@192.168.86.106")
    parser.add_argument("--interface", default="br-wan")
    parser.add_argument(
        "--direction",
        choices=("in", "out"),
        help="tcpdump direction on a physical interface",
    )
    parser.add_argument(
        "--capture-filter", default="", help="tcpdump capture filter, e.g. icmp"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="new output directory; defaults to ~/router-packet-samples/<timestamp>",
    )
    parser.add_argument(
        "--limit", type=int, default=1000, help="maximum retained packets per class"
    )
    parser.add_argument("--max-classes", type=int, default=256)
    parser.add_argument("--max-total-mib", type=int, default=512)
    parser.add_argument("--max-packet-bytes", type=int, default=262144)
    parser.add_argument("--decoder-batch-packets", type=int, default=50000,
                        help="restart TShark after this many packets to bound its memory")
    parser.add_argument("--checkpoint-seconds", type=int, default=60)
    parser.add_argument("--refresh-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if (
        min(
            args.limit,
            args.max_classes,
            args.max_total_mib,
            args.max_packet_bytes,
            args.decoder_batch_packets,
            args.checkpoint_seconds,
            args.refresh_seconds,
        )
        <= 0
    ):
        parser.error("all limits and checkpoint interval must be positive")
    if args.output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.output = Path.home() / "router-packet-samples" / stamp
    args.output = args.output.expanduser()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error(f"output directory is not empty: {args.output}")
    args.output.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(args.output, 0o700)
    os.umask(0o077)
    if not sys.stderr.isatty():
        print(f"samples: {args.output}", file=sys.stderr)

    def interrupt_once(signum, frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt

    previous_sigint = signal.signal(signal.SIGINT, interrupt_once)
    try:
        if args.pcap:
            with args.pcap.open("rb") as stream:
                collector = process(stream, args)
        else:
            with live_stream(args) as stream:
                collector = process(stream, args)
    except KeyboardInterrupt:
        if not sys.stderr.isatty():
            print("stopped; final checkpoint saved", file=sys.stderr)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
    if not sys.stderr.isatty():
        print(
            f"done: {collector.total_seen} packets, {len(collector.buckets)} classes",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
