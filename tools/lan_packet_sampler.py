#!/usr/bin/env python3
"""Sample decrypted Wi-Fi LAN traffic as Ethernet frames.

Live: python tools/lan_packet_sampler.py
Offline: python tools/lan_packet_sampler.py --pcap radiotap_capture.pcap --ssid SSID

Live mode creates a temporary monitor interface on --source-interface, fixed
to --channel. It may interrupt an existing connection on the same radio.
Capture starts immediately; a client must (re)connect after capture starts
for TShark to derive that client's WPA2 traffic keys. Ctrl+C saves the final
checkpoint. Only successfully decrypted data frames enter samples.pcap.
"""

from __future__ import annotations

import argparse
from collections import Counter
import getpass
import hashlib
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime

from packet_sampler import Collector, FIELDS, PCAP_MAGIC, classify, read_exact

DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127
SNAP_PREFIX = b"\xaa\xaa\x03\x00\x00\x00"
END_MARKER = "__ROUTER_WIFI_FRAME_END__"
DECRYPTED_HEADING = re.compile(r"^Decrypted .* data \((\d+) bytes\):$")
HEX_ROW = re.compile(r"^[0-9a-fA-F]{4,8}  ((?:[0-9a-fA-F]{2} ?)+)\s*$")


def private_key_config(ssid: str, password: str, directory: pathlib.Path) -> None:
    if not 8 <= len(password) <= 63:
        raise ValueError("WPA2-Personal password must be 8 to 63 characters")
    ssid_bytes = ssid.encode("utf-8")
    if not 1 <= len(ssid_bytes) <= 32:
        raise ValueError("SSID must be 1 to 32 bytes")
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), ssid_bytes, 4096, 32)
    target = directory / "80211_keys"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(f'"wpa-psk","{pmk.hex()}"\n')


def run_as_root(command: list[str], password: str) -> None:
    result = subprocess.run(
        ["sudo", "-S", "-p", "", "--", *command],
        input=(password + "\n").encode(), capture_output=True,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")


def connected_channel(interface: str) -> int | None:
    link = subprocess.run(["iw", "dev", interface, "link"], capture_output=True, text=True)
    if link.returncode:
        raise RuntimeError(f"cannot inspect Wi-Fi interface {interface}: {link.stderr.strip()}")
    if not link.stdout.startswith("Connected to "):
        return None
    info = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True)
    if info.returncode:
        raise RuntimeError(f"cannot inspect Wi-Fi channel for {interface}: {info.stderr.strip()}")
    match = re.search(r"^\s*channel (\d+)\b", info.stdout, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"{interface} is connected but its channel could not be determined")
    return int(match.group(1))


@contextmanager
def capture_stream(args):
    if args.pcap:
        with args.pcap.open("rb") as stream:
            yield stream
        return

    for program in ("iw", "ip", "sudo", "tcpdump"):
        if shutil.which(program) is None:
            raise RuntimeError(f"{program} is required for live capture")

    station_channel = connected_channel(args.source_interface)
    if station_channel is not None and station_channel != args.channel:
        raise RuntimeError(
            f"{args.source_interface} is connected on channel {station_channel}; "
            f"this radio cannot monitor channel {args.channel} at the same time"
        )
    password = getpass.getpass("Local sudo password: ")
    monitor = f"rmon{os.getpid() % 100000}"
    created = False
    capture = None
    stopped_by_us = False
    log_path = args.output / "capture.log"
    try:
        run_as_root(
            ["iw", "dev", args.source_interface, "interface", "add", monitor, "type", "monitor"],
            password,
        )
        created = True
        run_as_root(["ip", "link", "set", monitor, "up"], password)
        if station_channel is None:
            run_as_root(["iw", "dev", monitor, "set", "channel", str(args.channel)], password)
        with log_path.open("wb") as log:
            capture = subprocess.Popen(
                ["sudo", "-S", "-p", "", "--", "tcpdump", "-U", "-i", monitor,
                 "-s", "0", "-w", "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, bufsize=0,
            )
            capture.stdin.write((password + "\n").encode())
            capture.stdin.close()
            yield capture.stdout
    finally:
        if capture is not None:
            if capture.poll() is None:
                stopped_by_us = True
                capture.terminate()
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
            capture.stdout.close()
        if created:
            try:
                run_as_root(["iw", "dev", monitor, "del"], password)
            except RuntimeError as exc:
                print(f"monitor interface cleanup: {exc}", file=sys.stderr)
    if capture is not None and capture.returncode != 0 and not (
        stopped_by_us and capture.returncode == -15
    ):
        raise RuntimeError(f"tcpdump exited with {capture.returncode}; see {log_path}")


def read_dump(stream) -> bytes:
    lines = []
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("TShark stopped producing Wi-Fi packet dissections")
        if line.rstrip(b"\r\n") == END_MARKER.encode():
            return b"".join(lines)
        lines.append(line)


def decrypted_data(dump: bytes) -> bytes | None:
    expected = None
    data = bytearray()
    for line in dump.decode("ascii", "replace").splitlines():
        heading = DECRYPTED_HEADING.fullmatch(line)
        if heading:
            if expected is not None:
                break
            expected = int(heading.group(1))
            continue
        if expected is None:
            continue
        row = HEX_ROW.fullmatch(line)
        if row:
            data.extend(bytes.fromhex(row.group(1)))
        elif data:
            break
    return bytes(data) if expected is not None and len(data) == expected else None


def frame_direction(raw: bytes, linktype: int) -> tuple[str, bytes, bytes] | None:
    offset = 0
    if linktype == DLT_IEEE802_11_RADIO:
        if len(raw) < 4 or raw[0] != 0:
            return None
        offset = struct.unpack_from("<H", raw, 2)[0]
    if len(raw) < offset + 24:
        return None
    control = struct.unpack_from("<H", raw, offset)[0]
    if (control >> 2) & 3 != 2 or not control & 0x4000 or control & 0x0800:
        return None  # data frames only; protected; skip radio retries
    to_ds = bool(control & 0x0100)
    from_ds = bool(control & 0x0200)
    if from_ds and not to_ds:
        return "downlink", raw[offset + 4 : offset + 10], raw[offset + 16 : offset + 22]
    if to_ds and not from_ds:
        return "uplink", raw[offset + 16 : offset + 22], raw[offset + 10 : offset + 16]
    return None


def wlan_header(raw: bytes, linktype: int) -> tuple[int, int, int] | None:
    offset = 0
    if linktype == DLT_IEEE802_11_RADIO:
        if len(raw) < 4 or raw[0] != 0:
            return None
        offset = struct.unpack_from("<H", raw, 2)[0]
    if len(raw) < offset + 24:
        return None
    control = struct.unpack_from("<H", raw, offset)[0]
    return offset, (control >> 2) & 3, control


def advertised_ssid(raw: bytes, linktype: int) -> tuple[bytes, bytes] | None:
    header = wlan_header(raw, linktype)
    if header is None:
        return None
    offset, frame_type, control = header
    if frame_type != 0 or ((control >> 4) & 15) not in (5, 8):
        return None  # probe response or beacon
    bssid = raw[offset + 16 : offset + 22]
    position = offset + 36  # 24-byte management header plus fixed parameters
    while position + 2 <= len(raw):
        tag, length = raw[position : position + 2]
        position += 2
        if position + length > len(raw):
            break
        if tag == 0:
            return bssid, raw[position : position + length]
        position += length
    return None


def data_bssid(raw: bytes, linktype: int) -> bytes | None:
    header = wlan_header(raw, linktype)
    if header is None:
        return None
    offset, frame_type, control = header
    if frame_type != 2:
        return None
    to_ds = bool(control & 0x0100)
    from_ds = bool(control & 0x0200)
    if to_ds and not from_ds:
        return raw[offset + 4 : offset + 10]
    if from_ds and not to_ds:
        return raw[offset + 10 : offset + 16]
    return None


def data_client(raw: bytes, linktype: int) -> bytes | None:
    header = wlan_header(raw, linktype)
    if header is None:
        return None
    offset, frame_type, control = header
    if frame_type != 2:
        return None
    to_ds = bool(control & 0x0100)
    from_ds = bool(control & 0x0200)
    if to_ds and not from_ds:
        return raw[offset + 10 : offset + 16]
    if from_ds and not to_ds:
        return raw[offset + 4 : offset + 10]
    return None


def mac_text(mac: bytes) -> str:
    return mac.hex(":")


def ethernet_frame(dst: bytes, src: bytes, msdu: bytes) -> bytes | None:
    if not msdu.startswith(SNAP_PREFIX) or len(msdu) < 8:
        return None
    ethertype = int.from_bytes(msdu[6:8], "big")
    if ethertype < 1536 or ethertype == 0x888E:  # EAPOL stays on the Wi-Fi link
        return None
    frame = dst + src + msdu[6:]
    return frame.ljust(60, b"\0")


def ethernet_frames(dst: bytes, src: bytes, plaintext: bytes) -> list[bytes]:
    single = ethernet_frame(dst, src, plaintext)
    if single is not None:
        return [single]

    # An A-MSDU contains one or more 14-byte subframe headers and padded MSDUs.
    frames = []
    offset = 0
    while offset + 14 <= len(plaintext):
        sub_dst = plaintext[offset : offset + 6]
        sub_src = plaintext[offset + 6 : offset + 12]
        length = int.from_bytes(plaintext[offset + 12 : offset + 14], "big")
        end = offset + 14 + length
        if length < 8 or end > len(plaintext):
            return []
        frame = ethernet_frame(sub_dst, sub_src, plaintext[offset + 14 : end])
        if frame is None:
            return []
        frames.append(frame)
        if end == len(plaintext):
            return frames
        offset = end + (-(14 + length) % 4)
    return []


def stop_process(proc: subprocess.Popen) -> None:
    proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    proc.stdout.close()


def process(stream, args, key_directory: pathlib.Path) -> Collector:
    header = read_exact(stream, 24)
    if header is None or header[:4] not in PCAP_MAGIC:
        hint = f"; see {args.output / 'capture.log'}" if not args.pcap else ""
        raise ValueError(f"source did not provide a classic pcap header{hint}")
    endian = PCAP_MAGIC[header[:4]]
    linktype = struct.unpack_from(endian + "I", header, 20)[0] & 0xFFFF
    if linktype not in (DLT_IEEE802_11, DLT_IEEE802_11_RADIO):
        raise ValueError(f"expected raw 802.11 or radiotap pcap, got linktype {linktype}")
    ethernet_header = header[:20] + struct.pack(endian + "I", 1)
    collector = Collector(args, ethernet_header)
    observed = protected = decrypted = converted = 0
    handshake_messages = {number: 0 for number in range(1, 5)}
    handshakes_by_client: dict[bytes, Counter] = {}
    target_bssids: set[bytes] = set()
    protected_by_bssid: Counter = Counter()
    decrypted_by_bssid: Counter = Counter()
    protected_by_client: Counter = Counter()
    decrypted_by_client: Counter = Counter()
    own_mac = None
    if not args.pcap:
        own_mac = bytes.fromhex(
            (pathlib.Path("/sys/class/net") / args.source_interface / "address")
            .read_text().strip().replace(":", "")
        )
    collector.status_line = "Radio frames 0 | protected data 0 | decrypted 0"
    collector.extra_manifest = {}
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=str(key_directory))
    decoder_cmd = [
        "tshark", "-n", "-l", "-r", "-", "-o", "wlan.enable_decryption:TRUE",
        "-T", "text", "-P", "-x", "--hexdump", "noascii", "-S", END_MARKER,
    ]
    classifier_cmd = ["tshark", "-n", "-l", "-r", "-", "-T", "fields"]
    for field in FIELDS:
        classifier_cmd.extend(("-e", field))
    with (args.output / "decrypt.log").open("wb") as decrypt_log, \
         (args.output / "classify.log").open("wb") as classify_log:
        try:
            decoder = subprocess.Popen(
                decoder_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=decrypt_log, env=env, bufsize=0,
            )
            classifier = subprocess.Popen(
                classifier_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=classify_log, bufsize=0,
            )
        except BaseException:
            if "decoder" in locals():
                decoder.terminate()
                decoder.wait()
            collector.close()
            raise
        sent_ethernet_header = False

        def update_progress() -> None:
            target_protected = sum(protected_by_bssid[bssid] for bssid in target_bssids)
            target_decrypted = sum(decrypted_by_bssid[bssid] for bssid in target_bssids)
            own_handshakes = handshakes_by_client.get(own_mac, Counter())
            collector.status_line = (
                f"{args.ssid} protected/decrypted {target_protected}/{target_decrypted} | "
                f"this PC {protected_by_client[own_mac]}/{decrypted_by_client[own_mac]} "
                f"HS {own_handshakes[1]}/{own_handshakes[2]}/"
                f"{own_handshakes[3]}/{own_handshakes[4]}"
            )
            collector.extra_manifest = {
                "radio_frames_seen": observed,
                "protected_data_frames_seen": protected,
                "decrypted_data_frames_seen": decrypted,
                "ethernet_frames_classified": converted,
                "eapol_handshake_messages": {
                    str(number): count for number, count in handshake_messages.items()
                },
                "handshakes_by_client": {
                    mac_text(client): {str(number): counts[number] for number in range(1, 5)}
                    for client, counts in handshakes_by_client.items()
                },
                "target_bssids": {
                    mac_text(bssid): {
                        "protected": protected_by_bssid[bssid],
                        "decrypted": decrypted_by_bssid[bssid],
                    }
                    for bssid in sorted(target_bssids)
                },
                "capture_host_mac": mac_text(own_mac) if own_mac else None,
                "capture_host_protected": protected_by_client[own_mac],
                "capture_host_decrypted": decrypted_by_client[own_mac],
                "ssid": args.ssid,
                "channel": None if args.pcap else args.channel,
                "direction": args.direction,
            }

        try:
            while True:
                record_header = read_exact(stream, 16)
                if record_header is None:
                    break
                length = struct.unpack_from(endian + "I", record_header, 8)[0]
                if length > args.max_packet_bytes:
                    raise ValueError(f"radio packet exceeds --max-packet-bytes: {length}")
                packet = read_exact(stream, length)
                if packet is None:
                    raise ValueError("pcap stream ended before packet data")
                observed += 1
                advertised = advertised_ssid(packet, linktype)
                if advertised is not None and advertised[1] == args.ssid.encode("utf-8"):
                    target_bssids.add(advertised[0])
                bssid = data_bssid(packet, linktype)
                client = data_client(packet, linktype)
                try:
                    decoder.stdin.write((header if observed == 1 else b"") + record_header + packet)
                    decoder.stdin.flush()
                except BrokenPipeError as exc:
                    raise RuntimeError("Wi-Fi TShark decoder exited; see decrypt.log") from exc
                dump = read_dump(decoder.stdout)
                summary = dump.split(b"\n", 1)[0].decode("utf-8", "replace")
                message = re.search(r"\bEAPOL\b.*Key \(Message ([1-4]) of 4\)", summary)
                if message:
                    number = int(message.group(1))
                    handshake_messages[number] += 1
                    if client is not None:
                        handshakes_by_client.setdefault(client, Counter())[number] += 1
                direction = frame_direction(packet, linktype)
                if direction is not None and args.direction in ("both", direction[0]):
                    protected += 1
                    if bssid is not None:
                        protected_by_bssid[bssid] += 1
                    if client is not None:
                        protected_by_client[client] += 1
                    plaintext = decrypted_data(dump)
                    if plaintext is not None:
                        decrypted += 1
                        if bssid is not None:
                            decrypted_by_bssid[bssid] += 1
                        if client is not None:
                            decrypted_by_client[client] += 1
                        for frame in ethernet_frames(direction[1], direction[2], plaintext):
                            if len(frame) > args.max_packet_bytes:
                                continue
                            synthetic_header = record_header[:8] + struct.pack(endian + "II", len(frame), len(frame))
                            try:
                                classifier.stdin.write(
                                    (ethernet_header if not sent_ethernet_header else b"")
                                    + synthetic_header + frame
                                )
                                classifier.stdin.flush()
                            except BrokenPipeError as exc:
                                raise RuntimeError("Ethernet TShark classifier exited; see classify.log") from exc
                            sent_ethernet_header = True
                            line = classifier.stdout.readline()
                            if not line:
                                raise RuntimeError("Ethernet TShark stopped classifying; see classify.log")
                            parts = line.decode("utf-8", "replace").rstrip("\r\n").split("\t")
                            if len(parts) != len(FIELDS):
                                raise ValueError(f"unexpected TShark field count: {len(parts)}")
                            values = dict(zip(FIELDS, parts))
                            converted += 1
                            update_progress()
                            collector.add(f"{direction[0]}/{classify(values)}", observed, synthetic_header + frame)
                update_progress()
                if time.monotonic() - collector.last_checkpoint >= args.checkpoint_seconds:
                    collector.checkpoint()
                if time.monotonic() - collector.last_refresh >= args.refresh_seconds:
                    collector.render()
        finally:
            update_progress()
            try:
                stop_process(decoder)
                stop_process(classifier)
            finally:
                collector.close()
        if decoder.returncode:
            raise RuntimeError(f"Wi-Fi TShark exited with {decoder.returncode}; see decrypt.log")
        if classifier.returncode:
            raise RuntimeError(f"Ethernet TShark exited with {classifier.returncode}; see classify.log")
    return collector


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=pathlib.Path, help="read a local raw 802.11 or radiotap classic pcap")
    parser.add_argument("--source-interface", default="wlp8s0", help="radio on which to create monitor interface")
    parser.add_argument("--channel", type=int, default=149)
    parser.add_argument("--ssid", default="Fesslers")
    parser.add_argument("--direction", choices=("both", "downlink", "uplink"), default="both")
    parser.add_argument("--output", type=pathlib.Path, help="new output directory")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--max-classes", type=int, default=256)
    parser.add_argument("--max-total-mib", type=int, default=512)
    parser.add_argument("--max-packet-bytes", type=int, default=262144)
    parser.add_argument("--checkpoint-seconds", type=int, default=60)
    parser.add_argument("--refresh-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if min(args.channel, args.limit, args.max_classes, args.max_total_mib,
           args.max_packet_bytes, args.checkpoint_seconds, args.refresh_seconds) <= 0:
        parser.error("channel, limits, and intervals must be positive")
    if shutil.which("tshark") is None:
        parser.error("tshark is required")
    if not args.pcap:
        for program in ("iw", "ip", "sudo", "tcpdump"):
            if shutil.which(program) is None:
                hint = "; install with sudo pacman -S iw" if program == "iw" else ""
                parser.error(f"{program} is required for live capture{hint}")
    if args.output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.output = pathlib.Path.home() / "router-packet-samples" / f"lan-{stamp}"
    args.output = args.output.expanduser()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error(f"output directory is not empty: {args.output}")
    os.umask(0o077)
    args.output.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(args.output, 0o700)
    args.host = f"wifi:{args.source_interface}"  # Collector's manifest field
    args.interface = args.source_interface
    if not sys.stderr.isatty():
        print(f"samples: {args.output}", file=sys.stderr)
    try:
        wifi_password = getpass.getpass(f"WPA2 password for {args.ssid}: ")
        with tempfile.TemporaryDirectory(prefix="router-wifi-keys-") as private_dir:
            private_key_config(args.ssid, wifi_password, pathlib.Path(private_dir))
            del wifi_password
            with capture_stream(args) as stream:
                collector = process(stream, args, pathlib.Path(private_dir))
    except KeyboardInterrupt:
        if not sys.stderr.isatty():
            print("stopped; final checkpoint saved", file=sys.stderr)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not sys.stderr.isatty():
        print(f"done: {collector.total_seen} Ethernet frames classified", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
