#!/usr/bin/env python3
"""Relay Ethernet pcap from stdin to the oracle, calibrating the capture clock."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import socket
import struct
import sys
import threading
import time

from packet_sampler import read_exact

MAGIC = b"RLO1"
CLOCK_REPORT = struct.Struct("!qQ")
FRAME = struct.Struct("!QH")
REFRESH_SECONDS = 20
MAX_UNCERTAINTY_NS = 25_000_000


@dataclass(frozen=True)
class ClockSample:
    offset: int
    uncertainty: int


def calibrate(conn, source):
    samples = []
    for _ in range(7):
        start = time.time_ns()
        conn.sendall(b"P")
        reply = read_exact(source, 8)
        end = time.time_ns()
        if reply is None:
            raise ConnectionError("oracle closed the clock probe")
        if end >= start:
            remote = struct.unpack("!Q", reply)[0]
            samples.append(ClockSample(remote - (start + end) // 2, (end - start) // 2))
    if not samples:
        raise OSError("local clock changed during calibration")
    return min(samples, key=lambda item: item.uncertainty)


def timed_frames(conn, stream):
    while (kind := read_exact(stream, 1)) is not None:
        if kind == b"P":
            conn.sendall(struct.pack("!Q", time.time_ns()))
        elif kind == b"H":
            stats = read_exact(stream, CLOCK_REPORT.size)
            if stats is None:
                raise ValueError("LAN feed ended during clock report")
            offset, uncertainty = CLOCK_REPORT.unpack(stats)
            yield "clock", (offset, uncertainty)
        elif kind == b"F":
            header = read_exact(stream, FRAME.size)
            if header is None:
                raise ValueError("LAN feed ended during frame header")
            at, size = FRAME.unpack(header)
            if size > 16384:
                raise ValueError("LAN frame exceeds the oracle frame limit")
            frame = read_exact(stream, size)
            if size and frame is None:
                raise ValueError("LAN feed ended in a frame")
            yield "frame", (at / 1e9, frame if size else None)
        else:
            raise ValueError("unknown LAN feed message")


def relay(conn, pcap):
    # Import here so the decoder side can share the LAN protocol without a cycle.
    from readiness_oracle import pcap_packets

    conn.sendall(MAGIC)
    source = conn.makefile("rb")
    with source:
        lock = threading.Lock()
        finished = threading.Event()
        failed = []

        def sample():
            with lock:
                current = calibrate(conn, source)
                conn.sendall(b"H" + CLOCK_REPORT.pack(current.offset, current.uncertainty))
                return current

        current = sample()
        print(f"LAN feed clock offset {current.offset / 1e6:+.1f} ms, "
              f"uncertainty ±{current.uncertainty / 1e6:.1f} ms", file=sys.stderr, flush=True)

        def refresh():
            nonlocal current
            while not finished.wait(REFRESH_SECONDS):
                try:
                    current = sample()
                except OSError as exc:
                    failed.append(exc)
                    conn.shutdown(socket.SHUT_RDWR)
                    return

        worker = threading.Thread(target=refresh, daemon=True)
        worker.start()
        try:
            for at, frame in pcap_packets(pcap):
                if failed:
                    raise failed[0]
                with lock:
                    timestamp = round(at * 1e9) + current.offset
                    if timestamp < 0:
                        raise ValueError("negative corrected LAN capture timestamp")
                    if current.uncertainty > MAX_UNCERTAINTY_NS:
                        # Keep the socket and calibration alive while timing is uncertain.
                        continue
                    data = frame or b""
                    conn.sendall(b"F" + FRAME.pack(timestamp, len(data)) + data)
        finally:
            finished.set()
            worker.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=24686)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("invalid tunnel port")
    try:
        with socket.create_connection(("127.0.0.1", args.port), timeout=5) as conn:
            relay(conn, sys.stdin.buffer)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as exc:
        raise SystemExit(f"readiness feed: {exc}") from exc


if __name__ == "__main__":
    main()
