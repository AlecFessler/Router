"""Generate local Time Exceeded pcap and Wireshark CSV fixtures."""

from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent
PCAP = HERE / "time_exceeded_test.pcap"
CSV = HERE / "time_exceeded_test.csv"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header(source: bytes, destination: bytes, protocol: int, length: int, ttl: int) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, 0x1234, 0, ttl, protocol, 0, source, destination)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


original_source = bytes((192, 0, 2, 10))
original_destination = bytes((198, 51, 100, 20))
udp_header = struct.pack("!HHHH", 12345, 33434, 8, 0)
original = ipv4_header(original_source, original_destination, 17, 28, 1) + udp_header
outer_source = bytes((203, 0, 113, 1))
outer_destination = original_source
ethernet = bytes.fromhex("0200000000010200000000020800")

with PCAP.open("wb") as output:
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for code in (0, 1):
        icmp = struct.pack("!BBHI", 11, code, 0, 0) + original
        icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
        outer = ipv4_header(outer_source, outer_destination, 1, 20 + len(icmp), 64)
        frame = ethernet + outer + icmp
        output.write(struct.pack("<IIII", code + 1, 0, len(frame), len(frame)))
        output.write(frame)

with CSV.open("wb") as output:
    subprocess.run(
        [
            "tshark", "-r", str(PCAP), "-T", "fields", "-E", "header=y",
            "-E", "separator=,", "-E", "quote=d", "-e", "frame.number",
            "-e", "icmp.type", "-e", "icmp.code", "-e", "icmp.unused",
        ],
        check=True,
        stdout=output,
    )
