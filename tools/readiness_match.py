"""Packet normalization and comparison for readiness_oracle.py."""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from hashlib import blake2s
import heapq
from ipaddress import ip_address
import struct

VLAN_TAGS = (0x8100, 0x88A8)
# Capture order may disagree by a small amount even after clock calibration.
CLOCK_SLOP = 0.050
ARP, IPV4, IPV6 = 0x0806, 0x0800, 0x86DD
TCP, UDP, ICMP = 6, 17, 1


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


def digest(data):
    return blake2s(data, digest_size=12).digest()


@dataclass(frozen=True)
class Packet:
    frame: bytes
    ethertype: int
    src: bytes = b""
    dst: bytes = b""
    protocol: int = 0
    sport: int = 0
    dport: int = 0
    ttl: int = 0
    token: tuple | None = None
    transport: int = 0
    arp_op: int = 0
    echo_type: int = -1
    network_length: int = 0

    @classmethod
    def parse(cls, frame):
        if len(frame) < 14:
            return cls(frame, 0)
        kind, offset = u16(frame, 12), 14
        while kind in VLAN_TAGS and offset + 4 <= len(frame):
            kind, offset = u16(frame, offset + 2), offset + 4
        if kind == ARP and len(frame) >= offset + 28 and frame[offset:offset+6] == b"\0\1\x08\0\x06\x04":
            return cls(frame, kind, frame[offset+14:offset+18], frame[offset+24:offset+28],
                       arp_op=u16(frame, offset+6))
        if kind == IPV6 and len(frame) >= offset + 40 and frame[offset] >> 4 == 6:
            end = offset + 40 + u16(frame, offset + 4)
            src, dst = frame[offset+8:offset+24], frame[offset+24:offset+40]
            proto = frame[offset+6]
            token = None
            if end <= len(frame) and all(ip_address(addr).is_global for addr in (src, dst)):
                token = (kind, proto, src, dst, digest(frame[offset+40:end]))
            return cls(frame, kind, src, dst, proto, ttl=frame[offset+7], token=token,
                       network_length=end - offset if end <= len(frame) else 0)
        if kind != IPV4 or len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            return cls(frame, kind)
        start = offset + (frame[offset] & 15) * 4
        end = offset + u16(frame, offset + 2)
        proto, ttl = frame[offset+9], frame[offset+8]
        src, dst = frame[offset+12:offset+16], frame[offset+16:offset+20]
        body = frame[start:end]
        sport = dport = 0
        echo_type = -1
        token = None
        if offset + 20 <= start <= end <= len(frame) and not u16(frame, offset+6) & 0x3fff:
            if proto == TCP and len(body) >= 20 and 20 <= (body[12] >> 4) * 4 <= len(body):
                sport, dport = struct.unpack_from("!HH", body)
                token = (body[4:12], body[13], digest(body[(body[12] >> 4) * 4:]))
            elif proto == UDP and len(body) >= 8 and 8 <= u16(body, 4) <= len(body):
                sport, dport = struct.unpack_from("!HH", body)
                token = (digest(body[8:u16(body, 4)]),)
            elif proto == ICMP and len(body) >= 8 and body[0] in (0, 8) and body[1] == 0:
                echo_type = body[0]
                sport = dport = u16(body, 4)
                token = (echo_type, body[6:8], digest(body[8:]))
            elif proto not in (TCP, UDP, ICMP):
                token = (digest(body),)
        return cls(frame, kind, src, dst, proto, sport, dport, ttl, token, start, echo_type=echo_type,
                   network_length=end - offset if end <= len(frame) else 0)

    def key(self, direction):
        if self.token is None or self.ethertype == IPV6:
            return self.token
        remote = (self.dst, self.dport) if direction == "lan" else (self.src, self.sport)
        if self.protocol == ICMP:
            remote = remote[:1]
        signature = self.token[:2] if self.protocol == TCP else self.token
        return self.ethertype, self.protocol, remote, signature

    def peer_binding(self, outbound):
        local_port, peer, peer_port = ((self.sport, self.dst, self.dport) if outbound
                                       else (self.dport, self.src, self.sport))
        return self.protocol, local_port, peer, peer_port if self.protocol != ICMP else 0

    def translate(self, port):
        """Translate only the WAN NAT identifier, preserving the validity of the original checksum."""
        if self.dport == port:
            return self.frame
        frame = bytearray(self.frame)
        field, checksum = {TCP: (2, 16), UDP: (2, 6), ICMP: (4, 2)}[self.protocol]
        index = self.transport + checksum
        old = u16(frame, index)
        struct.pack_into("!H", frame, self.transport + field, port)
        if old or self.protocol != UDP:
            updated = (~old & 0xffff) + (~self.dport & 0xffff) + port
            updated = (updated >> 16) + (updated & 0xffff)
            updated = (updated >> 16) + (updated & 0xffff)
            result = ~updated & 0xffff
            struct.pack_into("!H", frame, index, result or (0xffff if self.protocol == UDP else 0))
        return frame


@dataclass(eq=False)
class Decision:
    id: int
    at: float
    direction: str
    packet: Packet
    key: tuple | None
    mode: str
    state_known: bool = True
    outcome: str = "pending"
    shadow: Packet | None = None
    shadow_reply: Packet | None = None
    shadow_reply_side: str | None = None
    google: Packet | None = None
    ambiguous: bool = False
    unhandled: bool = False
    error: str | None = None
    binding: tuple | None = None
    binding_source: Decision | None = field(default=None, repr=False)
    shadow_port: int | None = None
    reference_mapping_exact: bool = True
    reference_mapping_changed: bool = False
    google_at: float | None = None
    difference: tuple[str, ...] = ()
    coverage: str | None = None


@dataclass(eq=False)
class Observation:
    at: float
    packet: Packet
    pair: Decision | None = None


class Matcher:
    def __init__(self, window, limit, report, infer_drops=False, transit=0.25, live=False):
        self.window = window
        self.transit = transit
        self.live = live
        self.limit = limit
        self.report = report
        self.infer_drops = infer_drops
        self.ingress = defaultdict(list)
        self.egress = defaultdict(list)
        self.pending = OrderedDict()
        self.deadlines = []
        self.observations = deque()
        self.bindings = OrderedDict()
        self.port_bindings = defaultdict(set)
        self.counts = Counter()
        self.first_observed = {}
        self.last_observed = {}
        self.wan_output_stats = None
        self.wan_output_clean_from = float("inf")
        self.last_gap = defaultdict(lambda: float("-inf"))
        self.now = float("-inf")

    def advance(self, now):
        self.now = max(self.now, now)
        while len(self.pending) > self.limit:
            self.gap(self.now, "pending_limit")
            _, packet_id = heapq.heappop(self.deadlines)
            self.finish(self.pending[packet_id], interrupted=True)
        while self.deadlines and self.deadlines[0][0] <= self.now:
            _, packet_id = heapq.heappop(self.deadlines)
            self.finish(self.pending[packet_id])
        while self.observations:
            at, key, observation = self.observations[0]
            if self.now - at <= self.transit + CLOCK_SLOP and len(self.observations) <= self.limit:
                break
            if len(self.observations) > self.limit:
                self.gap(self.now, "observation_limit")
            self.observations.popleft()
            self.remove(self.egress, key, observation)
            if observation.pair is None:
                self.counts[f"google_{key[0]}_output_unpaired"] += 1

    def gap(self, at, reason):
        source = next((label for label in ("lan", "wan-in", "wan-out")
                       if reason.startswith(label + "_")), "all")
        self.last_gap[source] = max(self.last_gap[source], at)
        self.counts[reason] += 1

    def capture_stats(self, at, drops):
        previous = self.wan_output_stats
        if previous is None or drops != previous[1]:
            if previous is not None:
                self.counts["wan-out_kernel_drops"] += max(0, drops - previous[1])
            self.wan_output_clean_from = at
        self.wan_output_stats = at, drops

    @staticmethod
    def remove(index, key, item):
        group = index[key]
        group.remove(item)
        if not group:
            del index[key]

    def input(self, decision):
        self.pending[decision.id] = decision
        hold = self.window if decision.state_known else self.transit + CLOCK_SLOP
        heapq.heappush(self.deadlines, (decision.at + hold, decision.id))
        self.counts[f"{decision.direction}_input"] += 1
        if decision.key is not None:
            self.ingress[decision.key].append(decision)
            for observation in self.egress.get(decision.key, ()):
                self.try_pair(decision.key, observation)

    def output(self, key, at, packet, side):
        self.first_observed.setdefault(side, at)
        self.last_observed[side] = at
        if key is None:
            return
        observation = Observation(at, packet)
        self.egress[key].append(observation)
        self.observations.append((at, key, observation))
        self.try_pair(key, observation)

    def try_pair(self, key, observation):
        possible = [d for d in self.ingress.get(key, ())
                    if -CLOCK_SLOP <= observation.at - d.at <= self.transit]
        if key[:2] == ("transit", "wan") and possible:
            destination = observation.packet.dst, observation.packet.dport
            exact = [d for d in possible if d.binding == destination and d.reference_mapping_exact]
            compatible = [d for d in possible if d.binding in (None, destination)]
            if exact:
                possible = exact
            elif compatible:
                possible = compatible
            elif len(possible) == 1:
                possible[0].reference_mapping_changed = True
        if len(possible) > 1:
            for decision in possible:
                decision.ambiguous = True
            return
        if not possible:
            return
        decision = possible[0]
        if observation.pair is not None and observation.pair is not decision:
            decision.ambiguous = True
            observation.pair.ambiguous = True
            return
        if decision.google is not None:
            if observation.pair is not decision:
                decision.ambiguous = True
            return
        observation.pair = decision
        decision.google = observation.packet
        decision.google_at = observation.at
        self.learn(decision)

    def learn(self, decision):
        if (decision.direction != "lan" or decision.mode != "transit" or decision.ambiguous
                or decision.google is None or decision.packet.ethertype != IPV4
                or decision.packet.protocol not in (TCP, UDP, ICMP)):
            return
        key = decision.google.peer_binding(outbound=True)
        previous = self.get_binding(key, decision.at)
        inside = (decision.packet.src, decision.packet.sport)
        if previous is not None and (previous.packet.src, previous.packet.sport) != inside:
            previous.ambiguous = True
            decision.ambiguous = True
            return
        self.bindings[key] = decision
        self.port_bindings[key[:2]].add(key)
        self.bindings.move_to_end(key)
        while len(self.bindings) > self.limit:
            self.remove_binding(next(iter(self.bindings)))

    def remove_binding(self, key):
        del self.bindings[key]
        peers = self.port_bindings[key[:2]]
        peers.remove(key)
        if not peers:
            del self.port_bindings[key[:2]]

    def get_binding(self, key, at):
        source = self.bindings.get(key)
        if source is None:
            return None
        ttl = {TCP: 1800, UDP: 180, ICMP: 45}[key[0]]
        if at - source.at > ttl:
            self.remove_binding(key)
            return None
        return source if not source.ambiguous else None

    def lookup(self, packet, at):
        key = packet.peer_binding(outbound=False)
        source = self.get_binding(key, at)
        if source is not None:
            return (source.packet.src, source.packet.sport), source, True
        candidates = {}
        for peer in tuple(self.port_bindings.get(key[:2], ())):
            source = self.get_binding(peer, at)
            if source is not None:
                candidates[source.packet.src, source.packet.sport] = source
        if len(candidates) == 1:
            destination, source = next(iter(candidates.items()))
            return destination, source, False
        return None, None, False

    def result(self, kind, id, payload):
        decision = self.pending.get(id)
        if decision is None:
            self.counts["late_shadow_outcome"] += 1
            return
        if kind == b"F":
            decision.outcome = "forwarded"
            decision.shadow = Packet.parse(payload)
        elif kind in (b"R", b"S"):
            decision.outcome = "answered"
            decision.shadow_reply = Packet.parse(payload)
            decision.shadow_reply_side = "lan" if kind == b"R" else "wan"
        elif kind == b"X" and decision.outcome == "pending":
            decision.outcome = "dropped"
        elif kind == b"U":
            decision.unhandled = True
        elif kind == b"E":
            decision.error = payload.decode("ascii", "replace")

    def finish(self, decision, interrupted=False):
        self.pending.pop(decision.id)
        if decision.key is not None:
            self.remove(self.ingress, decision.key, decision)
        kind = self.classify(decision, interrupted)
        self.counts[kind] += 1
        if kind == "both_forwarded":
            self.counts[f"{decision.direction}_both_forwarded"] += 1
        if kind.startswith("google_forwarded_shadow_") or kind == "forwarded_differently":
            self.counts[f"{decision.direction}_forwarding_disagreements"] += 1
        if decision.unhandled:
            self.counts["unhandled"] += 1
        if decision.error:
            self.counts["handler_error"] += 1
        self.report(decision, kind)

    def classify(self, decision, interrupted):
        if decision.mode == "control":
            return "control"
        if decision.ambiguous or (decision.binding_source and decision.binding_source.ambiguous):
            return "inconclusive_ambiguous"
        if not decision.state_known:
            return "google_forwarded_nat_state_unknown" if decision.google else "unscoped_wan"
        if decision.reference_mapping_changed:
            return "inconclusive_google_mapping_changed"
        if decision.binding is not None:
            if not decision.reference_mapping_exact and decision.google is None:
                return "inconclusive_unconfirmed_peer_mapping"
            if decision.shadow_port is None:
                if decision.google is not None:
                    decision.coverage = "paired"
                    return "google_forwarded_shadow_no_mapping"
                return "inconclusive_shadow_nat_state"
        if decision.key is None:
            return "inconclusive_protocol"
        if decision.outcome == "pending":
            return "inconclusive_pending"
        if decision.google is not None:
            decision.coverage = "paired"
            expected = "answered" if decision.mode == "local" else "forwarded"
            if decision.outcome != expected:
                return f"google_{expected}_shadow_{decision.outcome}"
            if decision.shadow is not None:
                shadow, google = decision.shadow, decision.google
                checks = {
                    "packet_signature": (shadow.key(decision.direction) != google.key(decision.direction)
                                         or shadow.token != google.token),
                    "hop_limit": shadow.ttl != google.ttl,
                    "source_ip": shadow.src != google.src,
                    "destination_ip": shadow.dst != google.dst,
                    "inside_port": decision.direction == "wan" and shadow.dport != google.dport,
                }
                decision.difference = tuple(name for name, differs in checks.items() if differs)
                if decision.difference:
                    return "forwarded_differently"
            elif decision.shadow_reply is not None:
                reply, google = decision.shadow_reply, decision.google
                if (decision.shadow_reply_side != decision.direction
                        or (reply.ethertype, reply.src, reply.dst, reply.arp_op, reply.sport, reply.token)
                        != (google.ethertype, google.src, google.dst, google.arp_op, google.sport, google.token)):
                    decision.difference = ("local_reply",)
                    return "answered_differently"
            return f"both_{expected}"
        if interrupted:
            return "inconclusive_capture_end"
        if decision.outcome == "dropped":
            return "shadow_dropped_google_unobserved"
        side = ("wan" if decision.direction == "lan" else "lan") if decision.mode == "transit" else decision.direction
        covered_until = decision.at + self.transit
        healthy = (max(self.last_gap["all"], self.last_gap["wan-out"]) < decision.at - CLOCK_SLOP
                   and self.first_observed.get(side, float("inf")) <= decision.at
                   and self.last_observed.get(side, float("-inf")) >= covered_until)
        if self.live:
            stats = self.wan_output_stats
            healthy = (healthy and stats is not None and stats[0] >= covered_until
                       and self.wan_output_clean_from <= decision.at - CLOCK_SLOP)
        if (self.infer_drops and healthy and decision.direction == "lan"
                and decision.mode == "transit" and decision.outcome == "forwarded"):
            decision.coverage = "wired_capture_window" if self.live else "replay_capture_window"
            return "shadow_forwarded_google_likely_dropped"
        return f"shadow_{decision.outcome}_google_unobserved"

    def close(self):
        for decision in list(self.pending.values()):
            self.finish(decision, interrupted=True)
        self.deadlines.clear()
