# Two-interface network simulation

## Continuous validation

From the repository root, start the foreground campaign with one command.

```sh
zig build sim
```

The native Linux campaign runner builds the Zig fuzzer and the capture executable from the same source snapshot, including uncommitted changes. Zig's coverage-guided Smith worker varies the scenarios, packet fields, scheduling, and workload size. Most input mutations select a short workload. The initial campaign corpus includes a full-size choice. Full-size inputs use the campaign’s frame budget and contribute coverage to the same corpus. The supervisor selects a saved corpus input for a workload targeting 100,000 bulk inputs per interface. It records both RX streams, both expected egress streams and actual egress, then replays the RX streams on a fresh router. If generation stops early, it replays the available prefix and records the outcome of the independent egress comparison.

The terminal reports failing cases and coverage after each batch. To view the existing workstation session, run `tmux attach -t router-sim`. Press Ctrl+B, then D, to detach and leave it running. Ctrl+C stops the campaign. The same command resumes the corpus and the next batch. Results default to `~/.local/state/router-sim`.

- `status.json` records the current stage, batch seed, executable hash, resolved weights, cumulative fuzz counters for the current build/profile, the current corpus size, and catalog dispatches from successful extended runs. Passed and failed batch counts span versions. The fuzz counters describe the current source and profile. If Zig exits before printing its report, the supervisor reads the counters from that worker’s coverage map. `last_wire_replay` gives the seed and the separate results of running the fresh router and comparing its output. A comparison can detect missing output even if the fresh router also reported a handler error.
- `failures.jsonl` records failing inputs and timeouts. Evidence includes the exact Smith bytes, profile, source snapshot, executable, relevant logs and available captures. A capture replay may pass for a timing-dependent or test-allocator-only failure. The saved original outcome stands.
- Zig stops its worker when it finds a failure. The supervisor archives the case first, skips that exact decoded input on later instrumented runs of the same version/profile/budget, then schedules an extended corpus run before the next native batch if there is a saved input. Related inputs remain eligible. Repeated diagnostics for the same stage and profile reference the first capture and retain their individual Smith bytes. `--keep-all` saves full evidence for repeats.
- Source snapshots, build caches and coverage corpora live in `versions/`. Changing the source or traffic profile starts the corresponding worker with its own corpus. Older evidence stays reproducible. Earlier seed-only results are preserved in `previous_seeded`. An interrupted failure archive is finished against the original source and profile before an upgrade starts. The simulator source used for each run is recorded in status and failure records.

For a bounded campaign, use `zig build sim -- /tmp/router-campaign --runs 3 --seed 41`. `--fuzz-batch` sets the number of requested Zig iterations between extended runs, `--frames` sets the large workload size, and `--timeout` limits an active fuzz input or capture stage in seconds. A bounded campaign exits nonzero if any batch failed. `--weights profile.json` configures scenario weights in both exploration and replay. Omitting it resumes the saved profile.

## Scenario catalog

[scenarios/catalog.zig](../src/debug/scenarios/catalog.zig) lists the selectable traffic, the state required to run it, its default weight and its generator/oracle callback. The same registration creates its enum tag, configurable weight and run counter. A new client scenario also becomes eligible for Smith automatically. Add the exchange and its packet/state expectations together, then add its row. Each multi-turn conversation is a Zig struct with its fields, a `pub const Steps = enum { ... }`, and a `pub fn step(turn: *Sim.ConversationTurn) !void`. Put that type in [scenarios/](../src/debug/scenarios/) and register, for example, `.dns_fallback = episode(.bound, 1, Dns.Fallback, true)`. That row supplies the phase count, state storage at `turn.peer.network.episodes.dns_fallback`, its weight, and whether every run must execute it. Both workers enter every phase. The callback injects on the participating interface and checks the expected outputs and state before advancing.

| Participant | Selectable scenarios | Default weights |
| --- | --- | --- |
| LAN prerequisites | DHCP discover, DHCP request, resolve gateway MAC | Selected as required by each client's state |
| Bound LAN client | TCP, UDP, gateway DNS over UDP, gateway DNS over TCP, ping, ARP refresh, fragmented local echo, IPv4 multicast DNS, IPv6 multicast DNS | 54, 27, 9, 2, 3, 1, 2, 2, 1 |
| WAN server/gateway | Offer a lease, acknowledge a request, answer an observed translated flow | Triggered by the corresponding request |
| Idle WAN peer | ARP refresh, fragmented local echo | 3, 1 |
| Longer conversations | TCP download, UDP peer rotation, path-MTU recovery, parallel DNS, overlapping TCP upload/download, canceled download and reconnect, TCP window update, truncated DNS followed by TCP retry, interleaved local IPv4 fragments, fragmented ICMP feedback, simultaneous NTP clients, TCP half-close, UDP filtering, STUN discovery, UDP traceroute, ECN-capable TCP, RTP echo with alternating UDP checksums, WAN gateway MAC change, pipelined DNS over TCP, negative DNS answers, EDNS over UDP, UDP hairpin | 5, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 |

Weights apply among eligible options. A client waits for its address and gateway resolution before sending ordinary traffic. Forwarded conversations also require a bound WAN lease. TCP sockets stay busy until the reply burst completes. The reported catalog counts show the callbacks selected from these tables. Directed steps may also exercise the same packet behavior. For example, a profile containing `{"udp":54,"tcp":27}` changes those two LAN weights and inherits the other defaults. `zig-out/bin/router-sim weights profile.json` prints the resolved profile. A zero disables an optional pick in its pool. The guaranteed exercises still run.

The RTP echo peer returns the audio samples that reached the WAN. Across one remapped UDP socket, both endpoints alternate IPv4 datagrams with an omitted checksum and datagrams with a computed checksum. The oracle checks each translated datagram, the RTP stream at each endpoint and the existing mapping. [RFC 768](https://www.rfc-editor.org/rfc/rfc768) · [RFC 3022 §4.1](https://www.rfc-editor.org/rfc/rfc3022.html#section-4.1)

A phone sends two bursts of RTP audio and two RTCP sender reports. The listener uses the received stream to build its receiver reports. The oracle checks the reported packet and octet counts, sequence progression, report timing and CNAME, and follows both UDP sockets through NAT. [RFC 3550 §§6.1 and 6.4](https://www.rfc-editor.org/rfc/rfc3550.html#section-6.1)

The same catalog lists the directed startup and lease lifecycle steps, plus the flow outcomes. Every seed runs the prerequisites, the flow/outcome combinations, and the conversations marked mandatory in the catalog. The later clock-driven steps exercise actual lease and quarantine deadlines in order. Audit these lists alongside the selectable rows. Use the test's source coverage view to check for missing branches *inside* a listed scenario.

A joining client misses a DHCPOFFER after it leaves the LAN interface. It repeats DHCPDISCOVER after a seeded 3–5 seconds with the same transaction ID, requests the address in the offer it receives, and uses the acknowledged lease for an ARP and ping round trip. The oracle checks the reservation, the pool and the other clients’ leases throughout the exchange. [RFC 2131 §§4.1 and 4.4.1](https://www.rfc-editor.org/rfc/rfc2131.html#section-4.4.1)

The replacement DHCP client misses its first ACK, waits 3–5 seconds on its own clock and repeats its SELECTING request. The oracle checks both ACKs, the lease and pool, and the other clients’ bindings. The replacement client resolves the gateway and exchanges traffic after receiving the second ACK. [RFC 2131 §§3.1 and 4.1](https://www.rfc-editor.org/rfc/rfc2131.html#section-3.1)

UDP traceroute sends three probes from one socket to consecutive destination ports. The oracle checks the first local TTL expiration, a gateway’s Time Exceeded carrying a minimum quote, and the destination’s Port Unreachable carrying the entire final probe. The latter two share one NAT mapping and return the restored client port in the quote. [RFC 1812 §5.3.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.1) · [RFC 5508 §4.2.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-4.2.1)

The ECN-capable TCP transfer negotiates ECN at connection setup. In each direction, the peer sends ECN-capable data, receives a congestion-marked segment, acknowledges it with ECE and signals CWR on new data. The oracle checks those bits across NAT along with the IP and TCP checksums, sequence numbers and application payload. [RFC 3168 §§6.1.1–6.1.3](https://www.rfc-editor.org/rfc/rfc3168.html#section-6.1.1)

The DNS retry uses a client that still points to the gateway as its resolver. It sends the same UDP question again after a seeded timeout. Two delayed answers return to the original client socket with the gateway as their source. The oracle checks the DNS transaction ID, question and answer, and the lifetime and identity of the NAT mapping. [RFC 1035 §4.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.1)

The TCP DNS client sends two questions on one connection before either answer arrives. The resolver returns them in reverse transaction-ID order, with one response crossing a TCP segment boundary. The client reconstructs both messages from the bytes it received. The router is checked for correct translation of the service address and port throughout the stream. [RFC 7766 §§6–8](https://www.rfc-editor.org/rfc/rfc7766.html#section-6) · [RFC 1035 §4.2.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2)

A statically configured LAN device uses DHCPINFORM to request the network mask, default router and DNS servers. The scenario checks the ACK against the configured options and the address pool against its pre-request state, then follows the advertised route to send a DNS query. [RFC 2131 §4.3.5](https://www.rfc-editor.org/rfc/rfc2131.html#section-4.3.5)

Two home devices use CoAP Observe to subscribe to a relay from the same private UDP port. One sends keepalives at 120 and 240 seconds. The other remains idle. The relay sends notifications immediately before, at and immediately after the original 300-second NAT deadline. The oracle checks the application tokens and deliveries, each mapping’s generation and deadline, and release of the idle client’s public port. The 300-second value comes from this router’s configuration. [RFC 4787 §4.3](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3) · [RFC 7641 §3](https://www.rfc-editor.org/rfc/rfc7641.html#section-3)

A client uses the gateway DNS service to resolve a missing name and a camera with only an IPv4 address. It receives NXDOMAIN for the missing name, a NOERROR response with no AAAA answer for the camera, and then a usable A record. The oracle checks each transaction, the SOA authority records in both negative answers, and the same NAT mapping throughout. The UDP fixture contains eight empty AAAA answers with an SOA. [UDP capture](udp/udp_test.pcap) · [RFC 2308 §§2–3](https://www.rfc-editor.org/rfc/rfc2308.html#section-2)

The EDNS exchange uses the gateway’s DNS address and a single UDP mapping for small and large AAAA answers. The client advertises its UDP payload limit in an OPT record. The oracle checks that the resolver receives it, the client receives the complete reply with its OPT record, and an answer larger than 512 bytes fits in one IPv4 datagram. [RFC 6891 §§6.1–6.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1)

The TCP opening exercise loses a SYN beyond the WAN and a handshake ACK before the server receives it. The client repeats its SYN, the server repeats its SYN-ACK, and the client completes an HTTP exchange over the original mapping. The oracle checks that retransmission preserves the connection’s sequence space and translated port. [RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5) · [RFC 6298 §§2 and 5](https://www.rfc-editor.org/rfc/rfc6298.html#section-2)

In the WAN renewal scenario, the established DHCP server refuses the router’s unicast renewal with a DHCPNAK. A LAN lookup crosses the wire before the refusal, then another lookup arrives while the router has no WAN address. After rediscovery the client repeats its query over the new address and receives the DNS answer. The oracle checks the WAN transaction and both NAT directions, plus the LAN leases and pool across the change. [RFC 2131 §4.4.5](https://www.rfc-editor.org/rfc/rfc2131.html#section-4.4.5)

During WAN lease recovery, two DHCP servers offer different addresses and gateways. Their order varies by seed. The oracle reads the requested address and server identifier from the router’s broadcast DHCPREQUEST. It then checks that an unselected offer leaves the pending choice intact, that the selected ACK supplies the installed lease, and that the next DNS packet uses the selected gateway’s Ethernet address. [RFC 2131 §§3.1 and 4.4.1](https://www.rfc-editor.org/rfc/rfc2131.html#section-3.1)

The WAN client also reacquires its current address after the original DHCP server misses renewal. At T2 it broadcasts a DHCPREQUEST. A second server ACKs the existing address with new timers and a different gateway. The router resolves that gateway, carries a LAN client’s DNS request and reply, and sends its next renewal to the server that granted the lease. [RFC 2131 §4.4.5](https://www.rfc-editor.org/rfc/rfc2131.html#section-4.4.5)

During a firmware download, the client fills its receive buffer and advertises a zero TCP window. The server probes with one byte. The client’s window update is lost beyond WAN, so the server probes again, receives the new window, and finishes the download. The oracle checks the repeated byte’s sequence number, each cumulative ACK, the translated connection and the final application bytes. [RFC 9293 §3.8.6.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.6.1)

The established HTTP connection also exercises a lost final ACK during TCP close. One second later the client retransmits its FIN. The server in TIME-WAIT acknowledges the same sequence number, the translated socket remains stable, and neither endpoint receives extra application bytes. [RFC 9293 §§3.6.1 and 3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1)

### NAT filtering modes

Each run sets the router’s filtering mode before starting the two workers. Smith varies the mode alongside the traffic, and the ordinary fixture runs the same UDP scenario under all three settings. A client first contacts one remote UDP endpoint. The peers then send from its original socket, from another port at the same IP, and from a second IP. After the client contacts the second endpoint, that endpoint may reply under all three modes.

| Router mode | Original endpoint | Same IP, different port | Other IP before first contact |
| --- | --- | --- | --- |
| `full_cone` | Forward | Forward | Forward |
| `address_restricted` | Forward | Forward | Drop |
| `endpoint_dependent` | Forward | Drop | Drop |

Mapping and filtering are checked separately. The public socket stays the same across contacts. The oracle verifies peers, both indexes, generation, and expiry as well as the actual forwarded or dropped packets. A capture’s `filtering-mode` file selects the same policy on fresh replay. Older captures default to `address_restricted`. [RFC 4787 §5](https://www.rfc-editor.org/rfc/rfc4787.html#section-5)

## Inspect one seed

```sh
zig build -Doptimize=ReleaseSafe
zig-out/bin/router-sim run /tmp/router-seed-42 42 100000
zig-out/bin/router-sim check /tmp/router-seed-42
```

The arguments after the directory are the seed and the minimum number of bulk inputs per interface. Append `--filtering-mode endpoint_dependent` to select a policy for a seeded run. Setup and control traffic add frames. Each run writes six classic Ethernet PCAPs in the chosen directory, replacing files with the same names. The LAN and WAN each have an RX, expected TX, and actual TX capture. Reuse the seed and count to reproduce the generated conversations.

The LAN worker simulates 16 DHCP clients. The WAN worker acts as the upstream DHCP server, gateway, and remote endpoints. A LAN transmission must first match an independently serialized frame. The simulated server then takes the public socket and application bytes from that transmission to build its reply. While WAN processes earlier requests, LAN issues new ones. The simulated return delay ranges from one to three bursts per run, and replies within a burst arrive in shuffled order. Worker barriers keep each response behind the request that caused it. Virtual time advances at burst boundaries and jumps to lease and probe deadlines.

| Path | Evidence the run requires |
| --- | --- |
| DHCP on both interfaces | Discover, offer, request and ACK. A declined LAN address loses its bindings, stays quarantined under pool pressure, receives three ARP probes, and can be offered again. The WAN exchanges include a successful renewal and a second lease whose unanswered renewal leads to broadcast rebinding, expiry, and a fresh discover. LAN traffic during loss of the WAN lease must drop without creating a NAT binding or ARP waiter. The router must forward in both directions after acquiring a different public address and a different gateway. LAN INFORM and unicast renewal check configuration and the binding deadline. |
| ARP | Six outbound datagrams queue behind one WAN ARP request. The first return datagram also encounters a cold LAN neighbor. The solicited reply on each interface must learn the right MAC, drain the waiter, and transmit the original datagram. An unrelated request must leave the neighbor unknown. Both interfaces defend their addresses. A repeated WAN conflict forces relinquishment. |
| IPv4 and NAT | The independent model checks both NAT indexes, allocated ports, generations, peer lists, and deadlines after every traffic burst. The selected filtering mode determines which outside endpoints may reply. A dropped reply leaves a live mapping intact. Dropping a reply to an expired mapping removes both indexes and releases its port. Another client socket contacts five to eight peers, including repeats. Replies arrive in shuffled order after the peer list fills. The oracle checks admission, eviction, and silence on each reply. |
| TCP, UDP, DNS | Sixteen active hosts can each use 32 sockets per traffic kind. The remote peers consume the verified WAN output and respond in shuffled order within each burst. DNS over UDP and TCP includes A and AAAA questions, positive answers and NXDOMAIN, and restores the gateway service address on return. An answer from the resolver on the wrong source port must be silent and preserve the binding. Downloads use a complete handshake, a request, multiple 1,428-byte response segments, cumulative ACKs and FIN or RST. Some retransmit a segment. Payload size and timestamp options reflect the WAN captures. |
| ICMP and fragmentation | Both interfaces receive whole and fragmented local echo requests. Some reassemblies produce two or three MTU-sized reply fragments. The oracle checks partial table entries, completion, ECN, IPv4 options, offsets and full payload bytes. Routed TCP, UDP, and gateway DNS use head-first and tail-first delivery, with assertions on queued buffers, translated IDs and mapping generations. Both peers originate quoted host unreachable, port unreachable, fragmentation needed with an MTU, and time exceeded messages. |

The wire oracle checks every output of an input or timer tick, including unexpected transmissions and expected silence. The runtime also checks that all 16 LAN bindings, the WAN lease and its timers, and both ARP caches survive the bulk traffic intact. Each seed must visit every registered protocol entry on its applicable interfaces. The IPv6 multicast cases verify that the Ethernet layer reports the EtherType, releases the frame without transmission, and preserves IPv4 state. The tagged WAN cases cover double-tagged protocol 112 advertisements and a positive tagged echo exchange. Full NAT table eviction remains a simulator gap. The optional fragmented ICMP feedback scenario demonstrates a current forwarding failure. Separate every-entry checks measure protocol dispatch. Branches within those handlers require source coverage and specific packet/state assertions. Real NIC timing and DMA require hardware tests. The separate requirements and regression fixtures cover additional cases.

To rerun captured RX through the same two workers, use `zig-out/bin/router-sim replay DIR`, followed by `zig-out/bin/router-sim check DIR`. Replay reads `lan-rx.pcap` and `wan-rx.pcap` and replaces the TX captures. It accepts classic Ethernet PCAPs in either byte order. Capture timestamps determine millisecond groups. The offline check compares complete frame bytes and multiplicity by egress and time group, allowing independent worker outputs to interleave. External captures need the simulator's topology and initial conditions for meaningful comparison with expected TX.

## Reproducing a failure

From an archived evidence directory, use the saved engine and profile. For a failure during native fuzzing, reproduce the original workload size with the `frames` value from `case.json`.

```sh
./router-sim smith /tmp/router-repro input.smith --weights weights.json --full-size 100000
```

For an extended-run failure, use `--frames` in place of `--full-size` with the recorded value. A repeated diagnostic's individual input path is in `failures.jsonl`. `zig build test` also exercises a small deterministic Smith corpus under Zig’s testing allocator. Both NICs, observations and router tables use that allocator during fuzzing. The standalone capture executable uses the SMP allocator.

For interactive source inspection, developers can run the underlying Zig target with `zig build sim-fuzz -j1 --fuzz`. Its local web UI shows instrumented source locations across inputs, including the harness and libraries. The foreground campaign already uses that target for coverage feedback.

## Coverage review

| Scenario | Coverage and evidence |
| --- | --- |
| Concurrent TCP upload and download with selective acknowledgments | The [outbound WAN capture](wan_captures/router_to_isp.pcap) includes 93 segments with 1,388 payload bytes, 79 with 1,448, and nine ACKs carrying SACK blocks. The generated upload reorders segments and checks the SACK ranges, subsequent cumulative ACK, payloads and the distinct mappings of two simultaneous connections. |
| Concurrent DNS questions with several answers | The [combined WAN capture](wan_captures/first_wan_sample.pcap) contains 28 A and 25 AAAA questions from 53 sockets. One response contains eight A records. The generated conversation interleaves answers for multiple clients and checks each transaction against its original socket. |
| Outstanding application reply during WAN lease replacement | A client sends an HTTP request through the old lease. After the lease expires and the gateway changes, late replies to the old public address must stay silent, including while the client reopens the same private port. The retry must use the new gateway and deliver the new response. The oracle checks the old and new NAT keys, the independent live mapping, gateway and client ARP state, and the client’s LAN lease. |

The returning-client sequence starts with an unknown DHCP INIT-REBOOT request carrying option 61. After normal DORA and a later restart, the router must acknowledge the known address by unicast and forward that device’s traffic. The path-MTU scenario translates a 548-byte quote, then verifies a smaller client retry and return on the same NAT mapping. The sleeping-client sequence checks all three queued replies one millisecond before expiry, their release at the deadline, silence on a late ARP reply, and successful delivery of a fresh answer.

The handler review traced dispatch at Ethernet, ARP, IPv4, IPv4 fragmentation, UDP, TCP, gateway DNS, DHCPv4 and each registered ICMPv4 message handler. Reaching a handler does not establish that both sides of each conditional ran. Direct tests separately cover NAT capacity/policy and additional fragment cases. The two late DHCP arrivals cover no preferred address and an occupied preferred address. They exercise initial broadcast and unicast OFFER/ACK, announce their assigned addresses with ARP, and verify return traffic. The reclaim exercise independently predicts probe intervals from the simulated entropy source, checks the tick one millisecond before and at each deadline, and verifies the address becomes available after the final quiet period.

The packet and state oracle predicts translations before using verified wire values in a response. It checks both NAT indexes, allocator bits and unaffected bindings across DHCP removal. A missing expectation on a receive or timer fails the run. A forwarded request that receives ICMP Time Exceeded must resend the missing TCP data before a later ACK can cover it. A fresh PCAP replay checks the two egresses with a new router instance. The model's state assertions run during generation.

### Evidence from live traffic

The November 28 live capture (run `live-20261128-130547`, engine `9624081`) had 906 paired WAN inputs that Google forwarded and the shadow dropped at the 16:13 UTC snapshot. Each of the 20 retained samples was a valid STUN Binding Success response to one UDP socket. Fourteen server IPs appeared across those samples. The XOR-MAPPED-ADDRESS in every response matched the observed WAN destination, and the paired Google LAN packet preserved the payload. The sample does not retain the entire outbound contact sequence.

The `stun_discovery` scenario models overlapping requests to independently simulated servers from one client socket. With address-restricted filtering, four contacted servers can return four replies. With five or fourteen contacts followed by delayed replies, only the four most recently added peers can still reply. This demonstrates the effect of the router’s four-peer history under a known sequence. The same fourteen-server sequence delivered all fourteen replies under full-cone filtering. For the five-server case, save `{"stun_discovery":65535,"fragmented_feedback":0,"gateway_failover":0}` in `/tmp/stun-weights.json` and run `zig-out/bin/router-sim run /tmp/stun-five 432 16384 --weights /tmp/stun-weights.json`. The same five replies can be compared with `--filtering-mode full_cone` in a separate output directory. The contact-history limit is a candidate explanation for the live traffic. [STUN Binding](https://www.rfc-editor.org/rfc/rfc8489.html#section-6.3.1.1)

A separate single-server STUN transaction loses its first response before WAN ingress. After 500 ms the client repeats the same Binding request. The oracle checks the unchanged transaction ID and translated socket, the refreshed mapping, and the public endpoint reported to the client in the successful reply. [RFC 8489 §6.2.1](https://www.rfc-editor.org/rfc/rfc8489.html#section-6.2.1)

The NTP scenario uses an outbound NTPv3 request seen in the WAN capture. Two clients select the same private source port and receive answers in reverse order, including a version 4 RATE response in some runs. The TCP half-close conversation sends an upload and FIN, accepts the server’s response on the remaining half, and checks its checksum against the original upload. The DHCP handover releases a bound guest address, transfers it to a different MAC, and verifies a new flow with the reused ICMP identifier.

### Confirmed forwarding differences

The optional `fragmented_feedback` conversation sends a UDP datagram through NAT, then sends the upstream path-MTU notification as two valid IPv4 fragments. The complete ICMP checksum and the quotation of the actual WAN datagram validate independently. The router reports `BadChecksum` and emits no LAN response when the head arrives. Replacing the same two inputs with the complete datagram makes the fresh replay match both expected egresses. This can prevent a client from learning the smaller path MTU. The ordinary campaign keeps the scenario enabled, records the failing input and retains the expected LAN frame. Separate runs can set its weight to zero to isolate other scenarios.

The endpoint-dependent mode also exposes a remapped ICMP echo identifier issue during ordinary bulk traffic. A capture showed a client sending identifier 20029, the WAN request and valid WAN reply using identifier 49154, and no LAN reply. The expected translated LAN identifier was 20029. A second replay reached the same filter with WAN identifier 49152 and a TTL of 1. The expected WAN output was ICMP Time Exceeded quoting that echo reply. The router sent nothing. The filter runs before the forwarding TTL check. The same mode passed the UDP filtering matrix above. [RFC 1812 §5.3.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.1)

The `gateway_failover` conversation exercises a WAN next hop that keeps its IPv4 address when its hardware changes. The replacement sends an ARP Announcement during an existing DNS flow. The oracle accepts direct cache refresh or an ARP exchange confirming the replacement before the router sends the next query. In a fresh replay the router sent the query to the previous MAC. Repeating the announcement after two seconds and retrying the query at 4.5 seconds produced the same stale destination. A separate replay still used the old MAC 1 ms before the 300-second entry expired. After expiry the router requested the gateway’s MAC, accepted its solicited reply and delivered the queued DNS datagram over the original NAT mapping. Unsolicited-reply handling has a separate regression test. [RFC 826, Packet Reception](https://www.rfc-editor.org/rfc/rfc826) · [RFC 5227 §2.3](https://www.rfc-editor.org/rfc/rfc5227.html#section-2.3)

Two LAN game clients learn each other’s translated UDP sockets from a rendezvous server. Both can exchange relayed updates. With full-cone filtering, a second public address can also reach the client, yet neither direct update to the other player’s public socket emerges on either interface. Both NAT mappings remain live. The oracle expects each update on LAN with the sender’s external source socket and the recipient’s private destination. The restricted-mode scenarios exercise the relay and check admission of the separate WAN probe. [RFC 4787 §6, REQ-9](https://www.rfc-editor.org/rfc/rfc4787.html#section-6)

### Measured baseline

The post-fix native run sampled 57 Smith executions and 19 coverage-distinct inputs. These counts group LLVM instrumentation sites by router source file. The terminal’s overall site count includes simulator and library code. A hit shows a location executed; assertions on output and state establish what that execution checked.

| Router code | Sites hit / instrumented | Evidence and remaining limits |
| --- | --- | --- |
| Ethernet, ARP | 16/25, 53/75 | Ingress dispatch, cold lookup, reply, queue drain, defense, and background IPv6. Direct tests add VLAN and defense boundary cases. |
| DHCPv4, DHCP table | 148/187, 62/95 | Initial lease, renew, rebind, release, quarantine and reclaim on simulated time. Direct tests add competing claims during reclaim. |
| IPv4, transit fragment table, local reassembly table | 133/178, 27/39, 33/40 | Bidirectional forwarding and fragment handling, including two hosts interleaving local datagrams with the same ID. Direct tests add invalid metadata, VLAN separation and maximum datagram size. |
| TCP, UDP, gateway DNS | 7/8, 14/16, 5/5 | Successful and dropped traffic, cancellation, window updates, DNS alias answers and UDP truncation followed by TCP retry. Direct tests add TCP truncation and invalid offsets. |
| ICMPv4 dispatch, echo, unreachable, time exceeded | 44/62, 25/43, 5/8, 13/21 | Echo, quoted errors, translated pings and path-MTU retry. A later positive-weight scenario demonstrated a current failure when a valid ICMP error for a live mapping arrives in fragments. |
| NAT, ARP cache, ARP waiters | 52/80, 15/19, 22/28 | Both NAT indexes, per-protocol occupied ports and cursors, peer updates, deadlines, deferred packets and cleanup. Direct NAT tests cover capacity and alternate filter policy. |

One remaining state transition is a LAN lease reassignment while a packet for its previous owner awaits ARP. The campaign exercises two workers with a controlled schedule; its results do not establish correctness for every thread interleaving.

## Synchronization in the handlers

| Shared state | Critical section |
| --- | --- |
| WAN lease | WAN publishes the entire optional lease under a mutex. Cross-interface readers take a value snapshot. The WAN transaction belongs to the WAN loop. |
| NAT | One mutex covers both indexes, allocation, generation, deadlines and peer lists. Outbound creation or refresh and peer admission are one operation. The handlers rewrite packets after releasing the mutex. |
| ARP | Each interface has its own cache mutex. The slow path rechecks the cache before queueing. Learning and detaching a pending batch use the cache lock followed by the waiters lock. Frame transmission and expired-buffer release happen outside those locks. |
| Logging | Packet attribution is thread-local. The shared sink serializes writing and rotation. |
| Interface-owned tables | The LAN worker owns the DHCP server and quarantine state. The timer signals an event. Fragment forwarding, reassembly, and address defense each have separate state per ingress. |

The mock NIC keeps egress and allocation size with each buffer, so either worker can finish a buffer originally received by its peer. Each capture writer has its own mutex. There is no handler-wide lock.
