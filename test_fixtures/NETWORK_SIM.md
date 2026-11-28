# Two-interface network simulation

## Continuous validation

From the repository root, start the foreground campaign with one command.

```sh
zig build sim
```

The native Linux campaign runner builds the Zig fuzzer and the capture executable from the same source snapshot, including uncommitted changes. Zig's coverage-guided Smith worker varies the scenarios, packet fields, scheduling, and workload size. Most input mutations select a short workload. The initial campaign corpus includes a full-size choice. Full-size inputs use the campaign’s frame budget and contribute coverage to the same corpus. After each batch the supervisor also selects a real corpus input, extends it to 100,000 bulk inputs per interface, saves the six PCAP streams temporarily, and verifies both egresses again on a fresh router. The long replay gives wire-level evidence for that input.

The terminal reports failing cases and coverage after each batch. To view the existing workstation session, run `tmux attach -t router-sim`. Press Ctrl+B, then D, to detach and leave it running. Ctrl+C stops the campaign. The same command resumes the corpus and the next batch. Results default to `~/.local/state/router-sim`.

- `status.json` records the current stage, batch seed, executable hash, resolved weights, cumulative fuzz counters for the current build/profile, the current corpus size, and catalog dispatches from successful extended runs. Passed and failed batch counts span versions. The fuzz counters describe the current source and profile. Zig’s coverage-distinct run count and the number of saved corpus inputs are separate measurements.
- `failures.jsonl` records failing inputs and timeouts. Evidence includes the exact Smith bytes, profile, source snapshot, executable, relevant logs and available captures. A capture replay may pass for a timing-dependent or test-allocator-only failure. The saved original outcome stands.
- Zig stops its worker when it finds a failure. The supervisor archives the case first, skips that exact decoded input on later instrumented runs of the same version/profile/budget, then starts another coverage-guided batch. Related inputs remain eligible. Repeated extended-run diagnostics reference the first capture and retain their individual Smith bytes. `--keep-all` saves full evidence for repeats.
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
| Longer conversations | TCP download, UDP peer rotation, path-MTU recovery, parallel DNS, overlapping TCP upload/download, canceled download and reconnect, TCP window update, truncated DNS followed by TCP retry, interleaved local IPv4 fragments | 5, 1, 1, 2, 2, 1, 1, 1, 1 |

Weights apply among eligible options. A client waits for its address and gateway resolution before sending ordinary traffic. Forwarded conversations also require a bound WAN lease. TCP sockets stay busy until the reply burst completes. The reported catalog counts show the callbacks selected from these tables. Directed steps may also exercise the same packet behavior. For example, a profile containing `{"udp":54,"tcp":27}` changes those two LAN weights and inherits the other defaults. `zig-out/bin/router-sim weights profile.json` prints the resolved profile. A zero disables an optional pick in its pool. The guaranteed exercises still run.

The same catalog lists the directed startup and lease lifecycle steps, plus the flow outcomes. Every seed runs the prerequisites, the flow/outcome combinations, and the conversations marked mandatory in the catalog. The later clock-driven steps exercise actual lease and quarantine deadlines in order. Audit these lists alongside the selectable rows. Use the test's source coverage view to check for missing branches *inside* a listed scenario.

## Inspect one seed

```sh
zig build -Doptimize=ReleaseSafe
zig-out/bin/router-sim run /tmp/router-seed-42 42 100000
zig-out/bin/router-sim check /tmp/router-seed-42
```

The arguments after the directory are the seed and the minimum number of bulk inputs per interface. Setup and control traffic add frames. Each run writes six classic Ethernet PCAPs in the chosen directory, replacing files with the same names. The LAN and WAN each have an RX, expected TX, and actual TX capture. Reuse the seed and count to reproduce the generated conversations.

The LAN worker simulates 16 DHCP clients. The WAN worker acts as the upstream DHCP server, gateway, and remote endpoints. A LAN transmission must first match an independently serialized frame. The simulated server then takes the public socket and application bytes from that transmission to build its reply. While WAN processes earlier requests, LAN issues new ones. The simulated return delay ranges from one to three bursts per run, and replies within a burst arrive in shuffled order. Worker barriers keep each response behind the request that caused it. Virtual time advances at burst boundaries and jumps to lease and probe deadlines.

| Path | Evidence the run requires |
| --- | --- |
| DHCP on both interfaces | Discover, offer, request and ACK. A declined LAN address loses its bindings, stays quarantined under pool pressure, receives three ARP probes, and can be offered again. The WAN exchanges include a successful renewal and a second lease whose unanswered renewal leads to broadcast rebinding, expiry, and a fresh discover. LAN traffic during loss of the WAN lease must drop without creating a NAT binding or ARP waiter. The router must forward in both directions after acquiring a different public address and a different gateway. LAN INFORM and unicast renewal check configuration and the binding deadline. |
| ARP | Six outbound datagrams queue behind one WAN ARP request. The first return datagram also encounters a cold LAN neighbor. The solicited reply on each interface must learn the right MAC, drain the waiter, and transmit the original datagram. An unrelated request must leave the neighbor unknown. Both interfaces defend their addresses. A repeated WAN conflict forces relinquishment. |
| IPv4 and NAT | The independent model checks both NAT indexes, allocated ports, generations, peer lists, and deadlines after every traffic burst. Dropping an uncontacted peer leaves a live mapping intact. Dropping a reply to an expired mapping removes both indexes and releases its port. Another client socket contacts five to eight peers, including repeats. Replies arrive in shuffled order after the peer list fills. The oracle checks admission, eviction, and silence on each reply. |
| TCP, UDP, DNS | Sixteen active hosts can each use 32 sockets per traffic kind. The remote peers consume the verified WAN output and respond in shuffled order within each burst. DNS over UDP and TCP includes A and AAAA questions, positive answers and NXDOMAIN, and restores the gateway service address on return. An answer from the resolver on the wrong source port must be silent and preserve the binding. Downloads use a complete handshake, a request, multiple 1,428-byte response segments, cumulative ACKs and FIN or RST. Some retransmit a segment. Payload size and timestamp options reflect the WAN captures. |
| ICMP and fragmentation | Both interfaces receive whole and fragmented local echo requests. Some reassemblies produce two or three MTU-sized reply fragments. The oracle checks partial table entries, completion, ECN, IPv4 options, offsets and full payload bytes. Routed TCP, UDP, and gateway DNS use head-first and tail-first delivery, with assertions on queued buffers, translated IDs and mapping generations. Both peers originate quoted host unreachable, port unreachable, fragmentation needed with an MTU, and time exceeded messages. |

The wire oracle checks every output of an input or timer tick, including unexpected transmissions and expected silence. The runtime also checks that all 16 LAN bindings, the WAN lease and its timers, and both ARP caches survive the bulk traffic intact. Each seed must visit every registered protocol entry on its applicable interfaces. The IPv6 multicast cases verify that the Ethernet layer reports the EtherType, releases the frame without transmission, and preserves IPv4 state. The tagged WAN cases cover double-tagged protocol 112 advertisements and a positive tagged echo exchange. Remaining simulator gaps include full NAT table eviction and alternate filtering policies. The optional fragmented ICMP feedback scenario demonstrates a current forwarding failure. Separate every-entry checks measure protocol dispatch. Branches within those handlers require source coverage and specific packet/state assertions. Real NIC timing and DMA require hardware tests. The separate requirements and regression fixtures cover additional cases.

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

### Confirmed forwarding difference

The optional `fragmented_feedback` conversation sends a UDP datagram through NAT, then sends the upstream path-MTU notification as two valid IPv4 fragments. The complete ICMP checksum and the quotation of the actual WAN datagram validate independently. The router reports `BadChecksum` and emits no LAN response when the head arrives. Replacing the same two inputs with the complete datagram makes the fresh replay match both expected egresses. This can prevent a client from learning the smaller path MTU. The ordinary campaign keeps the scenario enabled, records the failing input and retains the expected LAN frame. Separate runs can set its weight to zero to isolate other scenarios.

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
