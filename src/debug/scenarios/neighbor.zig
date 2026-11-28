const std = @import("std");
const Router = @import("router");
const State = Router.State;
const IFace = Router.Nic.Api.IFace;
const Nat = Router.Tables.NatTable.NatTable;
const Sim = @import("../network_sim.zig");

pub const SleepingClient = struct {
    requests: [4]Sim.Job = undefined,
    generation: u64 = 0,
    bindings_before: usize = 0,
    binding_deadline: std.Io.Timestamp = .zero,
    waiter_deadline: std.Io.Timestamp = .zero,

    pub fn step(self: *SleepingClient, peer: *Sim.Peer, phase: Sim.Scenarios.Lifecycle) !void {
        const iface: IFace = switch (phase) {
            .sleeping_client_queries, .sleeping_client_late_arp, .sleeping_client_retries => .lan,
            .sleeping_client_replies, .sleeping_client_still_waiting, .sleeping_client_timeout, .sleeping_client_recovers => .wan,
            else => unreachable,
        };
        if (peer.iface != iface) return;
        var scratch = std.heap.FixedBufferAllocator.init(&peer.scratch);
        const alloc = scratch.allocator();
        const now = std.Io.Timestamp.now(peer.network.io, .boot);
        switch (phase) {
            .sleeping_client_queries => for (0..3) |i| try self.query(peer, alloc, i),
            .sleeping_client_replies => {
                self.waiter_deadline = now.addDuration(.fromSeconds(2));
                try self.answer(peer, alloc, 0);
                try self.answer(peer, alloc, 1);
            },
            .sleeping_client_still_waiting => {
                if (now.durationTo(self.waiter_deadline).toMilliseconds() != 1) return error.WrongSleepingClientClock;
                try peer.beginObservation();
                State.arp_waiters_table.expire(peer.network.mock.api());
                try peer.count(0);
                try self.checkQueue(peer, alloc, 2);
                try self.answer(peer, alloc, 2);
            },
            .sleeping_client_retries => try self.query(peer, alloc, 3),
            .sleeping_client_recovers => try self.answer(peer, alloc, 3),
            .sleeping_client_timeout => {
                if (!std.meta.eql(self.waiter_deadline, now)) return error.WrongSleepingClientClock;
                try peer.beginObservation();
                State.arp_waiters_table.expire(peer.network.mock.api());
                try peer.count(0);
                try self.checkQueue(peer, alloc, 0);
                // An unrelated ARP request on the uplink records this timer instant in the replay.
                try peer.inject(try Sim.arp(alloc, Sim.gateway_mac, .{ 198, 51, 100, 254 }, .{ 198, 51, 100, 253 }, null));
                try peer.expectDrop();
            },
            .sleeping_client_late_arp => {
                const job = self.requests[0];
                try peer.inject(try Sim.arp(alloc, job.mac(), job.host(), Sim.lan, Sim.lan_mac));
                try peer.count(0);
                try self.checkQueue(peer, alloc, 0);
                const index = State.lan_arp_table.indexOfValue(.ip, job.host()) orelse return error.WrongArpState;
                const entry = State.lan_arp_table.table.get(index);
                if (!std.meta.eql(entry.mac, job.mac()) or !std.meta.eql(entry.timestamp, now)) return error.WrongArpState;
            },
            else => unreachable,
        }
        const job = self.requests[0];
        const nat = &State.nat_table;
        const outside: Nat.Key = .{ .protocol = .udp, .ip = job.wan_ip, .port = job.public_port };
        const entry = nat.inside.get(job.insideKey()) orelse return error.MissingNatState;
        if (entry.generation != self.generation or !std.meta.eql(entry.deadline, self.binding_deadline) or
            !std.meta.eql(entry.outside, outside) or !std.meta.eql(nat.outside.get(outside), @as(?Nat.Key, job.insideKey())) or
            entry.peer_count != 1 or !std.meta.eql(entry.peers[0], Nat.Peer{ .ip = Sim.dns, .port = 53 }) or
            nat.inside.count() != self.bindings_before + 1 or nat.outside.count() != self.bindings_before + 1 or
            nat.next_generation != self.generation + 1 or !nat.udp_ports.used.isSet(job.public_port)) return error.WrongSleepingClientMapping;
    }

    fn query(self: *SleepingClient, peer: *Sim.Peer, alloc: std.mem.Allocator, i: usize) !void {
        const job = &self.requests[i];
        job.* = peer.network.cold;
        job.choice.kind = .dns_udp;
        job.choice.host = 2;
        job.choice.token = @as(u16, @truncate(peer.network.seed)) +% @as(u16, @intCast(i));
        job.remote = Sim.dns;
        job.wan_ip = peer.network.opened[@intFromEnum(Sim.Scenarios.Flow.tcp)].?.wan_ip;
        job.source_port = 37053;
        job.public_port = if (i == 0) peer.network.reservePort(.udp, job.source_port) else self.requests[0].public_port;
        job.makeDnsQuery(@truncate(job.choice.token), "www".*);
        if (i == 0) {
            const nat = &State.nat_table;
            if (nat.inside.contains(job.insideKey()) or nat.udp_ports.used.isSet(job.public_port)) return error.SleepingClientSocketInUse;
            const index = State.dhcp_table.lookupByIp(job.host()) orelse return error.MissingLanLease;
            const lease = State.dhcp_table.table.get(index);
            if (lease.state != .bound or !std.meta.eql(lease.mac, job.mac())) return error.MissingLanLease;
            self.generation = peer.network.newConversationBinding();
            self.bindings_before = nat.inside.count();
        }
        self.binding_deadline = std.Io.Timestamp.now(peer.network.io, .boot).addDuration(.fromSeconds(300));
        try peer.inject(try Sim.packet(alloc, job.*, false, false, 64));
        try peer.count(1);
        const tx = try peer.expect(0, .wan, try Sim.packet(alloc, job.*, false, true, 63));
        @memcpy(job.payload[0..job.len], tx[tx.len - job.len ..]);
    }

    fn answer(self: *SleepingClient, peer: *Sim.Peer, alloc: std.mem.Allocator, i: usize) !void {
        var reply = self.requests[i];
        reply.makeResponse();
        try peer.inject(try Sim.packet(alloc, reply, true, false, 64));
        switch (i) {
            0 => {
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.arp(alloc, Sim.lan_mac, Sim.lan, reply.host(), null));
            },
            3 => {
                try peer.count(1);
                _ = try peer.expect(0, .lan, try Sim.packet(alloc, reply, true, true, 63));
            },
            else => try peer.count(0),
        }
        try self.checkQueue(peer, alloc, if (i == 3) 0 else i + 1);
    }

    fn checkQueue(self: *const SleepingClient, peer: *Sim.Peer, alloc: std.mem.Allocator, pending: usize) !void {
        const waiters = &State.arp_waiters_table.table;
        if (waiters.count() != @intFromBool(pending != 0) or peer.network.mock.outstanding.load(.monotonic) != pending) return error.WrongSleepingClientQueue;
        if (pending == 0) return;
        const host = self.requests[0].host();
        const entry = waiters.get(.{ .iface = .lan, .ip = host }) orelse return error.MissingArpWaiter;
        if (entry.len != pending or !std.meta.eql(entry.deadline, self.waiter_deadline) or
            State.lan_arp_table.indexOfValue(.ip, host) != null) return error.WrongSleepingClientQueue;
        for (self.requests[0..pending], entry.buffers[0..pending]) |job, buffer| {
            var reply = job;
            reply.makeResponse();
            const expected = try Sim.packet(alloc, reply, true, true, 63);
            // The destination MAC is filled only when ARP resolves.
            if (buffer.len != expected.len or !std.mem.eql(u8, expected[6..], buffer[6..])) return error.WrongSleepingClientBuffer;
        }
    }
};
