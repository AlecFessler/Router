//! Wire-level acceptance tests. REQ numbers refer to REQUIREMENTS.md.
const std = @import("std");
const R = @import("router");
const f = @import("requirements_tests/packets.zig");
const P = f.P;
const expect = std.testing.expect;
const eq = std.testing.expectEqual;
const alloc = std.testing.allocator;
const io = std.testing.io;
const State = R.State;

test "REQ-01 acquire, renew, rebind and stop using an expired WAN lease" {
    var h = try f.H.init(alloc, io, .{});
    defer h.deinit();
    try f.D.tickWan(io, h.nic.api());
    const xid = (try f.message(&h, .wan, .discover)).get(.xid);
    try f.server(&h, xid, 2);
    try f.D.tickWan(io, h.nic.api());
    const request = try f.message(&h, .wan, .request);
    try eq(xid, request.get(.xid));
    try eq(f.public, try f.option(request, .requested_ip_address));
    try eq(f.dhcp_server, try f.option(request, .server_id));
    try f.server(&h, xid +% 1, 5);
    try expect(State.wan_lease == null);
    try f.server(&h, xid, 5);
    const lease = State.wan_lease orelse return error.MissingLease;
    try eq(f.public, lease.ip);
    try eq(f.gateway, lease.router);
    try eq([4]u8{ 255, 255, 255, 0 }, lease.subnet_mask);

    // Advance the timer boundaries without sleeping or replacing the handler.
    h.cacheArp(.wan, f.gateway, f.gm);
    State.wan_lease.?.renewal_deadline = .zero;
    h.nic.resetLogs();
    try f.D.tickWan(io, h.nic.api());
    const renewal = try f.message(&h, .wan, .request);
    try eq(f.public, renewal.get(.client_ip));
    try eq(f.dhcp_server, (try f.emitted(&h, 0, .wan)).get(.dst));
    try eq(f.gm, (try f.Eth.parse(h.txAt(0).bytes)).get(.dst_mac));
    try f.server(&h, renewal.get(.xid), 5);
    try expect(State.wan_lease.?.renewal_deadline.toNanoseconds() > 0);
    State.wan_lease.?.renewal_deadline = .zero;
    State.wan_lease.?.rebinding_deadline = .zero;
    h.nic.resetLogs();
    try f.D.tickWan(io, h.nic.api());
    _ = try f.message(&h, .wan, .request);
    try eq([_]u8{255} ** 4, (try f.emitted(&h, 0, .wan)).get(.dst));
    State.wan_lease.?.expiration_deadline = .zero;
    try f.D.tickWan(io, h.nic.api());
    try expect(State.wan_lease == null);
    _ = try f.message(&h, .wan, .discover);
    h.nic.resetLogs();
    const udp = try P.udp(alloc, f.client, f.peer, .{});
    defer alloc.free(udp);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .payload = udp });
    try eq(@as(usize, 0), h.txCount());
}

test "REQ-02 two LAN clients receive distinct usable leases and a client renews" {
    var h = try f.H.init(alloc, io, .{});
    defer h.deinit();
    var first: ?[4]u8 = null;
    for ([_]f.Eth.Mac{ f.cm, .{ 2, 0, 0, 0, 1, 43 } }, 0..) |mac, i| {
        const xid: u32 = @intCast(i + 50);
        const discover = try f.fixtures.DhcpClient.frame(alloc, mac, .{ .message_type = 1, .xid = xid, .broadcast_flag = true });
        defer alloc.free(discover);
        try f.inject(&h, .lan, discover);
        const offer = try f.message(&h, .lan, .offer);
        try eq(xid, offer.get(.xid));
        const address = offer.get(.your_ip);
        try std.testing.expectEqualSlices(u8, State.lan_ip[0..3], address[0..3]);
        try expect(address[3] > 1 and address[3] < 255);
        if (first) |previous| try expect(!std.mem.eql(u8, &previous, &address)) else first = address;
        const request = try f.fixtures.DhcpClient.frame(alloc, mac, .{ .message_type = 3, .xid = xid, .requested_ip = address, .server_id = State.lan_ip });
        defer alloc.free(request);
        try f.inject(&h, .lan, request);
        const ack = try f.message(&h, .lan, .ack);
        try eq(address, ack.get(.your_ip));
        try eq(xid, ack.get(.xid));
        try eq(State.lan_ip, (try f.option(ack, .router))[0]);
        try eq(State.lan_subnet_mask, try f.option(ack, .subnet_mask));
        try expect((try f.option(ack, .lease_time)).toSeconds() > 0);
        const dns = try f.option(ack, .dns_servers);
        try expect(dns.len > 0 and dns[0][0] != 0);
        try expect(State.dhcp_table.lookupByIp(address) != null);
        h.nic.resetLogs();
        try f.boundClient(&h, mac, .{ .message_type = 3, .xid = xid + 100, .ciaddr = address });
        const renewed = try f.message(&h, .lan, .ack);
        try eq(xid + 100, renewed.get(.xid));
        try eq(address, renewed.get(.your_ip));
    }
}

test "REQ-03 answer local ARP and resolve a cold WAN next hop before forwarding" {
    var h = try f.H.init(alloc, io, .{ .wan_lease = f.activeLease() });
    defer h.deinit();
    for ([_]f.Iface{ .lan, .wan }) |side| {
        const target = if (side == .lan) State.lan_ip else f.public;
        const sender = if (side == .lan) f.client else f.gateway;
        const mac = if (side == .lan) f.cm else f.gm;
        const req = try P.arp(alloc, .{ .sender_mac = mac, .sender_ip = sender, .target_ip = target });
        defer alloc.free(req);
        const eth = try P.eth(alloc, .{ .src = mac, .dst = .{255} ** 6, .ethertype = 0x0806, .payload = req });
        defer alloc.free(eth);
        try f.inject(&h, side, eth);
        try eq(@as(usize, 1), h.txCount());
        try eq(side, h.txAt(0).iface);
        const out = try f.Eth.parse(h.txAt(0).bytes);
        const arp = try R.Protocols.Arp.parse(out.get(.payload));
        try eq(mac, out.get(.dst_mac));
        try eq(target, arp.get(.sender_ip));
        try eq(h.nic.api().macAddress(side), arp.get(.sender_mac));
        try eq(sender, arp.get(.target_ip));
        try eq(@as(u16, 2), @intFromEnum(arp.get(.opcode)));
        h.nic.resetLogs();
    }
    State.wan_arp_table.remove(f.gateway);
    const udp = try P.udp(alloc, f.client, f.peer, .{ .payload = "queued" });
    defer alloc.free(udp);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .payload = udp });
    try eq(@as(usize, 1), h.txCount());
    const solicitation = try R.Protocols.Arp.parse((try f.Eth.parse(h.txAt(0).bytes)).get(.payload));
    try eq(f.gateway, solicitation.get(.target_ip));
    try eq(@as(u16, 1), @intFromEnum(solicitation.get(.opcode)));
    const reply = try P.arp(alloc, .{ .opcode = 2, .sender_mac = f.gm, .sender_ip = f.gateway, .target_ip = f.public, .target_mac = f.Nic.wan_mac });
    defer alloc.free(reply);
    const frame = try P.eth(alloc, .{ .src = f.gm, .dst = f.Nic.wan_mac, .ethertype = 0x0806, .payload = reply });
    defer alloc.free(frame);
    try f.inject(&h, .wan, frame);
    try eq(@as(usize, 2), h.txCount());
    try eq(f.public, (try f.emitted(&h, 1, .wan)).get(.src));
    try eq(f.gm, (try f.Eth.parse(h.txAt(1).bytes)).get(.dst_mac));
}

test "REQ-04 TCP and UDP round trips preserve payload and separate clients sharing a source port" {
    inline for (.{ R.Protocols.Tcp, R.Protocols.Udp }, .{ 6, 17 }) |transport, proto| {
        var h = try f.warm();
        defer h.deinit();
        var previous: ?u16 = null;
        for ([_][4]u8{ f.client, .{ 192, 168, 86, 43 } }) |inside| {
            h.cacheArp(.lan, inside, f.cm);
            const segment = if (proto == 6) try P.tcp(alloc, inside, f.peer, .{ .dst_port = 443, .payload = "request" }) else try P.udp(alloc, inside, f.peer, .{ .dst_port = 443, .payload = "request" });
            defer alloc.free(segment);
            try f.send(&h, .lan, .{ .src = inside, .dst = f.peer, .protocol = proto, .payload = segment });
            const out = try f.emitted(&h, 0, .wan);
            try eq(f.public, out.get(.src));
            try eq(f.peer, out.get(.dst));
            try eq(@as(u8, 63), out.get(.ttl));
            const tx = try transport.parse(out.get(.payload), out);
            const port = tx.get(.src_port);
            if (previous) |old| try expect(port != old);
            previous = port;
            try eq(@as(u16, 443), tx.get(.dst_port));
            try std.testing.expectEqualStrings("request", tx.get(.payload));
            const reply = if (proto == 6) try P.tcp(alloc, f.peer, f.public, .{ .src_port = 443, .dst_port = port, .payload = "response" }) else try P.udp(alloc, f.peer, f.public, .{ .src_port = 443, .dst_port = port, .payload = "response" });
            defer alloc.free(reply);
            try f.send(&h, .wan, .{ .src = f.peer, .dst = f.public, .protocol = proto, .payload = reply });
            const back = try f.emitted(&h, 1, .lan);
            try eq(inside, back.get(.dst));
            try eq(f.peer, back.get(.src));
            try eq(@as(u8, 63), back.get(.ttl));
            const rx = try transport.parse(back.get(.payload), back);
            try eq(@as(u16, 40000), rx.get(.dst_port));
            try std.testing.expectEqualStrings("response", rx.get(.payload));
            h.nic.resetLogs();
        }
    }
}

test "REQ-05 unsolicited WAN UDP and unrelated peers cannot reach a LAN client" {
    var h = try f.warm();
    defer h.deinit();
    const unsolicited = try P.udp(alloc, f.peer, f.public, .{ .src_port = 53, .dst_port = 40000 });
    defer alloc.free(unsolicited);
    try f.send(&h, .wan, .{ .src = f.peer, .dst = f.public, .payload = unsolicited });
    try eq(@as(usize, 0), h.txCount());
    const query = try P.udp(alloc, f.client, f.peer, .{});
    defer alloc.free(query);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .payload = query });
    const out = try f.emitted(&h, 0, .wan);
    const port = (try R.Protocols.Udp.parse(out.get(.payload), out)).get(.src_port);
    const other = [4]u8{ 198, 51, 100, 9 };
    const unrelated = try P.udp(alloc, other, f.public, .{ .src_port = 53, .dst_port = port });
    defer alloc.free(unrelated);
    try f.send(&h, .wan, .{ .src = other, .dst = f.public, .payload = unrelated });
    try eq(@as(usize, 1), h.txCount());
    try eq(@as(usize, 0), h.errorCount());
}

test "REQ-06 echo to the gateway and across NAT returns to the requesting client" {
    var h = try f.warm();
    defer h.deinit();
    const echo = try P.echo(alloc, .{ .identifier = 777, .data = "ping" });
    defer alloc.free(echo);
    try f.send(&h, .lan, .{ .src = f.client, .dst = State.lan_ip, .protocol = 1, .payload = echo });
    const local = try f.emitted(&h, 0, .lan);
    try eq(f.client, local.get(.dst));
    try eq(State.lan_ip, local.get(.src));
    try eq(@as(u8, 0), local.get(.payload)[0]);
    try std.testing.expectEqualSlices(u8, echo[4..], local.get(.payload)[4..]);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .protocol = 1, .payload = echo });
    const out = try f.emitted(&h, 1, .wan);
    try eq(f.public, out.get(.src));
    const ident = std.mem.readInt(u16, out.get(.payload)[4..6], .big);
    const reply = try P.echo(alloc, .{ .message_type = 0, .identifier = ident, .data = "ping" });
    defer alloc.free(reply);
    try f.send(&h, .wan, .{ .src = f.peer, .dst = f.public, .protocol = 1, .payload = reply });
    const back = try f.emitted(&h, 2, .lan);
    try eq(f.client, back.get(.dst));
    _ = try R.Protocols.ICMPv4.parse(back.get(.payload));
    try std.testing.expectEqualSlices(u8, echo[4..], back.get(.payload)[4..]);
}

test "REQ-07 expired TTL returns time exceeded and invalid IPv4 headers are discarded" {
    var h = try f.warm();
    defer h.deinit();
    const udp = try P.udp(alloc, f.client, f.peer, .{ .payload = "trace" });
    defer alloc.free(udp);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .ttl = 1, .payload = udp });
    try eq(@as(usize, 1), h.txCount());
    const ip = try f.emitted(&h, 0, .lan);
    try eq(f.client, ip.get(.dst));
    const icmp = try R.Protocols.ICMPv4.parse(ip.get(.payload));
    try eq(@as(u8, 11), @intFromEnum(icmp.get(.message_type)));
    try eq(@as(u8, 0), icmp.get(.code));
    const quote = try f.IP.parseQuoted(icmp.get(.payload)[4..]);
    try eq(f.peer, quote.get(.dst));
    try eq(f.client, quote.get(.src));
    try f.inject(&h, .lan, "short");
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .checksum = 0x1234, .payload = udp });
    try eq(@as(usize, 1), h.txCount());
    try eq(@as(usize, 2), h.errorCount());
}

test "REQ-08 return ICMP errors to the originator with a usable quote and path MTU" {
    var h = try f.warm();
    defer h.deinit();
    // Occupy this public port with another client's real outbound packet.
    const other = [4]u8{ 192, 168, 86, 43 };
    const competing = try P.udp(alloc, other, f.peer, .{ .src_port = 42345 });
    defer alloc.free(competing);
    try f.send(&h, .lan, .{ .src = other, .dst = f.peer, .payload = competing });
    _ = try f.emitted(&h, 0, .wan);
    h.nic.resetLogs();
    const udp = try P.udp(alloc, f.client, f.peer, .{ .src_port = 42345, .payload = "path MTU" });
    defer alloc.free(udp);
    try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .payload = udp });
    const wan = try f.Eth.parse(h.txAt(0).bytes);
    var body: [32]u8 = undefined;
    // Standard minimum quote, IPv4 header plus the first eight data bytes.
    @memcpy(body[4..], wan.get(.payload)[0..28]);
    for ([_][2]u8{ .{ 3, 1 }, .{ 3, 3 }, .{ 3, 4 }, .{ 11, 0 } }, 1..) |kind, index| {
        body[0..4].* = if (kind[1] == 4) .{ 0, 0, 5, 120 } else .{ 0, 0, 0, 0 };
        const err = try P.icmp(alloc, .{ .message_type = kind[0], .code = kind[1], .body = &body });
        defer alloc.free(err);
        try f.send(&h, .wan, .{ .src = f.gateway, .dst = f.public, .protocol = 1, .payload = err });
        const ip = try f.emitted(&h, index, .lan);
        try eq(f.client, ip.get(.dst));
        const msg = try R.Protocols.ICMPv4.parse(ip.get(.payload));
        try eq(kind[0], @intFromEnum(msg.get(.message_type)));
        try eq(kind[1], msg.get(.code));
        try std.testing.expectEqualSlices(u8, body[0..4], msg.get(.payload)[0..4]);
        const quote = try f.IP.parseQuoted(msg.get(.payload)[4..]);
        try eq(f.client, quote.get(.src));
        try eq(f.peer, quote.get(.dst));
        try std.testing.expectEqualSlices(u8, udp[0..8], quote.get(.payload));
    }
}

test "REQ-09 inbound TCP and UDP fragments retain a coherent translation in either order" {
    inline for (.{ R.Protocols.Tcp, R.Protocols.Udp }, .{ 6, 17 }) |transport, proto| {
        for ([_]bool{ false, true }) |reverse| {
            var h = try f.warm();
            defer h.deinit();
            const query = if (proto == 6) try P.tcp(alloc, f.client, f.peer, .{ .dst_port = 443 }) else try P.udp(alloc, f.client, f.peer, .{ .dst_port = 443 });
            defer alloc.free(query);
            try f.send(&h, .lan, .{ .src = f.client, .dst = f.peer, .protocol = proto, .payload = query });
            const wan = try f.emitted(&h, 0, .wan);
            const port = (try transport.parse(wan.get(.payload), wan)).get(.src_port);
            const data = "fragmented transport payload for acceptance";
            const response = if (proto == 6) try P.tcp(alloc, f.peer, f.public, .{ .src_port = 443, .dst_port = port, .payload = data }) else try P.udp(alloc, f.peer, f.public, .{ .src_port = 443, .dst_port = port, .payload = data });
            defer alloc.free(response);
            h.nic.resetLogs();
            for ([_]bool{ reverse, !reverse }, 0..) |tail, i| {
                try f.send(&h, .wan, .{ .src = f.peer, .dst = f.public, .protocol = proto, .identification = 1234, .more_fragments = !tail, .fragment_offset = if (tail) 3 else 0, .payload = if (tail) response[24..] else response[0..24] });
                if (tail and i == 0) try eq(@as(usize, 0), h.txCount());
            }
            const packet = try f.emitted(&h, 0, .lan);
            try eq(f.client, packet.get(.dst));
            const joined = if (h.txCount() == 1) blk: {
                try expect(!packet.get(.more_fragments) and packet.get(.fragment_offset) == 0);
                break :blk try alloc.dupe(u8, packet.get(.payload));
            } else blk: {
                try eq(@as(usize, 2), h.txCount());
                const second = try f.emitted(&h, 1, .lan);
                try eq(f.client, second.get(.dst));
                const first, const last = if (packet.get(.fragment_offset) == 0) .{ packet, second } else .{ second, packet };
                try eq(first.get(.identification), last.get(.identification));
                try eq(@as(u13, 0), first.get(.fragment_offset));
                try expect(first.get(.more_fragments) and !last.get(.more_fragments));
                try eq(first.get(.payload).len, @as(usize, last.get(.fragment_offset)) * 8);
                break :blk try std.mem.concat(alloc, u8, &.{ first.get(.payload), last.get(.payload) });
            };
            defer alloc.free(joined);
            const rebuilt = try P.ipv4(alloc, .{ .src = f.peer, .dst = f.client, .protocol = proto, .payload = joined });
            defer alloc.free(rebuilt);
            const ip = try f.IP.parse(rebuilt);
            const result = try transport.parse(joined, ip);
            try eq(@as(u16, 40000), result.get(.dst_port));
            try std.testing.expectEqualStrings(data, result.get(.payload));
        }
    }
}

test "REQ-10 clients retaining Google's DNS option can resolve through the gateway after cutover" {
    var h = try f.warm();
    defer h.deinit();
    // Synthetic A question for cutover.example., transaction 0x2580, RD set.
    const question = "\x07cutover\x07example\x00\x00\x01\x00\x01";
    const query = "\x25\x80\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ question;
    const client_port = 53008;
    const leased_dns = [4]u8{ 192, 168, 86, 1 };
    const udp = try P.udp(alloc, f.client, leased_dns, .{ .src_port = client_port, .dst_port = 53, .payload = query });
    defer alloc.free(udp);
    try f.send(&h, .lan, .{ .src = f.client, .dst = leased_dns, .identification = 0x25, .dont_fragment = true, .payload = udp });
    const first = h.lastTx() orelse return error.NoDnsServiceForExistingLease;
    // A proxy may choose its own public port, resolver and DNS transaction ID.
    if (first.iface == .wan) {
        const ip = try f.emitted(&h, 0, .wan);
        const request = try R.Protocols.Udp.parse(ip.get(.payload), ip);
        try eq(@as(u16, 53), request.get(.dst_port));
        const dns = request.get(.payload);
        try expect(dns.len >= 12 + question.len);
        try std.testing.expectEqualSlices(u8, question, dns[12..][0..question.len]);
        const resource = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x07";
        const answer = try std.mem.concat(alloc, u8, &.{ dns[0..2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", question, resource });
        defer alloc.free(answer);
        const upstream = try P.udp(alloc, ip.get(.dst), ip.get(.src), .{ .src_port = 53, .dst_port = request.get(.src_port), .payload = answer });
        defer alloc.free(upstream);
        try f.send(&h, .wan, .{ .src = ip.get(.dst), .dst = ip.get(.src), .payload = upstream });
    }
    const ip = try f.emitted(&h, h.txCount() - 1, .lan);
    try eq(f.client, ip.get(.dst));
    const reply = try R.Protocols.Udp.parse(ip.get(.payload), ip);
    try eq(leased_dns, ip.get(.src));
    try eq(@as(u16, 53), reply.get(.src_port));
    try eq(@as(u16, client_port), reply.get(.dst_port));
    const dns = reply.get(.payload);
    try expect(dns.len >= 12 + question.len + 16);
    try std.testing.expectEqualSlices(u8, query[0..2], dns[0..2]);
    try expect(dns[2] & 0x80 != 0 and dns[3] & 15 == 0);
    try eq(@as(u16, 1), std.mem.readInt(u16, dns[6..8], .big));
    try std.testing.expectEqualSlices(u8, question, dns[12..][0..question.len]);
    try expect(std.mem.indexOf(u8, dns[12 + question.len ..], "\x00\x04\xc0\x00\x02\x07") != null);
}

test "REQ-10 gateway DNS and direct DNS from one TCP socket keep distinct reply endpoints" {
    var h = try f.warm();
    defer h.deinit();
    const resolver = R.Protocols.Dns.upstream.ip;
    const gateway = State.lan_ip;
    const client_port: u16 = 45123;
    const question = "\x07cutover\x07example\x00\x00\x01\x00\x01";
    // Length-prefixed DNS messages as carried by TCP.
    const query = "\x00\x21\x25\x80\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ question;
    const answer = "\x00\x21\x25\x80\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" ++ question;
    var ports: [2]u16 = undefined;
    const endpoints = [_]f.IP.IPv4{ resolver, gateway };

    for (endpoints, &ports) |endpoint, *mapped_port| {
        const syn = try P.tcp(alloc, f.client, endpoint, .{ .src_port = client_port, .dst_port = 53, .syn = true, .ack = false });
        defer alloc.free(syn);
        try f.send(&h, .lan, .{ .src = f.client, .dst = endpoint, .protocol = 6, .payload = syn });
        const ip = try f.emitted(&h, h.txCount() - 1, .wan);
        try eq(resolver, ip.get(.dst));
        const tcp = try R.Protocols.Tcp.parse(ip.get(.payload), ip);
        try expect(tcp.get(.syn));
        mapped_port.* = tcp.get(.src_port);
    }
    try expect(ports[0] != ports[1]);

    for (endpoints, ports) |endpoint, mapped_port| {
        const syn_ack = try P.tcp(alloc, resolver, f.public, .{ .src_port = 53, .dst_port = mapped_port, .syn = true, .ack_number = 1 });
        defer alloc.free(syn_ack);
        try f.send(&h, .wan, .{ .src = resolver, .dst = f.public, .protocol = 6, .payload = syn_ack });
        const ack_ip = try f.emitted(&h, h.txCount() - 1, .lan);
        try eq(endpoint, ack_ip.get(.src));
        const ack = try R.Protocols.Tcp.parse(ack_ip.get(.payload), ack_ip);
        try expect(ack.get(.syn) and ack.get(.ack));
        try eq(client_port, ack.get(.dst_port));

        const data = try P.tcp(alloc, f.client, endpoint, .{ .src_port = client_port, .dst_port = 53, .seq_number = 1, .ack_number = 1, .payload = query });
        defer alloc.free(data);
        try f.send(&h, .lan, .{ .src = f.client, .dst = endpoint, .protocol = 6, .payload = data });
        const wan = try f.emitted(&h, h.txCount() - 1, .wan);
        try eq(resolver, wan.get(.dst));
        const request = try R.Protocols.Tcp.parse(wan.get(.payload), wan);
        try eq(mapped_port, request.get(.src_port));
        try std.testing.expectEqualSlices(u8, query, request.get(.payload));

        const result = try P.tcp(alloc, resolver, f.public, .{ .src_port = 53, .dst_port = mapped_port, .seq_number = 1, .ack_number = 1 + query.len, .payload = answer });
        defer alloc.free(result);
        try f.send(&h, .wan, .{ .src = resolver, .dst = f.public, .protocol = 6, .payload = result });
        const lan = try f.emitted(&h, h.txCount() - 1, .lan);
        try eq(endpoint, lan.get(.src));
        try eq(f.client, lan.get(.dst));
        const reply = try R.Protocols.Tcp.parse(lan.get(.payload), lan);
        try eq(@as(u16, 53), reply.get(.src_port));
        try eq(client_port, reply.get(.dst_port));
        try std.testing.expectEqualSlices(u8, answer, reply.get(.payload));
    }
}

test "REQ-10 fragmented gateway DNS uses the same resolver in both directions and rejects unrelated WAN packets" {
    var h = try f.warm();
    defer h.deinit();
    const old_mode = State.nat_filtering_mode;
    defer State.nat_filtering_mode = old_mode;
    State.nat_filtering_mode = .full_cone;
    const client_port: u16 = 53001;
    const question = "\x07cutover\x07example\x00\x00\x41\x00\x01";
    const query = "\x00\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ question;
    const answer = "\x00\x42\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" ++ question;
    const gateway = State.lan_ip;
    const resolver = R.Protocols.Dns.upstream.ip;
    var mapped_port: u16 = undefined;
    for ([_]f.Iface{ .lan, .wan }) |ingress| {
        const outbound = ingress == .lan;
        const src = if (outbound) f.client else resolver;
        const dst = if (outbound) gateway else f.public;
        const payload: []const u8 = if (outbound) query else answer;
        const udp = try P.udp(alloc, src, dst, .{ .src_port = if (outbound) client_port else 53, .dst_port = if (outbound) 53 else mapped_port, .payload = payload });
        defer alloc.free(udp);

        h.nic.resetLogs();
        try f.send(&h, ingress, .{ .src = src, .dst = dst, .identification = 42, .fragment_offset = 3, .payload = udp[24..] });
        try eq(@as(usize, 0), h.txCount());
        try f.send(&h, ingress, .{ .src = src, .dst = dst, .identification = 42, .more_fragments = true, .payload = udp[0..24] });
        try eq(@as(usize, 2), h.txCount());
        const egress: f.Iface = if (outbound) .wan else .lan;
        const first = try f.emitted(&h, 0, egress);
        const tail = try f.emitted(&h, 1, egress);
        for ([_]f.IP.IPv4PacketView{ first, tail }) |part| {
            try eq(if (outbound) f.public else gateway, part.get(.src));
            try eq(if (outbound) resolver else f.client, part.get(.dst));
        }
        try eq(first.get(.identification), tail.get(.identification));
        try eq(@as(u13, 3), tail.get(.fragment_offset));
        const joined = try std.mem.concat(alloc, u8, &.{ first.get(.payload), tail.get(.payload) });
        defer alloc.free(joined);
        const rebuilt = try P.ipv4(alloc, .{ .src = first.get(.src), .dst = first.get(.dst), .payload = joined });
        defer alloc.free(rebuilt);
        const parsed = try R.Protocols.Udp.parse(joined, try f.IP.parse(rebuilt));
        try std.testing.expectEqualSlices(u8, payload, parsed.get(.payload));
        if (outbound) mapped_port = parsed.get(.src_port);
        try eq(if (outbound) @as(u16, 53) else client_port, parsed.get(.dst_port));
    }

    h.nic.resetLogs();
    for ([_]f.IP.IPv4{ f.peer, resolver, f.peer }, [_]u16{ 53, 5353, 53000 }, [_]u16{ mapped_port, mapped_port, 53 }) |src, sport, dport| {
        const packet = try P.udp(alloc, src, f.public, .{ .src_port = sport, .dst_port = dport, .payload = answer });
        defer alloc.free(packet);
        try f.send(&h, .wan, .{ .src = src, .dst = f.public, .payload = packet });
        try eq(@as(usize, 0), h.txCount());
    }
}

test "REQ-08 ICMP errors for gateway DNS quote the endpoint visible to the recipient" {
    var h = try f.warm();
    defer h.deinit();
    const gateway = State.lan_ip;
    const resolver = R.Protocols.Dns.upstream.ip;
    const client_port: u16 = 43210;
    const query = try P.udp(alloc, f.client, gateway, .{ .src_port = client_port, .dst_port = 53, .payload = "question" });
    defer alloc.free(query);
    try f.send(&h, .lan, .{ .src = f.client, .dst = gateway, .payload = query });
    const wan = try f.emitted(&h, 0, .wan);
    const mapped_port = (try R.Protocols.Udp.parse(wan.get(.payload), wan)).get(.src_port);
    const answer = try P.udp(alloc, resolver, f.public, .{ .src_port = 53, .dst_port = mapped_port, .payload = "answer" });
    defer alloc.free(answer);
    try f.send(&h, .wan, .{ .src = resolver, .dst = f.public, .payload = answer });

    for ([_]f.Iface{ .wan, .lan }, 0..) |side, i| {
        const from_wan = side == .wan;
        const original = try f.Eth.parse(h.txAt(i).bytes);
        var body = [_]u8{0} ** 32;
        @memcpy(body[4..], original.get(.payload)[0..28]);
        const icmp = try P.icmp(alloc, .{ .message_type = 3, .code = 3, .body = &body });
        defer alloc.free(icmp);
        try f.send(&h, side, .{ .src = if (from_wan) resolver else f.client, .dst = if (from_wan) f.public else gateway, .protocol = 1, .payload = icmp });
        const ip = try f.emitted(&h, 2 + i, if (from_wan) .lan else .wan);
        try eq(if (from_wan) gateway else f.public, ip.get(.src));
        try eq(if (from_wan) f.client else resolver, ip.get(.dst));
        const message = try R.Protocols.ICMPv4.parse(ip.get(.payload));
        const quote = try f.IP.parseQuoted(message.get(.payload)[4..]);
        try eq(ip.get(.dst), quote.get(.src));
        try eq(ip.get(.src), quote.get(.dst));
        try std.testing.expectEqualSlices(u8, if (from_wan) query[0..8] else answer[0..8], quote.get(.payload));
    }
}
