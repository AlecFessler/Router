const std = @import("std");
const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const Ethernet = Router.Protocols.Ethernet;
const Fiber = Router.Async.Fiber.Fiber;
const FiberPool = Router.Async.FiberPool.FiberPool;
const ICMPv4Fixtures = Router.TestFixtures.ICMPv4;
const IFace = Router.Nic.Api.IFace;
const Mock = Router.Nic.Testing.Mock;
const NatTable = Router.Tables.NatTable.NatTable;
const NicApi = Router.Nic.Api.Api;
const ReadyQueue = Router.Async.ReadyQueue.ReadyQueue;
const Running = Router.Async.Running;
const State = Router.State;
const ViewStack = Router.Protocols.ViewStack;

const setRunning = Router.Async.setRunning;

const ARP_CAPACITY: u32 = 256;
const ARP_TTL = std.Io.Duration.fromSeconds(300);
const ARP_WAITERS_CAPACITY: usize = 256;
const ARP_WAITERS_TIMEOUT = std.Io.Duration.fromSeconds(2);
const FIBER_CACHE_CAPACITY: usize = 64;
const FIBER_STACK_SIZE: usize = 8 * 1024;
const NAT_CAPACITY: u32 = 16_384;

const PacketTask = struct {
    buffer: []u8,
    device: NicApi,
    iface: IFace,
    loop_context: *std.Io.fiber.Context,
    done: bool = false,

    fn start(fiber: *Fiber, arg: *anyopaque) noreturn {
        const self: *PacketTask = @ptrCast(@alignCast(arg));
        var views: ViewStack = .{};
        Ethernet.handle(self.buffer, self.device, self.iface, &views) catch |err| {
            self.device.release(self.buffer);
            std.debug.print("Error: {}\n", .{err});
        };
        self.done = true;
        Fiber.switchTo(fiber, self.loop_context);
        unreachable;
    }
};

fn runFiber(alloc: std.mem.Allocator, loop_context: *std.Io.fiber.Context, iface: IFace, fiber: *Fiber) void {
    const running: Running = .{ .fiber = fiber, .loop_context = loop_context, .owner = iface };
    setRunning(running);
    Fiber.switchTo(loop_context, fiber);
    setRunning(null);

    const task: *PacketTask = @ptrCast(@alignCast(fiber.arg));
    if (task.done) {
        const pool = switch (iface) {
            .lan => &State.lan_fiber_pool,
            .wan => &State.wan_fiber_pool,
        };
        pool.release(fiber);
        alloc.destroy(task);
    }
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.skip();
    const iface_arg = args.next() orelse {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    };
    const iface: IFace = if (std.mem.eql(u8, iface_arg, "lan"))
        .lan
    else if (std.mem.eql(u8, iface_arg, "wan"))
        .wan
    else {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    };
    if (args.next() != null) {
        std.debug.print("Usage: router <lan|wan>\n", .{});
        return error.InvalidArguments;
    }

    State.lan_ip = .{ 192, 168, 86, 1 };
    State.lan_subnet_mask = .{ 255, 255, 255, 0 };

    State.lan_arp_table = try ArpTable.init(init.gpa, init.io, ARP_CAPACITY, ARP_TTL);
    defer State.lan_arp_table.deinit(init.gpa);

    State.wan_arp_table = try ArpTable.init(init.gpa, init.io, ARP_CAPACITY, ARP_TTL);
    defer State.wan_arp_table.deinit(init.gpa);

    State.lan_fiber_pool = try FiberPool.init(init.gpa, FIBER_STACK_SIZE, FIBER_CACHE_CAPACITY);
    defer State.lan_fiber_pool.deinit();

    State.wan_fiber_pool = try FiberPool.init(init.gpa, FIBER_STACK_SIZE, FIBER_CACHE_CAPACITY);
    defer State.wan_fiber_pool.deinit();

    State.lan_ready_queue = ReadyQueue.init(init.io);
    State.wan_ready_queue = ReadyQueue.init(init.io);

    State.arp_waiters_table = try ArpWaitersTable.init(init.gpa, init.io, ARP_WAITERS_CAPACITY, ARP_WAITERS_TIMEOUT);
    defer State.arp_waiters_table.deinit(init.gpa);

    State.dhcp_table = blk: {
        var ip_pool: DhcpTable.IpPool = .empty;
        errdefer ip_pool.deinit(init.gpa);
        for (2..255) |host| {
            try ip_pool.append(init.gpa, .{ 192, 168, 86, @intCast(host) });
        }
        break :blk try DhcpTable.init(init.gpa, init.io, ip_pool);
    };
    defer State.dhcp_table.deinit(init.gpa);

    State.nat_table = try NatTable.init(init.gpa, init.io, NAT_CAPACITY);
    defer State.nat_table.deinit(init.gpa);

    const pcap_file = ICMPv4Fixtures.message_types_pcap_file;
    var mock = try Mock.init(pcap_file, init.gpa);
    defer mock.deinit();
    const mock_nic = mock.api();

    var loop_context: std.Io.fiber.Context = undefined;
    const ready_queue = switch (iface) {
        .lan => &State.lan_ready_queue,
        .wan => &State.wan_ready_queue,
    };
    const pool = switch (iface) {
        .lan => &State.lan_fiber_pool,
        .wan => &State.wan_fiber_pool,
    };
    while (true) {
        State.arp_waiters_table.expire();
        while (ready_queue.pop()) |fiber| runFiber(init.gpa, &loop_context, iface, fiber);
        const packet = mock_nic.receive(iface) orelse break;
        const task = init.gpa.create(PacketTask) catch |err| {
            mock_nic.release(packet);
            return err;
        };
        task.* = .{ .buffer = packet, .device = mock_nic, .iface = iface, .loop_context = &loop_context };
        const fiber = pool.acquire(PacketTask.start, task) catch |err| {
            init.gpa.destroy(task);
            mock_nic.release(packet);
            return err;
        };
        runFiber(init.gpa, &loop_context, iface, fiber);
        std.debug.print("\n", .{});
    }
    State.arp_waiters_table.expireAll();
    while (ready_queue.pop()) |fiber| runFiber(init.gpa, &loop_context, iface, fiber);
}
