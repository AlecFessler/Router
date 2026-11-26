const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DHCPv4Lease = Router.Protocols.DHCPv4.DHCPv4Lease;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const FiberPool = Router.Async.FiberPool.FiberPool;
const IPv4 = Router.Protocols.IPv4.IPv4;
const NatTable = Router.Tables.NatTable.NatTable;
const ReadyQueue = Router.Async.ReadyQueue.ReadyQueue;

pub var lan_arp_table: ArpTable = undefined;
pub var wan_arp_table: ArpTable = undefined;
pub var dhcp_table: DhcpTable = undefined;
pub var nat_table: NatTable = undefined;
pub var arp_waiters_table: ArpWaitersTable = undefined;

pub var wan_lease: ?DHCPv4Lease = null;

pub var lan_ip: IPv4 = undefined;
pub var lan_subnet_mask: IPv4 = undefined;

pub var lan_fiber_pool: FiberPool = undefined;
pub var wan_fiber_pool: FiberPool = undefined;
pub var lan_ready_queue: ReadyQueue = undefined;
pub var wan_ready_queue: ReadyQueue = undefined;
