const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const ArpWaitersTable = Router.Tables.ArpWaitersTable.ArpWaitersTable;
const DHCPv4Lease = Router.Protocols.DHCPv4.DHCPv4Lease;
const WanTransaction = Router.Protocols.DHCPv4.WanTransaction;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const IPv4 = Router.Protocols.IPv4.IPv4;
const IPv4FragmentTable = Router.Tables.IPv4FragmentTable.IPv4FragmentTable;
const NatFilteringMode = Router.Tables.NatTable.NatTable.FilteringMode;
const NatTable = Router.Tables.NatTable.NatTable;

pub var lan_arp_table: ArpTable = undefined;
pub var wan_arp_table: ArpTable = undefined;
pub var dhcp_table: DhcpTable = undefined;
pub var nat_table: NatTable = undefined;

pub var nat_filtering_mode: NatFilteringMode = .address_restricted;
pub var arp_waiters_table: ArpWaitersTable = undefined;

pub var lan_fragment_table: IPv4FragmentTable = undefined;
pub var wan_fragment_table: IPv4FragmentTable = undefined;
pub var reassembly_tables: [2]Router.Tables.ReassemblyTable.ReassemblyTable = undefined;

pub var wan_lease: ?DHCPv4Lease = null;
pub var wan_transaction: ?WanTransaction = null;

pub var lan_ip: IPv4 = undefined;
pub var lan_subnet_mask: IPv4 = undefined;
