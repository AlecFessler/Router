const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const DHCPv4Lease = Router.Protocols.DHCPv4.DHCPv4Lease;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const IPv4 = Router.Protocols.IPv4.IPv4;
const NatTable = Router.Tables.NatTable.NatTable;

pub var dhcp_table: DhcpTable = undefined;
pub var lan_arp_table: ArpTable = undefined;
pub var lan_ip: IPv4 = undefined;
pub var lan_subnet_mask: IPv4 = undefined;
pub var nat_table: NatTable = undefined;
pub var wan_arp_table: ArpTable = undefined;
pub var wan_lease: ?DHCPv4Lease = null;
