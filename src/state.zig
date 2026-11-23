const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const DHCPv4Lease = Router.Protocols.DHCPv4.DHCPv4Lease;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const NatTable = Router.Tables.NatTable.NatTable;

pub var arp_table: ArpTable = undefined;
pub var dhcp_table: DhcpTable = undefined;
pub var nat_table: NatTable = undefined;
pub var wan_lease: ?DHCPv4Lease = null;
