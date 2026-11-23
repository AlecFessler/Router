const Router = @import("router");

const ArpTable = Router.Tables.ArpTable.ArpTable;
const DhcpTable = Router.Tables.DhcpTable.DhcpTable;
const NatTable = Router.Tables.NatTable.NatTable;

pub var arp_table: ArpTable = undefined;
pub var dhcp_table: DhcpTable = undefined;
pub var nat_table: NatTable = undefined;
