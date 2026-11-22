// DHCP packets from the overnight WAN sample, followed by the Wi-Fi LAN sample.
// This mixed capture is for parser debugging, not interface-specific handler behavior.
pub const CsvParser = @import("csv_parser.zig");
pub const csv_file = @embedFile("dhcpv4_test.csv");
pub const pcap_file = @embedFile("dhcpv4_test.pcap");
