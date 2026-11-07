pub const csv_parser = @import("csv_parser.zig");
pub const pcap_parser = @import("../pcap_parser.zig");

pub const csv = @embedFile("arp_test.csv");
pub const pcap = @embedFile("arp_test.pcap");
