pub const csv_parser = @import("csv_parser.zig");
pub const pcap_parser = @import("../pcap_parser.zig");

pub const csv = @embedFile("ethernet_test.csv");
pub const pcap = @embedFile("ethernet_test.pcap");
