pub const CsvParser = @import("csv_parser.zig");
pub const PcapParser = @import("../pcap_parser.zig");

pub const csv_file = @embedFile("arp_test.csv");
pub const pcap_file = @embedFile("arp_test.pcap");
