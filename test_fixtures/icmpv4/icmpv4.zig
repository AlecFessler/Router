pub const CsvParser = @import("csv_parser.zig");

pub const csv_file = @embedFile("icmpv4_test.csv");
pub const pcap_file = @embedFile("icmpv4_test.pcap");
pub const message_types_pcap_file = @embedFile("icmpv4_message_types.pcap");
