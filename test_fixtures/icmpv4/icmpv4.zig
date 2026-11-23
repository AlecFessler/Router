pub const CsvParser = @import("csv_parser.zig");
pub const DestinationUnreachableCsvParser = @import("destination_unreachable_csv_parser.zig");
pub const EchoCsvParser = @import("echo_csv_parser.zig");
pub const TimeExceededCsvParser = @import("time_exceeded_csv_parser.zig");

pub const csv_file = @embedFile("icmpv4_test.csv");
pub const destination_unreachable_csv_file = @embedFile("destination_unreachable_test.csv");
pub const echo_csv_file = @embedFile("echo_test.csv");
pub const pcap_file = @embedFile("icmpv4_test.pcap");
pub const message_types_pcap_file = @embedFile("icmpv4_message_types.pcap");
pub const time_exceeded_csv_file = @embedFile("time_exceeded_test.csv");
pub const time_exceeded_pcap_file = @embedFile("time_exceeded_test.pcap");
