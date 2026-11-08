pub const IFace = enum {
    lan,
    wan,
};

pub const Api = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        receive: *const fn (ctx: *anyopaque, iface: IFace) []u8,
        nextTxBuffer: *const fn (ctx: *anyopaque, iface: IFace) []u8,
        release: *const fn (ctx: *anyopaque, buffer: []u8) void,
        transmit: *const fn (ctx: *anyopaque, buffer: []u8) void,
    };
};
