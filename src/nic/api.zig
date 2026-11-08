pub const IFace = enum {
    lan,
    wan,
};

pub const Api = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        receive: *const fn (ctx: *anyopaque, iface: IFace) ?[]u8,
        nextTxBuffer: *const fn (ctx: *anyopaque, iface: IFace) []u8,
        release: *const fn (ctx: *anyopaque, buffer: []u8) void,
        transmit: *const fn (ctx: *anyopaque, buffer: []u8) void,
    };

    pub fn receive(self: Api, iface: IFace) ?[]u8 {
        return self.vtable.receive(self.ptr, iface);
    }

    pub fn nextTxBuffer(self: Api, iface: IFace) []u8 {
        return self.vtable.nextTxBuffer(self.ptr, iface);
    }

    pub fn release(self: Api, buffer: []u8) void {
        self.vtable.release(self.ptr, buffer);
    }

    pub fn transmit(self: Api, buffer: []u8) void {
        self.vtable.transmit(self.ptr, buffer);
    }
};
