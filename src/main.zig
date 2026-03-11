const std = @import("std");
const private_zocail = @import("private_zocail");

pub fn main() !void {
    try private_zocail.bufferedPrint();
}
