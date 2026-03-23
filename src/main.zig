const std = @import("std");
const mastadon = @import("mastadon.zig");
const crypto = @import("crypto.zig");
const client_mod = @import("client.zig");

const Client = client_mod.Client;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }

    var client_a = try Client.fromFile(allocator, "alice");
    defer client_a.deinit();
    var client_b = try Client.fromFile(allocator, "bob");
    defer client_b.deinit();

    //try client_b.dmInvite("alice");
    //try client_a.acceptInvites();

    try client_b.saveToFile();
    try client_a.saveToFile();
}
