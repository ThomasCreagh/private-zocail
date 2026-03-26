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

    var client_a = try Client.init(allocator, "alice", "y5Rql1ZvWYfqEwdPxout4pz1IUD1JamIaAiS4yTzZTg");
    defer client_a.deinit();
    var client_b = try Client.init(allocator, "bob", "r4wsr-ygHOtFztmpBpnrbkGX5a1YmnMOK4ggrGI3exQ");
    defer client_b.deinit();

    //var client_a = try Client.fromFile(allocator, "alice");
    //defer client_a.deinit();
    //var client_b = try Client.fromFile(allocator, "bob");
    //defer client_b.deinit();

    _ = try client_b.createGroup("bob_alice");
    try client_b.groupInvite(try client_b.getUserIdFromName("alice"), try client_b.getGroupIdFromName("bob_alice"));
    //try client_b.sendMessage(try client_b.getUserIdFromName("alice"), "Hey alice! I invited you to a new group.");
    try client_a.acceptDmInvites();
    try client_a.acceptGroupInvites();

    //try client_b.sendMessage(try client_b.getUserIdFromName("alice"), "Hey alice!");
    //try client_a.recieveMessage(try client_a.getUserIdFromName("bob"));

    try client_b.saveToFile();
    try client_a.saveToFile();
}
