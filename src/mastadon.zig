const std = @import("std");
const config = @import("config.zig");
const models = @import("models.zig");
const crypto = @import("crypto.zig");
const parseFromSlice = std.json.parseFromSlice;
const Parsed = std.json.Parsed;
const Client = std.http.Client;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const Username = []const u8;

pub fn authenticateUser(allocator: Allocator) ![]const u8 {
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const stdin: *std.io.Reader = &stdin_reader.interface;

    const auth_url: []const u8 =
        "\thttps://social.thomascreagh.com/oauth/authorize" ++
        "?client_id={s}" ++
        "&scope=read+write+push" ++
        "&redirect_uri=urn:ietf:wg:oauth:2.0:oob" ++
        "&response_type=code";

    try stdout.writeAll("Please authenticate with this url:\n\n");
    try stdout.print(auth_url, .{config.CLIENT_ID});
    try stdout.writeAll("\n\nAnd enter the auth code below: ");

    try stdout.flush();
    const raw_line = try stdin.takeDelimiter('\n') orelse unreachable;
    const auth_code = std.mem.trim(u8, raw_line, "\r");

    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse("https://social.thomascreagh.com/oauth/token");

    var request = try client.request(.POST, uri, .{
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
    });
    defer request.deinit();

    const redirect_uri = "urn:ietf:wg:oauth:2.0:oob";
    const body_options = "grant_type=authorization_code&client_id={s}&client_secret={s}&redirect_uri={s}&code={s}";

    const body = try std.fmt.allocPrint(
        allocator,
        body_options,
        .{ config.CLIENT_ID, config.CLIENT_SECRET, redirect_uri, auth_code },
    );
    defer allocator.free(body);

    try request.sendBodyComplete(body);

    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);

    var transfer_buf: [4096]u8 = undefined;
    const response_reader = response.reader(&transfer_buf);

    std.debug.print("AuthenticateUser Status: {}\n", .{response.head.status});

    const raw_body = try response_reader.allocRemaining(allocator, .limited(4096));
    defer allocator.free(raw_body);

    const parsed = try std.json.parseFromSlice(models.UserToken, allocator, raw_body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const access_token = allocator.dupe(u8, parsed.value.access_token);
    return access_token;
}

pub fn getUser(
    allocator: Allocator,
    username: Username,
) !Parsed(models.User) {
    const url_format = try std.fmt.allocPrint(
        allocator,
        "https://social.thomascreagh.com/api/v1/accounts/lookup?acct={s}",
        .{username},
    );
    defer allocator.free(url_format);

    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url_format);

    var request = try client.request(.GET, uri, .{
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer request.deinit();

    try request.sendBodiless();

    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);

    std.debug.print("getUser Status: {}\n", .{response.head.status});

    var transfer_buf: [4096]u8 = undefined;
    const response_reader = response.reader(&transfer_buf);

    const raw_body = try response_reader.allocRemaining(allocator, .limited(4096));
    defer allocator.free(raw_body);

    return try std.json.parseFromSlice(
        models.User,
        allocator,
        raw_body,
        .{ .ignore_unknown_fields = true },
    );
}

/// Get messages by the id. If id not given then all broadcast messages are given
pub fn getMessages(
    allocator: Allocator,
    access_token: []const u8,
    id: ?crypto.UUID,
) !Parsed([]models.Message) {
    var auth_url: []u8 = undefined;
    if (id) |uuid| {
        auth_url = try std.fmt.allocPrint(
            allocator,
            "https://social.thomascreagh.com/api/v1/timelines/tag/private_zocial_{s}",
            .{uuid.str},
        );
    } else {
        auth_url = try allocator.dupe(u8, "https://social.thomascreagh.com/api/v1/timelines/tag/private_zocial_0");
    }
    defer allocator.free(auth_url);

    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(auth_url);

    const auth_format = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token});
    defer allocator.free(auth_format);

    var request = try client.request(.GET, uri, .{
        .headers = .{
            .authorization = .{ .override = auth_format },
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer request.deinit();

    try request.sendBodiless();

    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);

    std.debug.print("getMessages Status: {}\n", .{response.head.status});

    var transfer_buf: [4096]u8 = undefined;
    const response_reader = response.reader(&transfer_buf);

    const raw_body = try response_reader.allocRemaining(allocator, .limited(4096 * 16));
    defer allocator.free(raw_body);

    return try std.json.parseFromSlice(
        []models.Message,
        allocator,
        raw_body,
        .{ .ignore_unknown_fields = true },
    );
}

pub fn sendMessage(
    allocator: Allocator,
    access_token: []const u8,
    message: []const u8,
    id: ?crypto.UUID,
) !void {
    std.debug.print("MESSAGE: {s}\n", .{message});
    var tag: []u8 = undefined;
    if (id) |uuid| {
        tag = try std.fmt.allocPrint(allocator, "#private_zocial_{s}", .{uuid.str});
    } else {
        tag = try allocator.dupe(u8, "#private_zocial_0");
    }
    defer allocator.free(tag);

    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse("https://social.thomascreagh.com/api/v1/statuses");

    const auth_format = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token});
    defer allocator.free(auth_format);

    var request = try client.request(.POST, uri, .{
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
            .authorization = .{ .override = auth_format },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
    });
    defer request.deinit();

    const body = try std.fmt.allocPrint(allocator, "status={s}\n\n{s}", .{ message, tag });
    defer allocator.free(body);

    try request.sendBodyComplete(body);

    var redirect_buf: [1024]u8 = undefined;
    const response = try request.receiveHead(&redirect_buf);

    std.debug.print("sendMessage Status: {}\n", .{response.head.status});
}

pub fn setBio(
    allocator: Allocator,
    access_token: []const u8,
    message: []const u8,
) !void {
    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse("https://social.thomascreagh.com/api/v1/accounts/update_credentials");

    const auth_format = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token});
    defer allocator.free(auth_format);

    var request = try client.request(.PATCH, uri, .{
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
            .authorization = .{ .override = auth_format },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
    });
    defer request.deinit();

    const body = try std.fmt.allocPrint(allocator, "note={s}", .{message});
    defer allocator.free(body);

    try request.sendBodyComplete(body);

    var redirect_buf: [1024]u8 = undefined;
    const response = try request.receiveHead(&redirect_buf);

    std.debug.print("setBio Status: {}\n", .{response.head.status});
}
