//! Client Module

const std = @import("std");
const models = @import("models.zig");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");
const base32 = @import("base32.zig").standard;

const json = std.json;
const dprint = std.debug.print;
const Allocator = std.mem.Allocator;
const HashMap = std.AutoArrayHashMap;
const ArrayList = std.ArrayList;
const BaseMethods = models.BaseMethods;

pub const Group = struct {
    name: []const u8,
    key: crypto.AesKey,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.name);
    }
};

pub const Dm = struct {
    name: []const u8,
    key: crypto.AesKey,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.name);
    }
};

pub const Client = struct {
    name: []const u8,
    access_token: []const u8,
    /// Long term keys
    long_term_keys: crypto.X25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, Dm),
    allocator: Allocator,
    free_token: bool,

    pub fn init(allocator: Allocator, name: []const u8, access_token: ?[]const u8) !@This() {
        const long_term_keys = crypto.genKeyPair();
        var token: []const u8 = undefined;
        var free_token: bool = false;
        if (access_token) |t| {
            token = t;
        } else {
            token = try social.authenticateUser(allocator);
            free_token = true;
        }

        var client = Client{
            .name = name,
            .access_token = token,
            .long_term_keys = long_term_keys,
            .groups = HashMap(crypto.UUID, Group).init(allocator),
            .dms = HashMap(crypto.UUID, Dm).init(allocator),
            .allocator = allocator,
            .free_token = free_token,
        };
        try client.postPublicKey();

        return client;
    }
    pub fn postPublicKey(self: *@This()) !void {
        const keys = self.long_term_keys;
        var key_buf: [base32.Encoder.calcSize(keys.public_key.len)]u8 = undefined;
        const public_key = base32.Encoder.encode(&key_buf, &keys.public_key);
        try social.setBio(self.allocator, self.access_token, public_key);
    }
    pub fn createGroup(self: *@This(), group_name: []const u8) !crypto.UUID {
        const id = crypto.UUID.init();
        var aes_key: crypto.AesKey = undefined;
        crypto.generateRandomAesKey(&aes_key);
        try deallocPut(Group, self.allocator, &self.groups, id, Group{
            .key = aes_key,
            .name = try self.allocator.dupe(u8, group_name),
        });
        return id;
    }
    pub fn acceptGroupInvites(self: *@This()) !void {
        var dm_it = self.dms.iterator();
        while (dm_it.next()) |item| {
            const id = item.key_ptr.*;
            const dm = item.value_ptr;
            const parsed_messages = try social.getMessages(self.allocator, self.access_token, id);
            defer parsed_messages.deinit();

            const messages = parsed_messages.value;
            for (0..messages.len) |i| {
                const encoded_message = messages[i].getContent();

                var group_invite = try BaseMethods(models.GroupInvite).fromBase32(self.allocator, encoded_message);
                defer group_invite.base.deinit(self.allocator);

                const aes_key = dm.*.key;

                group_invite.base.decrypt(self.allocator, aes_key) catch {
                    dprint("acceptGroupInvites: couldnt decrypt message\n", .{});
                    break;
                };

                const sec: *models.GroupInvite.Secret = &group_invite.base.secret.?;

                if (sec.label == .group_invite) {
                    dprint("acceptGroupInvite: group invite taken\n", .{});

                    try deallocPut(Group, self.allocator, &self.groups, sec.id, Group{
                        .key = sec.key,
                        .name = try self.allocator.dupe(u8, sec.name),
                    });
                    break;
                }
            }
        }
    }
    pub fn groupInvite(self: *@This(), user_id: crypto.UUID, group_id: crypto.UUID) !void {
        const group: Group = self.groups.get(group_id).?;
        var user_key: crypto.AesKey = undefined;
        if (self.dms.get(user_id)) |dm| {
            user_key = dm.key;
        } else {
            return error.UserIdNotFound;
        }
        var group_invite: models.GroupInvite = try BaseMethods(models.GroupInvite).fromEncryptedAndSecret(
            self.allocator,
            models.GroupInvite.Encrypted{},
            models.GroupInvite.Secret{
                .key = group.key,
                .id = group_id,
                .name = group.name,
            },
        );
        defer group_invite.base.deinit(self.allocator);

        try group_invite.base.encrypt(self.allocator, user_key);

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(group_invite.base.json_encrypted.?.written().len));
        defer self.allocator.free(encode_buf);

        const encoded_str = try group_invite.base.toBase32(encode_buf);

        try social.sendMessage(self.allocator, self.access_token, encoded_str, user_id);
    }
    pub fn acceptDmInvites(self: *@This()) !void {
        const parsed_messages = try social.getMessages(self.allocator, self.access_token, null);
        defer parsed_messages.deinit();

        const messages = parsed_messages.value;
        for (0..messages.len) |i| {
            const encoded_message = messages[i].getContent();

            var dm_invite = try BaseMethods(models.DmInvite).fromBase32(self.allocator, encoded_message);
            defer dm_invite.base.deinit(self.allocator);

            const enc: *models.DmInvite.Encrypted = &dm_invite.base.encrypted.?;

            var aes_key: crypto.AesKey = undefined;

            crypto.deriveAesKey(
                &aes_key,
                self.long_term_keys.secret_key,
                enc.ephemeral_key,
                enc.nonce,
                &enc.id.key,
            ) catch |err| {
                dprint("acceptDmInvite: couldnt get key {}\n", .{err});
                break;
            };

            dm_invite.base.decrypt(self.allocator, aes_key) catch {
                dprint("acceptDmInvite: couldnt decrypt message\n", .{});
                break;
            };

            if (dm_invite.base.secret.?.label != .dm_invite) {
                dprint("acceptDmInvite: wrong label\n", .{});
                break;
            }

            try deallocPut(Dm, self.allocator, &self.dms, enc.id, Dm{
                .name = try self.allocator.dupe(u8, messages[i].account.username),
                .key = aes_key,
            });
        }
    }
    pub fn dmInvite(self: *@This(), username: social.Username) !crypto.UUID {
        const id = crypto.UUID.init();

        const ephemeral_keys = crypto.genKeyPair();

        const parsed_user = try social.getUser(self.allocator, username);
        defer parsed_user.deinit();

        var user = parsed_user.value;
        var decoded_key: [crypto.X25519.public_length]u8 = undefined;
        try user.getPublicKey(&decoded_key);

        var dm_invite: models.DmInvite = try BaseMethods(models.DmInvite).fromEncryptedAndSecret(
            self.allocator,
            models.DmInvite.Encrypted{
                .ephemeral_key = ephemeral_keys.public_key,
                .id = id,
            },
            models.DmInvite.Secret{},
        );
        defer dm_invite.base.deinit(self.allocator);

        var aes_key: crypto.AesKey = undefined;
        try crypto.deriveAesKey(&aes_key, ephemeral_keys.secret_key, decoded_key, dm_invite.base.encrypted.?.nonce, &id.key);

        try deallocPut(Dm, self.allocator, &self.dms, id, Dm{
            .name = try self.allocator.dupe(u8, username),
            .key = aes_key,
        });

        try dm_invite.base.encrypt(self.allocator, aes_key);

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(dm_invite.base.json_encrypted.?.written().len));
        defer self.allocator.free(encode_buf);

        const encoded_str = try dm_invite.base.toBase32(encode_buf);

        try social.sendMessage(self.allocator, self.access_token, encoded_str, null);
        return id;
    }
    pub fn getUserIdFromName(self: *@This(), name: []const u8) !crypto.UUID {
        var it = self.dms.iterator();
        while (it.next()) |dm| {
            if (std.mem.eql(u8, dm.value_ptr.*.name, name)) {
                return dm.key_ptr.*;
            }
        }
        return self.dmInvite(name);
    }
    pub fn getGroupIdFromName(self: *@This(), name: []const u8) !crypto.UUID {
        var it = self.groups.iterator();
        while (it.next()) |group| {
            if (std.mem.eql(u8, group.value_ptr.*.name, name)) {
                return group.key_ptr.*;
            }
        }
        return error.GroupNotFound;
    }
    pub fn sendMessage(self: *@This(), id: crypto.UUID, message: []const u8) !void {
        var aes_key: crypto.AesKey = undefined;
        if (self.dms.get(id)) |x| {
            aes_key = x.key;
        } else {
            return error.IdNotFound;
        }

        var dm_message: models.DmMessage = try BaseMethods(models.DmMessage).fromEncryptedAndSecret(
            self.allocator,
            models.DmMessage.Encrypted{},
            models.DmMessage.Secret{
                .message = message,
            },
        );
        defer dm_message.base.deinit(self.allocator);

        try dm_message.base.encrypt(self.allocator, aes_key);

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(dm_message.base.json_encrypted.?.written().len));
        defer self.allocator.free(encode_buf);

        const encoded_str = try dm_message.base.toBase32(encode_buf);

        try social.sendMessage(self.allocator, self.access_token, encoded_str, id);
    }
    pub fn recieveMessage(self: *@This(), id: crypto.UUID) !void {
        var aes_key: crypto.AesKey = undefined;
        if (self.dms.get(id)) |x| {
            aes_key = x.key;
        } else {
            return error.IdNotInMap;
        }

        const parsed_messages = try social.getMessages(self.allocator, self.access_token, id);
        defer parsed_messages.deinit();
        const messages: []models.Message = parsed_messages.value;

        dprint("ID: {s}\n", .{id.str});
        for (0..messages.len) |i| {
            const encoded_message = messages[i].getContent();

            var dm_message = try BaseMethods(models.DmMessage).fromBase32(self.allocator, encoded_message);
            defer dm_message.base.deinit(self.allocator);

            dm_message.base.decrypt(self.allocator, aes_key) catch {
                dprint("recieveMessage: couldnt decrypt message\n", .{});
                break;
            };

            if (dm_message.base.secret.?.label != .dm_message) {
                dprint("recieveMessage: wrong label\n", .{});
                break;
            }

            dprint("recieveMessage: Message {} from {s}:\n\t{s}\n", .{
                i,
                messages[i].account.username,
                dm_message.base.secret.?.message,
            });
        }
    }
    pub fn saveToFile(self: *@This()) !void {
        var client_save = ClientSave{
            .name = self.name,
            .access_token = self.access_token,
            .long_term_keys = self.long_term_keys,
        };
        var group_array = try client_save.groupMapToArray(self.allocator, self.groups);
        defer group_array.deinit(self.allocator);

        var dm_array = try client_save.dmMapToArray(self.allocator, self.dms);
        defer dm_array.deinit(self.allocator);

        var string: std.io.Writer.Allocating = .init(self.allocator);
        defer string.deinit();

        try string.writer.print("{f}", .{std.json.fmt(client_save, .{})});

        const path = try std.fmt.allocPrint(self.allocator, "data/{s}.json", .{self.name});
        defer self.allocator.free(path);

        const file = std.fs.cwd().createFile(path, .{}) catch |err| {
            dprint("saveToFile: file error: {}\n", .{err});
            return err;
        };
        defer file.close();

        try file.writeAll(string.written());

        dprint("saveToFile: file written with: {s}\n", .{string.written()});
    }
    pub fn fromFile(allocator: Allocator, name: []const u8) !@This() {
        const path = try std.fmt.allocPrint(allocator, "data/{s}.json", .{name});
        defer allocator.free(path);

        const file = try std.fs.cwd().openFile(path, .{});

        try file.seekTo(0);
        const raw = try file.readToEndAlloc(allocator, 4096 * 8);
        defer allocator.free(raw);

        const parsed = try std.json.parseFromSlice(
            ClientSave,
            allocator,
            raw,
            .{},
        );
        defer parsed.deinit();

        var saved_client: ClientSave = parsed.value;
        const client = Client{
            .name = name,
            .access_token = try allocator.dupe(u8, saved_client.access_token),
            .long_term_keys = saved_client.long_term_keys,
            .groups = try saved_client.arrayToGroupMap(allocator),
            .dms = try saved_client.arrayToDmMap(allocator),
            .allocator = allocator,
            .free_token = true,
        };
        return client;
    }
    pub fn deinit(self: *@This()) void {
        var group_it = self.groups.iterator();
        while (group_it.next()) |group| {
            group.value_ptr.*.deinit(self.allocator);
        }
        var dm_it = self.dms.iterator();
        while (dm_it.next()) |dm| {
            dm.value_ptr.*.deinit(self.allocator);
        }
        if (self.free_token) self.allocator.free(self.access_token);
        self.groups.deinit();
        self.dms.deinit();
    }
};

pub const GroupPair = struct {
    id: crypto.UUID,
    group: Group,
};

pub const DmPair = struct {
    id: crypto.UUID,
    dm: Dm,
};

pub const ClientSave = struct {
    name: []const u8,
    access_token: []const u8,
    /// Long term keys
    long_term_keys: crypto.X25519.KeyPair,
    groups: []const GroupPair = undefined,
    dms: []const DmPair = undefined,

    pub fn groupMapToArray(self: *@This(), allocator: Allocator, group_map: HashMap(crypto.UUID, Group)) !ArrayList(GroupPair) {
        var array = ArrayList(GroupPair){};
        var it = group_map.iterator();
        while (it.next()) |group| {
            try array.append(allocator, .{
                .id = group.key_ptr.*,
                .group = group.value_ptr.*,
            });
        }
        self.groups = array.items;
        return array;
    }
    pub fn arrayToGroupMap(self: *@This(), allocator: Allocator) !HashMap(crypto.UUID, Group) {
        var hashmap = HashMap(crypto.UUID, Group).init(allocator);
        for (0..self.groups.len) |i| {
            try deallocPut(Group, allocator, &hashmap, self.groups[i].id, Group{
                .key = self.groups[i].group.key,
                .name = try allocator.dupe(u8, self.groups[i].group.name),
            });
        }
        return hashmap;
    }
    pub fn dmMapToArray(self: *@This(), allocator: Allocator, group_map: HashMap(crypto.UUID, Dm)) !ArrayList(DmPair) {
        var array = ArrayList(DmPair){};
        var it = group_map.iterator();
        while (it.next()) |group| {
            try array.append(allocator, .{
                .id = group.key_ptr.*,
                .dm = group.value_ptr.*,
            });
        }
        self.dms = array.items;
        return array;
    }
    pub fn arrayToDmMap(self: *@This(), allocator: Allocator) !HashMap(crypto.UUID, Dm) {
        var hashmap = HashMap(crypto.UUID, Dm).init(allocator);
        for (0..self.dms.len) |i| {
            try deallocPut(Dm, allocator, &hashmap, self.dms[i].id, Dm{
                .name = try allocator.dupe(u8, self.dms[i].dm.name),
                .key = self.dms[i].dm.key,
            });
        }
        return hashmap;
    }
};

fn deallocPut(comptime T: type, allocator: Allocator, map: *HashMap(crypto.UUID, T), key: crypto.UUID, val: T) !void {
    if (try map.fetchPut(key, val)) |old| {
        var old_val = old.value;
        old_val.deinit(allocator);
    }
}
