//! Client Module

const std = @import("std");
const models = @import("models.zig");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");
const base32 = @import("base32.zig").standard;

const json = std.json;
const Allocator = std.mem.Allocator;
const HashMap = std.AutoArrayHashMap;
const ArrayList = std.ArrayList;

const clientErrors = error{
    IdNotInMap,
};

pub const Member = struct {
    username: social.Username,
    admin: bool,
};

pub const Members = struct {
    /// map from username to Member
    list: ArrayList(Member),
    signature: crypto.Ed25519.Signature,

    pub fn init(signature: crypto.Ed25519.Signature) @This() {
        return .{
            .list = ArrayList(Member){},
            .signature = signature,
        };
    }
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        self.list.deinit(allocator);
    }
};

pub const Group = struct {
    name: []const u8,
    aes_key: crypto.AesKey,
    members: Members,

    pub fn init(aes_key: [crypto.Aes128Ocb.key_length]u8, allocator: Allocator) @This() {
        return .{
            .aes_key = aes_key,
            .members = Members.init(allocator),
        };
    }
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.name);
        self.members.deinit(allocator);
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
    /// Long term Ed25519 signing keys
    lt_sign_keys: crypto.Ed25519.KeyPair,
    /// Long term X25519 key exchange keys
    lt_ke_keys: crypto.X25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, Dm),
    allocator: Allocator,
    free_token: bool,

    pub fn init(allocator: Allocator, name: []const u8, access_token: ?[]const u8) !@This() {
        const lt_sign_keys = crypto.generateSigningKeyPair();
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
            .lt_sign_keys = lt_sign_keys,
            .lt_ke_keys = try crypto.deriveX25519KeyPair(lt_sign_keys),
            .groups = HashMap(crypto.UUID, Group).init(allocator),
            .dms = HashMap(crypto.UUID, Dm).init(allocator),
            .allocator = allocator,
            .free_token = free_token,
        };
        try client.postPublicKey();

        return client;
    }
    pub fn postPublicKey(self: *@This()) !void {
        const keys = self.lt_sign_keys;
        var key_buf: [base32.Encoder.calcSize(keys.public_key.bytes.len)]u8 = undefined;
        const public_key = base32.Encoder.encode(&key_buf, &keys.public_key.toBytes());
        try social.setBio(self.allocator, self.access_token, public_key);
    }
    pub fn acceptInvites(self: *@This()) !void {
        const parsed_messages = try social.getMessages(self.allocator, self.access_token, null);
        defer parsed_messages.deinit();

        const messages = parsed_messages.value;
        for (0..messages.len) |i| {
            const encoded_message = messages[i].getContent();
            const decode_len = try base32.Decoder.calcSize(encoded_message);

            const json_buf = try self.allocator.alloc(u8, decode_len);
            defer self.allocator.free(json_buf);

            try base32.Decoder.decode(json_buf, encoded_message);

            const parsed_json = try json.parseFromSlice(models.DmInvite.Encrypted, self.allocator, json_buf, .{});
            defer parsed_json.deinit();

            const encrypted_dm_invite: models.DmInvite.Encrypted = parsed_json.value;

            var aes_key: crypto.AesKey = undefined;
            crypto.deriveAesKey(
                &aes_key,
                self.lt_ke_keys.secret_key,
                encrypted_dm_invite.ephemeral_key,
                encrypted_dm_invite.nonce,
                &encrypted_dm_invite.id.key,
            ) catch |err| {
                std.debug.print("acceptInvite: couldnt get key {}", .{err});
                break;
            };

            const secret_json_raw = try self.allocator.alloc(u8, encrypted_dm_invite.encrypted.len);
            defer self.allocator.free(secret_json_raw);

            crypto.aesDecrypt(
                secret_json_raw,
                encrypted_dm_invite.encrypted,
                encrypted_dm_invite.tag,
                encrypted_dm_invite.nonce,
                aes_key,
            ) catch |err| {
                std.debug.print("acceptInvite: couldnt decrypt {}", .{err});
                break;
            };

            const parsed_secret_json = try json.parseFromSlice(models.DmInvite.Secret, self.allocator, secret_json_raw, .{});
            defer parsed_secret_json.deinit();

            const secret_dm_invite: models.DmInvite.Secret = parsed_secret_json.value;
            std.debug.print("acceptInvite: decoded json secret: {any}\n", .{secret_dm_invite});
            if (secret_dm_invite.label != .dm_invite) {
                std.debug.print("acceptInvite: wrong label", .{});
                break;
            }

            try self.dms.put(encrypted_dm_invite.id, Dm{
                .name = try self.allocator.dupe(u8, messages[i].account.username),
                .key = aes_key,
            });
        }
    }
    pub fn dmInvite(self: *@This(), username: social.Username, id: ?crypto.UUID) !void {
        const uuid = id orelse crypto.UUID.init();

        const ephemeral_keys = crypto.getEphemeralKeyPair();
        const sender_public_key = ephemeral_keys.public_key;
        const sender_secret_key = ephemeral_keys.secret_key;

        const parsed_user = try social.getUser(self.allocator, username);
        defer parsed_user.deinit();

        var user = parsed_user.value;
        const reciever_public_ed25519_key = user.getPublicKey();
        var decoded_buf: [crypto.Ed25519.PublicKey.encoded_length]u8 = undefined;
        try base32.Decoder.decode(&decoded_buf, reciever_public_ed25519_key);
        const decoded_key = try crypto.Ed25519.PublicKey.fromBytes(decoded_buf);
        const reciever_public_key = try crypto.getRecieversPublicKeyFromEd25519(decoded_key);

        var nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);
        var aes_key: crypto.AesKey = undefined;
        try crypto.deriveAesKey(&aes_key, sender_secret_key, reciever_public_key, nonce, &uuid.key);

        try self.dms.put(uuid, Dm{
            .name = try self.allocator.dupe(u8, username),
            .key = aes_key,
        });

        const json_secret = models.DmInvite.Secret{};

        var serial_secret = std.io.Writer.Allocating.init(self.allocator);
        defer serial_secret.deinit();

        try serial_secret.writer.print("{f}", .{std.json.fmt(json_secret, .{})});
        const secret_str = serial_secret.written();

        const encrypted_secret = try self.allocator.alloc(u8, secret_str.len);
        defer self.allocator.free(encrypted_secret);
        var tag: [crypto.Aes128Ocb.tag_length]u8 = undefined;
        crypto.aesEncrypt(encrypted_secret, &tag, secret_str, &nonce, aes_key);

        const json_model = models.DmInvite.Encrypted{
            .ephemeral_key = sender_public_key,
            .nonce = nonce,
            .tag = tag,
            .id = uuid,
            .encrypted = encrypted_secret,
        };

        var serialized: std.io.Writer.Allocating = .init(self.allocator);
        defer serialized.deinit();

        try serialized.writer.print("{f}", .{std.json.fmt(json_model, .{})});
        const serialized_str = serialized.written();

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(serialized_str.len));
        defer self.allocator.free(encode_buf);
        const decoded_str = base32.Encoder.encode(encode_buf, serialized_str);

        try social.sendMessage(self.allocator, self.access_token, decoded_str, null);
    }
    pub fn getIdFromUsername(self: *@This(), username: []const u8) !crypto.UUID {
        var it = self.dms.iterator();
        while (it.next()) |dm| {
            if (std.mem.eql(u8, dm.value_ptr.*.name, username)) {
                return dm.key_ptr.*;
            }
        }
        const uuid = crypto.UUID.init();
        try self.dmInvite(username, uuid);
        return uuid;
    }
    pub fn sendMessage(self: *@This(), id: crypto.UUID, message: []const u8) !void {
        var aes_key: crypto.AesKey = undefined;
        if (self.dms.get(id)) |x| {
            aes_key = x.key;
        } else {
            return clientErrors.IdNotInMap;
        }

        var nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);

        const json_secret = models.DmMessage.Secret{ .message = message };

        var serial_secret = std.io.Writer.Allocating.init(self.allocator);
        defer serial_secret.deinit();

        try serial_secret.writer.print("{f}", .{std.json.fmt(json_secret, .{})});
        const secret_str = serial_secret.written();

        const encrypted_secret = try self.allocator.alloc(u8, secret_str.len);
        defer self.allocator.free(encrypted_secret);
        var tag: [crypto.Aes128Ocb.tag_length]u8 = undefined;
        crypto.aesEncrypt(encrypted_secret, &tag, secret_str, &nonce, aes_key);

        const json_model = models.DmMessage.Encrypted{
            .nonce = nonce,
            .tag = tag,
            .encrypted = encrypted_secret,
        };

        var serialized: std.io.Writer.Allocating = .init(self.allocator);
        defer serialized.deinit();

        try serialized.writer.print("{f}", .{std.json.fmt(json_model, .{})});
        const serialized_str = serialized.written();

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(serialized_str.len));
        defer self.allocator.free(encode_buf);
        const decoded_str = base32.Encoder.encode(encode_buf, serialized_str);

        try social.sendMessage(self.allocator, self.access_token, decoded_str, id);
    }
    pub fn saveToFile(self: *@This()) !void {
        var client_save = ClientSave{
            .name = self.name,
            .access_token = self.access_token,
            .lt_sign_keys = self.lt_sign_keys,
            .lt_ke_keys = self.lt_ke_keys,
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
            std.debug.print("file error: {}\n", .{err});
            return err;
        };
        defer file.close();

        try file.writeAll(string.written());

        std.debug.print("file written with: {s}\n", .{string.written()});
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
            .lt_sign_keys = saved_client.lt_sign_keys,
            .lt_ke_keys = saved_client.lt_ke_keys,
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
    key: Dm,
};

pub const ClientSave = struct {
    name: []const u8,
    access_token: []const u8,
    /// Long term Ed25519 signing keys
    lt_sign_keys: crypto.Ed25519.KeyPair,
    /// Long term X25519 key exchange keys
    lt_ke_keys: crypto.X25519.KeyPair,
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
        // This is definetly super broken.
        var hashmap = HashMap(crypto.UUID, Group).init(allocator);
        for (0..self.groups.len) |i| {
            try hashmap.put(self.groups[i].id, Group{
                .aes_key = self.groups[i].group.aes_key,
                .members = self.groups[i].group.members,
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
                .key = group.value_ptr.*,
            });
        }
        self.dms = array.items;
        return array;
    }
    pub fn arrayToDmMap(self: *@This(), allocator: Allocator) !HashMap(crypto.UUID, Dm) {
        var hashmap = HashMap(crypto.UUID, Dm).init(allocator);
        for (0..self.dms.len) |i| {
            try hashmap.put(self.dms[i].id, Dm{
                .name = try allocator.dupe(u8, self.dms[i].key.name),
                .key = self.dms[i].key.key,
            });
        }
        return hashmap;
    }
};
