const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const default_alphabet_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".*;
pub const default_pad_char = '_';

pub const Codecs = struct {
    alphabet_chars: [32]u8,
    pad_char: u8,
    Encoder: Base32Encoder,
    Decoder: Base32Decoder,
};

pub const standard = Codecs{
    .alphabet_chars = default_alphabet_chars,
    .pad_char = default_pad_char,
    .Encoder = Base32Encoder.init(default_alphabet_chars, default_pad_char),
    .Decoder = Base32Decoder.init(default_alphabet_chars, default_pad_char),
};

pub const Base32Encoder = struct {
    alphabet_chars: [32]u8 = default_alphabet_chars,
    pad_char: u8 = default_pad_char,

    pub fn init(alphabet_chars: [32]u8, pad_char: u8) Base32Encoder {
        assert(alphabet_chars.len == 32);
        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars) |c| {
            assert(!char_in_alphabet[c]);
            char_in_alphabet[c] = true;
        }
        return Base32Encoder{
            .alphabet_chars = alphabet_chars,
            .pad_char = pad_char,
        };
    }
    pub fn calcSize(encoder: *const Base32Encoder, source_len: usize) usize {
        _ = encoder;
        return @divTrunc(source_len + 4, 5) * 8;
    }
    pub fn encode(encoder: *const Base32Encoder, dest: []u8, source: []const u8) []const u8 {
        const out_len = encoder.calcSize(source.len);
        assert(dest.len >= out_len);

        var idx: usize = 0;
        var out_idx: usize = 0;
        while (idx + 4 < source.len) : (idx += 5) {
            const bits: u64 = @as(u64, source[idx]) << 32 |
                @as(u64, source[idx + 1]) << 24 |
                @as(u64, source[idx + 2]) << 16 |
                @as(u64, source[idx + 3]) << 8 |
                @as(u64, source[idx + 4]);
            dest[out_idx] = encoder.alphabet_chars[(bits >> 35) & 0x1f];
            dest[out_idx + 1] = encoder.alphabet_chars[(bits >> 30) & 0x1f];
            dest[out_idx + 2] = encoder.alphabet_chars[(bits >> 25) & 0x1f];
            dest[out_idx + 3] = encoder.alphabet_chars[(bits >> 20) & 0x1f];
            dest[out_idx + 4] = encoder.alphabet_chars[(bits >> 15) & 0x1f];
            dest[out_idx + 5] = encoder.alphabet_chars[(bits >> 10) & 0x1f];
            dest[out_idx + 6] = encoder.alphabet_chars[(bits >> 5) & 0x1f];
            dest[out_idx + 7] = encoder.alphabet_chars[(bits) & 0x1f];
            out_idx += 8;
        }
        if (idx + 3 < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 3];
            dest[out_idx + 1] = encoder.alphabet_chars[((source[idx] & 0b111) << 2) | (source[idx + 1] >> 6)];
            dest[out_idx + 2] = encoder.alphabet_chars[(source[idx + 1] & 0b111110) >> 1];
            dest[out_idx + 3] = encoder.alphabet_chars[((source[idx + 1] & 0b1) << 4) | ((source[idx + 2] & 0b11110000) >> 4)];
            dest[out_idx + 4] = encoder.alphabet_chars[((source[idx + 2] & 0b1111) << 1) | ((source[idx + 3] & 0b10000000) >> 7)];
            dest[out_idx + 5] = encoder.alphabet_chars[(source[idx + 3] & 0b01111100) >> 2];
            dest[out_idx + 6] = encoder.alphabet_chars[(source[idx + 3] & 0b11) << 3];
            out_idx += 7;
        } else if (idx + 2 < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 3];
            dest[out_idx + 1] = encoder.alphabet_chars[((source[idx] & 0b111) << 2) | (source[idx + 1] >> 6)];
            dest[out_idx + 2] = encoder.alphabet_chars[(source[idx + 1] & 0b111110) >> 1];
            dest[out_idx + 3] = encoder.alphabet_chars[((source[idx + 1] & 0b1) << 4) | ((source[idx + 2] & 0b11110000) >> 4)];
            dest[out_idx + 4] = encoder.alphabet_chars[(source[idx + 2] & 0b1111) << 1];
            out_idx += 5;
        } else if (idx + 1 < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 3];
            dest[out_idx + 1] = encoder.alphabet_chars[((source[idx] & 0b111) << 2) | (source[idx + 1] >> 6)];
            dest[out_idx + 2] = encoder.alphabet_chars[(source[idx + 1] & 0b111110) >> 1];
            dest[out_idx + 3] = encoder.alphabet_chars[(source[idx + 1] & 0b1) << 4];
            out_idx += 4;
        } else if (idx < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 3];
            dest[out_idx + 1] = encoder.alphabet_chars[(source[idx] & 0b111) << 2];
            out_idx += 2;
        }
        for (dest[out_idx..out_len]) |*pad| {
            pad.* = encoder.pad_char;
        }
        return dest[0..out_len];
    }
};

pub const Base32Decoder = struct {
    char_to_index: [256]u8,
    pad_char: u8,

    pub fn init(alphabet_chars: [32]u8, pad_char: u8) Base32Decoder {
        var result = Base32Decoder{
            .char_to_index = [_]u8{0xff} ** 256,
            .pad_char = pad_char,
        };
        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars, 0..) |c, i| {
            assert(!char_in_alphabet[c]);
            assert(c != pad_char);

            result.char_to_index[c] = @as(u8, @intCast(i));
            char_in_alphabet[c] = true;
        }
        return result;
    }
    pub fn calcSize(decoder: *const Base32Decoder, source: []const u8) !usize {
        const source_len = source.len;
        var result = source_len / 8 * 5;
        const leftover = source_len % 8;

        if (leftover != 0) return error.InvalidPadding;
        var pad_chars: usize = 0;
        for (0..6) |i| {
            if (source_len > i and source[source_len - 1 - i] == decoder.pad_char) {
                pad_chars += 1;
            } else break;
        }
        switch (pad_chars) {
            6 => result -= 4,
            4 => result -= 3,
            3 => result -= 2,
            1 => result -= 1,
            0 => {},
            else => return error.InvalidPadding,
        }

        return result;
    }
    pub fn decode(decoder: *const Base32Decoder, dest: []u8, source: []const u8) !void {
        if (source.len % 8 != 0) return error.InvalidPadding;
        var dest_idx: usize = 0;
        var acc: u12 = 0;
        var acc_len: u4 = 0;
        var leftover_idx: ?usize = null;
        for (source, 0..) |c, src_idx| {
            const d = decoder.char_to_index[c];
            if (d == 0xff) {
                if (c != decoder.pad_char) return error.InvalidCharacter;
                leftover_idx = src_idx;
                break;
            }
            acc = (acc << 5) + d;
            acc_len += 5;
            if (acc_len >= 8) {
                acc_len -= 8;
                dest[dest_idx] = @as(u8, @truncate(acc >> acc_len));
                dest_idx += 1;
            }
        }
        if (acc_len > 4 or (acc & (@as(u12, 1) << acc_len) - 1) != 0) {
            return error.InvalidPadding;
        }
        if (leftover_idx == null) return;
        const leftover = source[leftover_idx.?..];
        const padding_len: usize = switch (acc_len) {
            2 => 6,
            4 => 4,
            1 => 3,
            3 => 1,
            0 => 0,
            else => return error.InvalidPadding,
        };
        var padding_chars: usize = 0;
        for (leftover) |c| {
            if (c != decoder.pad_char) {
                return if (c == 0xff) error.InvalidCharacter else error.InvalidPadding;
            }
            padding_chars += 1;
        }
        if (padding_chars != padding_len) return error.InvalidPadding;
    }
};

// Tests from https://github.com/gernest/base32/blob/master/src/base32.zig
const TestPair = struct {
    decoded: []const u8,
    encoded: []const u8,
};
const pairs = [_]TestPair{
    TestPair{ .decoded = "", .encoded = "" },
    TestPair{ .decoded = "f", .encoded = "MY______" },
    TestPair{ .decoded = "fo", .encoded = "MZXQ____" },
    TestPair{ .decoded = "foo", .encoded = "MZXW6___" },
    TestPair{ .decoded = "foob", .encoded = "MZXW6YQ_" },
    TestPair{ .decoded = "fooba", .encoded = "MZXW6YTB" },
    // Wikipedia examples, converted to base32
    TestPair{ .decoded = "sure.", .encoded = "ON2XEZJO" },
    TestPair{ .decoded = "sure", .encoded = "ON2XEZI_" },
    TestPair{ .decoded = "sur", .encoded = "ON2XE___" },
    TestPair{ .decoded = "su", .encoded = "ON2Q____" },
    TestPair{ .decoded = "leasure.", .encoded = "NRSWC43VOJSS4___" },
    TestPair{ .decoded = "easure.", .encoded = "MVQXG5LSMUXA____" },
    TestPair{ .decoded = "easure.", .encoded = "MVQXG5LSMUXA____" },
    TestPair{ .decoded = "asure.", .encoded = "MFZXK4TFFY______" },
    TestPair{ .decoded = "sure.", .encoded = "ON2XEZJO" },
};

test "Encoding" {
    const codecs = Codecs{
        .alphabet_chars = default_alphabet_chars,
        .pad_char = default_pad_char,
        .Encoder = Base32Encoder.init(default_alphabet_chars, default_pad_char),
        .Decoder = Base32Decoder.init(default_alphabet_chars, default_pad_char),
    };
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = codecs.Encoder.calcSize(ts.decoded.len);
        const result = codecs.Encoder.encode(buf[0..(size)], ts.decoded);
        try testing.expectEqualSlices(u8, ts.encoded, result);
    }
}

test "Decoding" {
    const codecs = Codecs{
        .alphabet_chars = default_alphabet_chars,
        .pad_char = default_pad_char,
        .Encoder = Base32Encoder.init(default_alphabet_chars, default_pad_char),
        .Decoder = Base32Decoder.init(default_alphabet_chars, default_pad_char),
    };
    var buf: [1024]u8 = undefined;
    for (pairs) |ts| {
        const size = try codecs.Decoder.calcSize(ts.encoded);
        try codecs.Decoder.decode(buf[0..size], ts.encoded);
        try testing.expectEqualSlices(u8, ts.decoded, buf[0..size]);
    }
}
