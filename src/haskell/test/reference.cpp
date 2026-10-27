// Frozen pre-migration C++ rules: test oracle only, never linked into the node.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>
#include <algorithm>
#include <cstdlib>
#include <string>

extern "C" int32_t reference_parent_message(uint32_t size, const uint8_t* bytes,
    uint32_t* fields, uint16_t* votes)
{
    fields[0] = fields[1] = 0;
    if (size < 5) return 0;
    if (std::memcmp(bytes, "\xd5\xe0\xc4\xaf", 4) == 0) fields[0] = 1;
    else if (size == 37 && std::memcmp(bytes, "\xd6\xe1\xc5\xdf", 4) == 0) fields[0] = 2;
    else if (size == 37 && std::memcmp(bytes, "\xd4\x5a\xa9\x43", 4) == 0) fields[0] = 3;
    else if (std::memcmp(bytes, "\xd7\x7d\x17\x76", 4) == 0) {
        uint32_t count{0};
        switch (bytes[4]) {
        case 0: case 3:
            if (size != 5) return 0;
            fields[1] = bytes[4] == 0 ? 1 : 3;
            break;
        case 1:
            fields[1] = 2;
            for (uint32_t i = 5; i < size; ++i)
                votes[count++] = bytes[i] == 255 ? 65535 : bytes[i] == 254 ? 65534 : bytes[i];
            break;
        case 2:
            if ((size - 5) & 1) return 0;
            for (uint32_t i = 5; i < size; i += 2)
                votes[count++] = uint16_t(bytes[i]) | (uint16_t(bytes[i + 1]) << 8);
            fields[1] = std::all_of(votes, votes + count, [](uint16_t n) { return n <= 253; }) ? 0 : 2;
            break;
        default: return 0;
        }
        fields[0] = 4;
        return count;
    } else if (size == 37 && std::memcmp(bytes, "\xd1\x61\x73\x68", 4) == 0) fields[0] = 5;
    return 0;
}

extern "C" int32_t reference_parent_replay_record(uint32_t kind, uint32_t facts, int64_t value,
    uint64_t first, uint64_t second)
{
    switch (kind) {
    case 0:
        if (facts > 1) return -1;
        return (facts ? second : first) > INT32_MAX ? -1 : static_cast<int32_t>(facts ? second : first);
    case 1:
        if (facts > 7) return -1;
        return (facts & 1) && (facts & 2) && (facts & 4) && value > 0 &&
            static_cast<uint64_t>(value) <= second && first != 0 && first <= 128;
    case 2:
        if (facts > 15) return -1;
        return (facts & 1) && (facts & 2) && first < UINT32_MAX && second == first + 1 &&
            (!(facts & 4) || (facts & 8));
    case 3: return facts > 1 ? -1 : facts != 0;
    case 4: return first <= UINT32_MAX && second <= UINT32_MAX && first <= second;
    case 5: case 6: return first <= UINT32_MAX && second <= first && value >= 0 &&
        static_cast<uint64_t>(value) <= first - second + (kind == 6 ? 2 : 0);
    case 7: return value >= 0 && static_cast<uint64_t>(value) <= second;
    case 8: return first < UINT32_MAX;
    case 9: return first < UINT32_MAX && second == first + 1;
    case 10: return first > 0;
    case 11: return first < second;
    case 12:
        if (facts > 7) return -1;
        if (first > UINT32_MAX || second > UINT32_MAX) return 0;
        if (!(facts & 1) || (facts & 4)) return 1;
        if (facts & 2) return 0;
        return second >= first;
    default: return -1;
    }
}

extern "C" int32_t reference_event_identity(uint32_t kind, const unsigned char* hash, uint32_t size,
    uint64_t number, uint32_t status, unsigned char* output, uint32_t capacity)
{
    if (size > 64) return -1;
    const std::string txid(reinterpret_cast<const char*>(hash), size);
    std::string result;
    switch (kind) {
    case 0: result = "sidechain:bundle:" + txid + ":" + std::to_string(static_cast<int64_t>(number)); break;
    case 1: result = "sidechain:deposit:" + txid + ":" + std::to_string(number); break;
    case 2: result = "sidechain:withdrawal:" + txid + ":" + std::to_string(number); break;
    case 3: result = "l1:deposit:" + txid + ":" + std::to_string(static_cast<int64_t>(number)); break;
    case 4: {
        const char* names[]{"submitted", "succeeded", "failed"};
        if (status > 2) return -1;
        result = "l1:withdrawal:" + txid + ":" + names[status] + ":" + std::to_string(static_cast<int64_t>(number));
        break;
    }
    default: return -1;
    }
    if (result.size() > capacity) return -1;
    std::memcpy(output, result.data(), result.size());
    return result.size();
}

extern "C" int32_t reference_split_signature(uint64_t count, const unsigned char* bytes, uint64_t* prefix)
{
    if (!count || count > uint64_t(std::numeric_limits<intptr_t>::max()) || !bytes || !prefix) return -1;
    const auto hash_type = bytes[count - 1];
    *prefix = count - 1;
    return hash_type;
}

extern "C" void reference_private_template(uint32_t height, uint32_t time, uint32_t median,
    uint32_t slot, const unsigned char* critical, uint32_t* fields, unsigned char* commitment)
{
    fields[0] = 2;
    fields[1] = height + 1;
    fields[2] = 0x20000000;
    fields[3] = std::max(time + 1, median + 1);
    const unsigned char magic[]{0xd1, 0x61, 0x73, 0x68};
    std::memcpy(commitment, magic, 4);
    commitment[4] = static_cast<unsigned char>(slot);
    for (unsigned i = 0; i < 32; ++i) commitment[5+i] = critical[31-i];
}

extern "C" int32_t reference_empty_state_write(void*, uint32_t, uint32_t) { return 1; }
extern "C" int32_t reference_state_write(void* opaque, uint32_t action, uint32_t height)
{
    auto* fields = static_cast<int64_t*>(opaque);
    fields[1] = fields[1] * 10 + action + 1;
    fields[2] = height;
    return fields[0] != action;
}
extern "C" int32_t reference_store_state(int32_t height, int32_t restore, void* context)
{
    if (!reference_state_write(context, 0, 0)) return -1;
    if (!reference_state_write(context, 1, 0)) return -1;
    if (!reference_state_write(context, 2, std::max<int64_t>(int64_t{height} - restore, 0))) return -1;
    return 1;
}
extern "C" int32_t reference_encode_state(void* context)
{
    if (!reference_state_write(context, 0, 0)) return -1;
    if (!reference_state_write(context, 1, 0)) return -1;
    if (!reference_state_write(context, 2, 0)) return -1;
    if (!reference_state_write(context, 3, 117)) return -1;
    if (!reference_state_write(context, 3, 0)) return -1;
    return 1;
}
extern "C" int32_t reference_preimage(uint32_t kind, void* context)
{
    if (kind > 1) return -1;
    const uint32_t count = kind == 0 ? 10 : 4;
    for (uint32_t field = 0; field < count; ++field)
        if (!reference_state_write(context, field, 0)) return -1;
    return 1;
}
extern "C" int32_t reference_bmm_interval(int64_t timespan, int64_t spacing, int64_t* output)
{
    if (!output || spacing == 0 || (timespan == INT64_MIN && spacing == -1)) return -1;
    *output = timespan / spacing;
    return 0;
}

extern "C" int32_t reference_signature_actions(uint32_t plan, void* context)
{
    if (plan > 15) return -1;
    if ((plan & 1) && !reference_state_write(context, 0, 0)) return -1;
    if ((plan & 2) && !reference_state_write(context, 1, 0)) return -1;
    if (plan & 4) {
        if (!reference_state_write(context, 2, 0)) return -1;
    } else if ((plan & 8) && !reference_state_write(context, 3, 0)) return -1;
    return 1;
}

extern "C" int32_t reference_bmm_identity(uint32_t* fields, unsigned char* bytes)
{
    if (!fields || !bytes) return -1;
    const unsigned char expected[121] = {67,229,222,57,73,77,243,166,89,226,255,210,97,0,73,239,94,64,103,3,42,244,74,6,66,19,36,137,203,49,47,148,152,105,64,168,114,179,123,104,122,184,243,221,24,139,59,194,227,58,227,229,14,218,36,38,230,242,55,176,227,223,119,206,249,159,87,0,19,42,3,8,140,185,182,168,245,93,161,209,234,88,84,13,84,213,116,109,198,167,200,136,202,247,188,240,100,114,105,118,101,99,104,97,105,110,45,98,109,109,45,118,49,236,199,218,162,209,97,115,104};
    fields[0] = 0;
    fields[1] = (1U << 0) | (1U << 2) | (1U << 4) | (1U << 11);
    for (unsigned i = 0; i < 121; ++i) bytes[i] = expected[i];
    return 0;
}

extern "C" int32_t reference_bmm_checkpoint(uint32_t mode, uint32_t* fields, unsigned char* hash)
{
    if (mode > 1 || !fields || !hash) return -1;
    const uint32_t values[2][16] = {
        {6400,1784826005,0x1e0376cc,6048,1784614805,1784820005,1784820605,1784821205,
         1784821805,1784822405,1784823005,1784823605,1784824205,1784824805,1784825405,1784826005},
        {2096,1802055061,0x207fffff,2016,1786323045,1802055058,1802055058,1802055059,
         1802055058,1802055059,1802055059,1802055060,1802055059,1802055060,1802055060,1802055061}};
    const unsigned char hashes[2][32] = {{0x65,0x76,0x74,0x19,0x0b,0x9b,0xd4,0x39,0xb4,0x7f,0xff,0x98,0xfb,0x29,0xde,0x90,0xee,0x6c,0xab,0xc0,0x8c,0xd4,0xeb,0xd1,0x4e,0x84,0x9e,0xb6,0x1b,0x03,0x00,0x00},{0x9f,0x8d,0x72,0xf9,0x78,0xf7,0x1a,0x6c,0xce,0x89,0xc3,0x3f,0x50,0x23,0x57,0x43,0xa7,0x7a,0xf1,0x26,0xa6,0x51,0xee,0x4f,0xd2,0x0c,0x19,0x68,0xd4,0xe8,0x4f,0x63}};
    for (unsigned i = 0; i < 16; ++i) fields[i] = values[mode][i];
    for (unsigned i = 0; i < 32; ++i) hash[i] = hashes[mode][i];
    return 0;
}

extern "C" int32_t reference_bmm_preset(uint32_t mode, uint64_t* fields, unsigned char* pow_limit, unsigned char* challenge)
{
    if (mode > 1 || !fields || !pow_limit || !challenge) return -1;
    const uint64_t numbers[]{14 * 24 * 60 * 60, 10 * 60, 24, 128, 1000000, mode == 0 ? 1U : 0U};
    for (unsigned i = 0; i < 6; ++i) fields[i] = numbers[i];
    for (unsigned i = 0; i < 32; ++i) pow_limit[i] = mode == 0 ? 0 : 255;
    if (mode == 1) { pow_limit[31] = 127; return 0; }
    pow_limit[27] = 0xae; pow_limit[28] = 0x77; pow_limit[29] = 3;
    const unsigned char script[]{0,0x14,0x88,0x35,0x83,0x2e,0x28,0xc8,0x16,0xb7,0xac,0xd8,0xfd,0xb1,0x97,0x72,0xab,0x21,0x99,0x60,0x3a,0x56};
    for (unsigned i = 0; i < 22; ++i) challenge[i] = script[i];
    return 22;
}

extern "C" int32_t reference_commitment_bytes(uint32_t kind, uint32_t size,
    const unsigned char* input, unsigned char* output)
{
    if (!input || !output || (kind != 0 && kind != 1) || size != (kind == 0 ? 37U : 32U)) return -1;
    for (uint32_t i = 0; i < 32; ++i) output[i] = input[kind == 0 ? 36 - i : i];
    return 0;
}

extern "C" int32_t reference_signet_actions(uint32_t mode, void* context)
{
    if (mode > 1) return -1;
    const uint32_t count = mode == 0 ? 6 : 2;
    for (uint32_t action = 0; action < count; ++action)
        if (!reference_state_write(context, action, 0)) return -1;
    return 1;
}

extern "C" int32_t reference_bmm_scale_target(uint32_t count, uint64_t factor, uint64_t divisor,
    unsigned char* target, const unsigned char* limit)
{
    if (count != 32 || !target || !limit || !divisor) return -1;
    unsigned char product[32], quotient[32]{};
    uint64_t carry{0}, remainder{0};
    for (unsigned i = 0; i < 32; ++i) {
        carry += uint64_t(target[i]) * uint32_t(factor);
        product[i] = carry;
        carry >>= 8;
    }
    for (int bit = 255; bit >= 0; --bit) {
        const bool overflow = remainder >> 63;
        remainder = (remainder << 1) | ((product[bit / 8] >> (bit % 8)) & 1);
        if (overflow || remainder >= divisor) {
            remainder -= divisor;
            quotient[bit / 8] |= 1U << (bit % 8);
        }
    }
    const unsigned char* result = quotient;
    for (int i = 31; i >= 0; --i) {
        if (quotient[i] == limit[i]) continue;
        if (quotient[i] > limit[i]) result = limit;
        break;
    }
    std::memmove(target, result, 32);
    return 0;
}

extern "C" int32_t reference_empty_fingerprint(void*, uint32_t, uint32_t, uint64_t* value, unsigned char** bytes)
{
    *value = 0;
    *bytes = nullptr;
    return 1;
}

// Fixture context: seed, private mode, failing field (group*32+index+1),
// writer failure; counters at 4..6, scratch blob at 16, emitted bytes at 32.
extern "C" int32_t reference_fingerprint_read(void* opaque, uint32_t group, uint32_t index,
    uint64_t* value, unsigned char** bytes)
{
    auto* ctx = static_cast<uint64_t*>(opaque);
    ++ctx[4];
    if (ctx[2] == group * 32 + index + 1) return 0;
    if (group == 1) {
        *value = (ctx[0] + index) % 16;
        *bytes = reinterpret_cast<unsigned char*>(ctx + 16);
        for (uint64_t i = 0; i < *value; ++i) (*bytes)[i] = (ctx[0] >> (i % 8 * 8)) + index + i;
    } else if (group == 0 && index == 2) *value = ctx[1];
    else if ((group == 2 || group == 4) && index == 5) *value = ctx[0] % 12;
    else *value = ctx[0] ^ (uint64_t(group) << 40) ^ (uint64_t(index) << 16);
    return 1;
}

extern "C" int32_t reference_fingerprint_write(void* opaque, unsigned char* bytes, uint64_t size)
{
    auto* ctx = static_cast<uint64_t*>(opaque);
    ++ctx[5];
    if (ctx[3] || size > 992) return 0;
    ctx[6] = size;
    for (uint64_t i = 0; i < size; ++i) ctx[32+i] = bytes[i];
    return 1;
}

extern "C" int32_t reference_fingerprint(void* opaque)
{
    unsigned char payload[992];
    size_t size = 0;
    bool ok = true;
    const auto append_number = [&](unsigned width, uint64_t value) {
        for (int shift = (width - 1) * 8; shift >= 0; shift -= 8) payload[size++] = value >> shift;
    };
    const auto number = [&](uint32_t group, uint32_t index, unsigned width) {
        uint64_t value{0}; unsigned char* bytes{nullptr};
        if (ok) ok = reference_fingerprint_read(opaque, group, index, &value, &bytes);
        if (ok) append_number(width, value);
        return value;
    };
    const auto blob = [&](uint32_t index, bool sized) {
        uint64_t count{0}; unsigned char* bytes{nullptr};
        if (ok) ok = reference_fingerprint_read(opaque, 1, index, &count, &bytes);
        if (ok) {
            if (sized) append_number(8, count);
            for (uint64_t i = 0; i < count; ++i) payload[size++] = bytes[i];
        }
    };
    uint64_t mode{0}; unsigned char* ignored{nullptr};
    ok = reference_fingerprint_read(opaque, 0, 2, &mode, &ignored);
    if (!ok || mode > 1) return -1;
    append_number(4, 4);
    number(0, 0, 1); number(0, 1, 4); append_number(1, mode);
    blob(0, false); number(0, 3, 8); number(0, 4, 8); blob(1, true);
    number(0, 5, 1); number(0, 6, 4); number(0, 7, 8); number(0, 8, 8);
    for (uint32_t state = 0; state <= mode; ++state) {
        blob(8 + state, false);
        const uint32_t group = 2 + 2 * state;
        for (uint32_t index = 0; index < 5; ++index) number(group, index, 4);
        const auto count = number(group, 5, 8);
        for (uint32_t i = 0; i < count && ok; ++i) number(group + 1, i, 4);
    }
    blob(2, false); blob(3, false); blob(4, false); number(0, 9, 4);
    blob(5, true); blob(6, false); blob(7, false); number(0, 10, 4);
    return ok ? reference_fingerprint_write(opaque, payload, size) : -1;
}

// Frozen signet control flow, with a decimal action trace instead of Bitcoin primitives.
extern "C" int32_t reference_signet_validation(const uint64_t* f, uint64_t* trace)
{
    *trace = 1;
    if (!f[0]) return -1;
    *trace = *trace * 10 + 2;
    if (!f[1]) return -2;
    *trace = *trace * 10 + 3;
    if (f[2]) {
        *trace = *trace * 10 + 4;
        if (f[3] == 1) return -3;
        if (f[3] == 2) return -4;
        if (f[3] != 0) return -7;
    }
    *trace = *trace * 10 + 5;
    if (!f[4] || f[5] != 1 || f[6] != 1 || f[7] != 0) return -5;
    *trace = *trace * 10 + 6;
    if (!f[8]) return -5;
    *trace = *trace * 10 + 7;
    return f[9] ? 0 : -6;
}

extern "C" int32_t reference_bmm_sighash_plan(int32_t type, uint32_t index, uint64_t outputs)
{
    int32_t result{0};
    const auto base = type & 0x1f;
    if (!(type & 0x80)) result |= 1;
    if (!(type & 0x80) && base != 3 && base != 2) result |= 2;
    if (base != 3 && base != 2) result |= 4;
    else if (base == 3 && index < outputs) result |= 8;
    return result;
}

extern "C" int32_t reference_bmm_signature_gate(uint32_t witness, uint64_t size, uint32_t index, uint64_t inputs)
{
    return !witness || !size || index >= inputs ? 0 : 1;
}

extern "C" int32_t reference_signet_step(void* opaque, uint32_t action, int64_t* fields)
{
    auto* ctx = static_cast<int64_t*>(opaque);
    ++ctx[2];
    ctx[3] = (ctx[3] * 7 + action + 1) % 1000000007;
    if (action != 0) return action <= 4 ? 1 : 0;
    const auto row = ctx[1]++;
    if (row == ctx[0]) { fields[0] = 0; fields[1] = 1; fields[2] = fields[3] = 0; }
    else std::memcpy(fields, ctx + 4 + row * 4, 4 * sizeof(int64_t));
    return fields[0] == -1 ? 0 : 1;
}

extern "C" int32_t reference_signet_empty(void*, uint32_t action, int64_t* fields)
{
    if (action) return 0;
    fields[0] = 0; fields[1] = 1; fields[2] = fields[3] = 0;
    return 1;
}

extern "C" int32_t reference_signet_fail_write(void* context, uint32_t action, int64_t* fields)
{
    const auto result = reference_signet_step(context, action, fields);
    return action == 0 ? result : 0;
}

extern "C" int32_t reference_signet_extract(void* context)
{
    bool found{false};
    int64_t f[4];
    while (true) {
        if (reference_signet_step(context, 0, f) != 1 || f[0] < 0 || f[0] > 1 ||
            f[1] < 0 || f[1] > 1 || f[2] < 0 || f[3] < 0 || f[3] > 0xffffffffLL) return -1;
        if (!f[0]) {
            if (!f[1]) return 0;
            if (found) reference_signet_step(context, 4, f);
            return 1;
        }
        if (!found && f[2] > 4 && f[3] == 0xa2dac7ec) {
            reference_signet_step(context, 1, f);
            found = true;
        }
        reference_signet_step(context, f[2] > 0 ? 2 : 3, f);
    }
}

extern "C" int64_t reference_bmm_retarget(uint32_t height, int64_t interval, int64_t target, uint32_t time, uint32_t start)
{
    if (interval <= 0) return -2;
    if ((int64_t(height) + 1) % interval != 0) return -1;
    if (target <= 0 || target > std::numeric_limits<int64_t>::max() / 4) return -2;
    int64_t actual = int64_t(time) - start;
    actual = std::max(target / 4, actual);
    return std::min(target * 4, actual);
}

extern "C" int64_t reference_bmm_median(uint32_t count, const uint32_t* times)
{
    if (!count || !times) return -2;
    auto* sorted = static_cast<uint32_t*>(std::malloc(size_t(count) * sizeof(uint32_t)));
    if (!sorted) return -2;
    std::memcpy(sorted, times, size_t(count) * sizeof(uint32_t));
    std::qsort(sorted, count, sizeof(uint32_t), +[](const void* a, const void* b) {
        const auto x = *static_cast<const uint32_t*>(a), y = *static_cast<const uint32_t*>(b);
        return (x > y) - (x < y);
    });
    const auto result = sorted[count / 2];
    std::free(sorted);
    return result;
}

extern "C" int32_t reference_bmm_fields(void* opaque, uint32_t index, int64_t* fields)
{
    auto* context = static_cast<int64_t*>(opaque);
    ++context[0];
    std::memcpy(fields, context + 1 + index * 4, 4 * sizeof(int64_t));
    return fields[0] == -1 ? 0 : 1;
}

extern "C" int64_t reference_bmm_commitment(uint32_t kind, int32_t slot, uint32_t count, void* context)
{
    if (kind > 2) return -3;
    int64_t found{-1};
    for (uint32_t i = 0; i < count; ++i) {
        int64_t f[4];
        if (reference_bmm_fields(context, i, f) != 1) return -3;
        if (kind == 2) {
            if (f[0] < 0 || f[1] < 0 || f[1] > 0xffffffffffffLL) return -3;
            if (f[0] >= 38 && f[1] == 0xeda921aa246aLL) found = i;
            continue;
        }
        if (f[0] < 0 || f[0] > 524287 || f[1] < 0) return -3;
        if ((f[0] & 511) != 106 || ((f[0] >> 9) & 511) > 78 || !(f[0] & (1 << 18))) continue;
        if (kind == 0 ? (f[1] != 37 || f[2] != 0x687361d1 || f[3] != slot) : f[1] != 32) continue;
        if (found >= 0) return -2;
        found = i;
    }
    return found;
}

extern "C" int32_t reference_bmm_script(void* opaque, uint32_t index, uint32_t action, int64_t* fields)
{
    auto* context = static_cast<int64_t*>(opaque);
    const auto* row = context + 1 + index * 4;
    if (action < 2) ++context[0];
    if (row[0] == -1) return 0;
    std::memset(fields, 0, 4 * sizeof(int64_t));
    if (action == 0) std::memcpy(fields, row, 4 * sizeof(int64_t));
    else if (action == 1) {
        if (row[0] < 0 || row[0] > 524287) return 0;
        fields[0] = row[0] & 511;
    } else if (action == 2) fields[0] = (row[0] >> 9) & 511;
    else if (action == 3) {
        fields[0] = row[0] >> 18;
        for (unsigned i = 1; i < 4; ++i) fields[i] = row[i];
    } else return 0;
    return 1;
}

extern "C" int32_t reference_bmm_decode_flow(uint32_t begin, uint32_t end, uint32_t failure, uint64_t* trace)
{
    *trace = 0;
    for (uint32_t action = begin; action <= end; ++action) {
        *trace = *trace * 43 + action;
        if (action == failure) return -1;
    }
    return 0;
}

extern "C" int32_t reference_bmm_extension_flow(uint32_t facts, uint64_t* trace)
{
    *trace = 50;
    const bool parent = facts & 1;
    bool difficulty = false, time = false;
    if (parent) { *trace = *trace * 59 + 51; difficulty = facts & 2; }
    if (difficulty) { *trace = *trace * 59 + 52; time = facts & 4; }
    *trace = *trace * 59 + 53;
    if (!time) return -1;
    *trace = *trace * 59 + 54;
    return facts & 8 ? 0 : -1;
}

extern "C" int32_t reference_bmm_selection_flow(uint32_t mode, uint32_t facts, uint64_t* trace)
{
    *trace = 0;
    const auto visit = [&](uint32_t action) { *trace = *trace * 79 + action; };
    if (mode == 0) {
        visit(64);
        if (!(facts & 1)) return -1;
        visit(65);
        const bool decoded = facts & 2;
        visit(66);
        if (!decoded || !(facts & 4)) return -1;
        visit(67);
        return facts & 8 ? 0 : -1;
    }
    visit(69);
    if (!(facts & 1)) return -1;
    visit(70);
    if (facts & 2) return 0;
    if (facts & 4) return -1;
    visit(71);
    if (facts & 8) { visit(72); return 0; }
    visit(73);
    if (!(facts & 16)) return -1;
    visit(74);
    return 0;
}

extern "C" int32_t reference_bmm_state_flow(uint32_t disconnect, const int32_t* replies, uint64_t* out)
{
    out[0] = out[1] = 0;
    const auto visit = [&](uint32_t action) {
        out[0] = (out[0] * 29 + action) % 1000000007;
        if (action == 6 || action == 11 || action == 15 || action == 20) ++out[1];
        return replies[action];
    };
    if (!disconnect) {
        if (visit(1) == 1) {
            if (!visit(2)) return -1;
            return visit(3) == 0 ? 0 : -1;
        }
        if (visit(4) == 3) {
            if (visit(5) != 5) return -1;
            visit(6);
            return 0;
        }
        if (visit(7) == 0) return 0;
        if (visit(8) == 0) return 0;
        if (!visit(9) || !visit(10)) return -1;
        visit(11);
        return 0;
    }
    if (visit(13) == 1) {
        if (visit(14) != 3) return -1;
        return visit(15) == 0 ? 0 : -1;
    }
    if (visit(16) == 0) return 0;
    if (!visit(17) || visit(18) != 5) return -1;
    if (!visit(19) || !visit(21)) { visit(23); return -1; }
    if (visit(22) != 6) return -1;
    visit(20);
    return 0;
}

extern "C" int32_t reference_private_build(uint32_t failure, uint32_t retries, uint64_t* out)
{
    out[0] = out[1] = 0;
    const auto visit = [&](uint32_t action) {
        out[0] = (out[0] * 37 + action) % 1000000007;
        if (action == 31) ++out[1];
        return action != failure;
    };
    if (!visit(25) || !visit(26)) return -1;
    visit(27);
    visit(28);
    visit(29);
    while (retries--) { visit(30); visit(29); }
    visit(31);
    return visit(32) ? 0 : -1;
}

extern "C" int32_t reference_bmm_lifecycle(uint32_t phase, uint32_t f)
{
    switch (phase) {
    case 0: if (f <= 1) return f ? 1 : 2; break;
    case 1: if (f <= 1) return f ? -1 : 0; break;
    case 2: if (f <= 1) return f ? 3 : 4; break;
    case 3: if (f <= 3) return (f & 1) ? -2 : (f & 2) ? -3 : 5; break;
    case 4: if (f <= 3) return f ? 6 : 0; break;
    case 5: if (f <= 15) return f == 15 ? 0 : 7; break;
    case 6: if (f <= 1) return f ? 1 : 2; break;
    case 7: if (f <= 7) return (f & 3) == 3 ? 3 : (f & 4) ? -3 : -4; break;
    case 8: if (f <= 1) return f ? 0 : -5; break;
    case 9: if (f <= 1) return f ? 4 : 0; break;
    case 10: if (f <= 3) return (f & 1) ? 5 : (f & 2) ? -3 : -6; break;
    case 11: if (f <= 1) return f ? 6 : -7; break;
    }
    return -8;
}

extern "C" int32_t reference_bmm_state_source(uint32_t phase, uint32_t facts)
{
    if (phase == 0 && facts <= 1) return facts ? -1 : 1;
    if (phase == 1 && facts <= 3) return (facts & 1) ? 0 : (facts & 2) ? -2 : 2;
    if (phase == 2 && facts <= 1) return facts ? 3 : 4;
    if (phase == 3 && facts <= 1) return facts ? 5 : -3;
    if (phase == 4 && facts <= 1) return facts ? 1 : 0;
    if (phase == 5 && facts <= 1) return facts ? 0 : -2;
    return -4;
}

extern "C" int32_t reference_bmm_wrapper(uint32_t failure, uint64_t* trace)
{
    *trace = 0;
    for (uint32_t phase = 12; phase <= 17; ++phase) {
        *trace = *trace * 19 + phase;
        if (phase == failure) return -1;
    }
    return 0;
}

extern "C" int32_t reference_bmm_advance(int64_t interval, uint32_t time, uint32_t bits, uint32_t* f)
{
    if (interval <= 0) return -1;
    ++f[0];
    f[1] = time;
    f[2] = bits;
    std::memmove(f + 5, f + 6, 10 * sizeof(uint32_t));
    f[15] = time;
    if (f[0] % interval == 0) {
        f[3] = f[0];
        f[4] = f[1];
    }
    return 0;
}

extern "C" int32_t reference_bmm_traversal(uint64_t count, uint64_t signet, uint64_t fail_entry, uint32_t fail_phase, uint64_t* out)
{
    out[0] = out[1] = 0;
    const auto visit = [&](uint32_t phase) { out[0] = (out[0] * 13 + phase) % 1000000007; };
    visit(1);
    if (!count || fail_phase == 1) return -1;
    visit(18);
    if (fail_phase == 18) return -1;
    for (uint64_t i = 0; i < count; ++i) {
        for (uint32_t phase = 2; phase <= (signet ? 6U : 5U); ++phase) {
            visit(phase);
            if (i == fail_entry && phase == fail_phase) return phase >= 5 ? -2 : -1;
            if (phase == 2) {
                visit(20);
                if (i == fail_entry && fail_phase == 20) return -1;
            }
        }
        visit(7);
        ++out[1];
    }
    for (uint32_t phase = 8; phase <= 10; ++phase) {
        visit(phase);
        if (phase == fail_phase) return -1;
    }
    visit(19);
    if (fail_phase == 19) return -1;
    return 0;
}

extern "C" int32_t reference_bmm_codec(uint32_t phase, uint32_t f, uint64_t a, uint64_t b)
{
    switch (phase) {
    case 0: return a == 0 || a > b ? 1 : 0;
    case 1: return a == 0 || a > b ? 2 : 0;
    case 2: return f != 3 || a == 0 || a > b ? 3 : 0;
    case 3: return f ? 0 : 3;
    case 4: return f ? 0 : 4;
    case 5: return f == 31 ? 0 : 5;
    case 6: return !f || a > 78 ? 6 : 0;
    case 7: return !f || a != 117 ? 6 : 0;
    case 8: return f != 3 || a != 0 ? 6 : 0;
    case 9: return f == 3 ? 0 : 7;
    case 10: return 8;
    default: return -1;
    }
}

extern "C" int32_t reference_bmm_proof(uint32_t phase, uint32_t f, uint64_t a, uint64_t b, uint64_t c)
{
    switch (phase) {
    case 0: return !f || !a || a > b ? 1 : 0;
    case 1: return !a || a > c || !b || b > c ? 2 : 0;
    case 2: return f != 31 || a != 1 ? 3 : 0;
    case 3: return !f || a != 1 || b != 1 || c != 0 ? 4 : 0;
    case 4: return f != 7 ? 5 : 0;
    case 5: return f ? 0 : 6;
    case 6: return f ? 0 : 7;
    case 7: return f != 3 || !a || a > b ? 8 : 0;
    case 8: return f ? 0 : 8;
    case 9: return f ? 0 : 9;
    case 10: return f ? 0 : 4;
    case 11: return f == 0 ? 0 : 10;
    case 12: return f ? 0 : 10;
    case 13: return f ? 0 : 11;
    default: return -1;
    }
}

extern "C" int32_t reference_bmm_activation(uint32_t phase, uint32_t facts, int64_t height, int64_t activation)
{
    if (phase == 0 && facts <= 3) return (facts & 1) || !(facts & 2) ? 0 : 2;
    if (phase == 1 && facts <= 1) {
        if (!facts) return -2;
        if (activation <= 0 || activation >= 2147483647) return -3;
        return height >= activation - 1 ? 1 : 0;
    }
    if (phase == 2 && facts <= 3) return facts ? 1 : 0;
    if (phase == 3 && facts == 0) return activation != 2147483647 && height >= activation;
    if (phase == 4 && facts <= 1) {
        if (height >= activation) return 1;
        return facts == 1 && height == activation - 1;
    }
    return -1;
}

extern "C" int32_t reference_bmm_state(uint32_t hash, int64_t interval, uint32_t height,
    uint32_t time, uint32_t bits, uint32_t start, uint32_t start_time, uint64_t count, uint32_t latest)
{
    return !hash || !height || !time || !bits || interval <= 0 || start > height ||
        start % interval != 0 || height - start >= static_cast<uint32_t>(interval) ||
        !start_time || count != 11 || latest != time ? 1 : 0;
}

extern "C" int32_t reference_bmm_header(uint32_t f)
{
    if (f > 511) return -1;
    if (!(f & 256)) {
        if (f & 1) return (f & (16 | 32)) ? 1 : 0;
        if (!(f & 2)) return 0;
        if ((f & 4) && !(f & 8)) return 2;
        return 6;
    }
    if ((f & 64) && !(f & 16)) return 3;
    if ((f & 64) && !(f & 32) && !(f & 128)) return 4;
    return !(f & 64) && (f & 16) ? 5 : 0;
}

extern "C" int64_t reference_peg_event(uint32_t kind, int64_t a, int64_t b, int64_t c)
{
    if (kind == 1) return a < 0 || b <= 0 || c < 0 ? -3 : 0;
    if (kind == 2) {
        if (a < 0 || a > 3 || b < 0 || b > 3) return -6;
        if (b == 3) return -4;
        if (b == 0) return a == 0 ? 1 : a;
        if (a >= 2 && a != b + 1) return -5;
        return b + 1;
    }
    if (kind != 0 || a < 0 || a > 7 || b < 0 || b > 7) return -6;
    int count{0}, selected{0};
    for (int i = 0; i < 3; ++i) if (a & (1 << i)) { ++count; selected = i; }
    if (count != 1) return -1;
    return b & (1 << selected) ? selected : -2;
}

extern "C" int32_t reference_live_empty(void*, uint32_t, int64_t* fields)
{
    for (unsigned i = 0; i < 4; ++i) fields[i] = 0;
    return 1;
}

// Scripted callback: cursor, response count, then (step,status,f0,f1,f2,f3).
extern "C" int32_t reference_scripted_fields(void* opaque, uint32_t step, int64_t* fields)
{
    auto* state = static_cast<int64_t*>(opaque);
    const int64_t cursor = state[0]++;
    if (cursor >= state[1]) return -1;
    const auto* response = state + 2 + 6 * cursor;
    if (response[0] != step) return -1;
    if (response[1] == 1) std::memcpy(fields, response + 2, 4 * sizeof(int64_t));
    return response[1];
}

extern "C" int32_t reference_live_fields(void* opaque, uint32_t step, int64_t* fields)
{
    auto* state = static_cast<int64_t*>(opaque);
    ++state[0];
    state[1] = state[1] * 8 + step + 1;
    if (step > 5) return -1;
    if (state[2] == step) return state[3];
    std::memcpy(fields, state + 4 + 4 * step, 4 * sizeof(int64_t));
    return 1;
}

extern "C" int32_t reference_live_evidence(uint32_t phase,
    int32_t (*reader)(void*, uint32_t, int64_t*), void* context)
{
    int64_t f[4];
    const auto read = [&](uint32_t step) {
        const auto status = reader(context, step, f);
        return status == 0 ? -1 : status == 1 ? 0 : -2;
    };
    if (phase > 5) return -2;
    if (const auto failure = read(0)) return failure;
    switch (phase) {
    case 0:
        if (f[0] < 0 || f[0] > 255) return 1;
        if (!f[1]) return 2;
        if (!f[2]) return 3;
        if (const auto failure = read(1)) return failure;
        if (!f[0]) return 4;
        if (!f[1]) return 5;
        if (const auto failure = read(2)) return failure;
        if (!f[0]) return 6;
        if (const auto failure = read(3)) return failure;
        if (!f[0]) return 7;
        if (const auto failure = read(4)) return failure;
        if (!f[0] || !f[1]) return 8;
        if (const auto failure = read(5)) return failure;
        return !f[0] || f[1] != f[2] ? 9 : 0;
    case 1:
        if (!f[0]) return 10;
        if (const auto failure = read(1)) return failure;
        if (f[0] <= 0) return 11;
        if (f[1] != f[2]) return 12;
        if (const auto failure = read(2)) return failure;
        if (!f[0]) return 13;
        return f[1] ? 0 : 14;
    case 2:
        if (!f[0]) return 15;
        if (const auto failure = read(1)) return failure;
        if (f[0] <= 0) return 16;
        if (const auto failure = read(2)) return failure;
        return !f[0] || f[1] != f[2] ? 17 : 0;
    case 3:
        if (f[0] < 0 || f[0] > UINT32_MAX) return 35;
        if (const auto failure = read(1)) return failure;
        if (f[0] <= 0 || f[1] < 0) return 18;
        if (f[1] < f[2]) return 19;
        return f[1] == f[2] && !f[3] ? 20 : 0;
    case 4: {
        const int64_t count = f[0];
        if (count < 0) return -2;
        bool found{false};
        for (int64_t i = 0; i < count; ++i) {
            if (const auto failure = read(1)) return failure;
            if (!f[0]) return 21;
            if (f[1] != f[2]) continue;
            if (found) return 22;
            if (const auto failure = read(2)) return failure;
            found = true;
        }
        if (!found) return 23;
        if (const auto failure = read(3)) return failure;
        if (f[0] < 0 || f[0] > f[1]) return 24;
        for (uint32_t step = 4; step <= 6; ++step) {
            if (const auto failure = read(step)) return failure;
            if (!f[0]) return 25;
        }
        return 0;
    }
    default: {
        const int64_t count = f[0];
        if (count < 0) return -2;
        bool found{false};
        for (int64_t block = 0; block < count; ++block) {
            if (const auto failure = read(1)) return failure;
            if (!f[0]) return 26;
            if (const auto failure = read(2)) return failure;
            if (!f[0]) continue;
            if (f[0] != 1) return 27;
            const int64_t events = f[1];
            if (events < 0) return -2;
            for (int64_t event = 0; event < events; ++event) {
                if (const auto failure = read(3)) return failure;
                if (!f[0]) return 28;
                if (const auto failure = read(4)) return failure;
                if (!f[0]) continue;
                if (!f[1]) return 29;
                if (const auto failure = read(5)) return failure;
                if (f[1] < 0 || f[1] > UINT32_MAX) return 35;
                if (!f[0]) continue;
                if (found) return 30;
                if (const auto failure = read(6)) return failure;
                if (f[0] <= 0 || f[0] != f[1]) return 31;
                if (f[2] < 0) return 32;
                if (const auto failure = read(7)) return failure;
                if (f[0] < 0) return -2;
                if (!f[0]) return 36;
                for (int64_t remaining = f[0]; remaining > 0; remaining -= 4) {
                    if (const auto failure = read(9)) return failure;
                    for (int i = 0; i < 4 && i < remaining; ++i)
                        if (f[i] < 0x21 || f[i] > 0x7e) return 37;
                }
                if (const auto failure = read(8)) return failure;
                if (!f[0]) return 33;
                if (const auto failure = read(10)) return failure;
                found = true;
            }
        }
        return found ? 0 : 34;
    }
    }
}

extern "C" int32_t reference_legacy_claim(uint32_t facts, int64_t actual, int64_t expected)
{
    if (!(facts & 1) || actual != expected) return 1;
    if (!(facts & 2)) return 2;
    return 0;
}

extern "C" int32_t reference_destination_inspect(void* opaque, uint32_t index, uint32_t action)
{
    auto* state = static_cast<int64_t*>(opaque);
    if (action == 0) { ++state[0]; state[2] = index; return state[3 + 2 * index]; }
    if (action != 1 || state[2] != index) return -1;
    ++state[1];
    return state[4 + 2 * index];
}

extern "C" int64_t reference_deposit_destination(uint32_t count,
    int32_t (*inspect)(void*, uint32_t, uint32_t), void* context)
{
    int64_t found{-1};
    for (uint32_t index = 0; index < count; ++index) {
        const int32_t script = inspect(context, index, 0);
        if (script < 0 || script > 1048575) return -3;
        if ((script & 511) != 106 || ((script >> 9) & 511) > 78 || ((script >> 18) & 3) != 3) continue;
        const auto valid = inspect(context, index, 1);
        if (valid < 0 || valid > 1) return -3;
        if (!valid) continue;
        if (found >= 0) return -2;
        found = index;
    }
    return found;
}

// Project the frozen packed fixture into the new primitive-read protocol.
extern "C" int32_t reference_destination_inspect_v2(void* opaque, uint32_t index, uint32_t action)
{
    auto* state = static_cast<int64_t*>(opaque);
    if (action == 0) {
        const int32_t packed = reference_destination_inspect(opaque, index, 0);
        return packed < 0 || packed > 1048575 ? -1 : packed & 511;
    }
    if (state[2] != index) return -1;
    if (action == 1) return state[3 + 2 * index] >> 9;
    if (action == 2) return reference_destination_inspect(opaque, index, 1);
    return action == 3 ? 1 : -1;
}

extern "C" int32_t reference_deposit_state(uint32_t phase, uint32_t facts)
{
    const bool present = facts & 1, corrupt = facts & 2, matches = facts & 4;
    switch (phase) {
    case 0:
        if (present) return 1;
        if (corrupt) return 2;
        return 0;
    case 1:
        if (!present) return corrupt ? 2 : 3;
        return matches ? 0 : 4;
    case 2:
        if (!present) return corrupt ? 2 : 5;
        return matches ? 0 : 6;
    case 3: return present ? 0 : corrupt ? 2 : 7;
    case 4: return matches ? 0 : 8;
    case 5: return matches ? 0 : 9;
    case 6: return matches ? 0 : 10;
    case 7: return matches ? 0 : 11;
    default: return -1;
    }
}

extern "C" int32_t reference_ctip_decode(void* opaque, int64_t* fields)
{
    auto* state = static_cast<int64_t*>(opaque);
    ++state[3];
    if (state[0] >= 8 && state[0] <= 15) std::memcpy(fields, state + 1, 2 * sizeof(int64_t));
    return state[0];
}

extern "C" int32_t reference_persisted_ctip(uint32_t facts, int64_t amount, uint32_t script,
    int32_t (*decode)(void*, int64_t*), void* context)
{
    if (!(facts & 1) || !(facts & 2) || !(facts & 4) || !(facts & 8) || amount != 0) return 1;
    if ((script & 511) > 78 || ((script >> 9) & 511) != 117 ||
        ((script >> 18) & 511) != 0 || !(facts & 16)) return 2;
    int64_t fields[2];
    const int32_t decoded = decode(context, fields);
    if (decoded == 0) return 4;
    if (decoded < 8 || decoded > 15) return -1;
    return decoded != 15 || fields[0] <= 0 || fields[1] < 0 ? 3 : 0;
}

extern "C" int32_t reference_parent_header(void* opaque, uint32_t index)
{
    auto* state = static_cast<int64_t*>(opaque);
    ++state[0];
    return state[index + 1];
}

extern "C" int32_t reference_deposit_inclusion(uint32_t facts, uint64_t matches, uint32_t count,
    int32_t (*check_header)(void*, uint32_t), void* context)
{
    if (!(facts & 1)) return 1;
    if (!(facts & 2) || matches != 1 || !(facts & 4) || !(facts & 8)) return 2;
    if (count == 0 || count > 2017) return -1; // Evidence decoder's established precondition.
    for (uint32_t i = 0; i < count; ++i) {
        const int32_t result = check_header(context, i);
        if (result < 0 || result > 3) return -1;
        if (!(result & 1)) return 3;
        if (i > 0 && !(result & 2)) return 4;
    }
    return 0;
}

extern "C" int32_t reference_deposit_ctip(uint32_t facts, uint64_t matches,
    int64_t current, int64_t previous, int64_t witnessed)
{
    if (!(facts & 1) || current <= 0) return 5;
    if (matches != 1) return 6;
    if (!(facts & 2) || previous <= 0 || current <= previous || current - previous != witnessed) return 7;
    return 0;
}

// Decoder double: status, current sequence, previous sequence, headers, calls.
extern "C" int32_t reference_evidence_decode(void* opaque, int64_t* output)
{
    auto* state = static_cast<int64_t*>(opaque);
    ++state[4];
    if (state[0] == 1) std::memcpy(output, state + 1, 3 * sizeof(int64_t));
    return state[0];
}

extern "C" int32_t reference_deposit_evidence(uint32_t maximum_tx, uint32_t count,
    const uint32_t* sizes, const unsigned char* const* stack, const unsigned char* prevout,
    int32_t (*hasher)(const unsigned char*, uint32_t, unsigned char*),
    int32_t (*decode)(void*, int64_t*), void* context)
{
    const char* marker = "drivechain-deposit-v2";
    if (count != 11 || sizes[4] != std::strlen(marker) || std::memcmp(stack[4], marker, sizes[4])) return 1;
    if (!sizes[5] || sizes[5] > maximum_tx || !sizes[6] || sizes[6] > maximum_tx ||
        !sizes[7] || sizes[7] > maximum_tx || !sizes[10] || sizes[10] > 2017 * 80 + 16) return 2;
    unsigned char txid[32];
    if (hasher(stack[5], sizes[5], txid) != 1 || std::memcmp(txid, prevout, 32)) return 3;
    int64_t decoded[3];
    if (decode(context, decoded) != 1) return 4;
    if (decoded[0] < 0 || decoded[1] < 0 || decoded[1] == std::numeric_limits<int64_t>::max() ||
        decoded[0] != decoded[1] + 1) return 5;
    return decoded[2] < 1 || decoded[2] > 2017 ? 6 : 0;
}

extern "C" int32_t reference_authenticated_deposit(uint64_t inputs, uint64_t index,
    uint64_t witnesses, uint32_t facts, int64_t claimed, int64_t witnessed,
    uint64_t count, const unsigned char* flags, const int64_t* amounts)
{
    if (inputs != 1 || index != 0 || index >= inputs) return 1;
    if (witnesses != 1) return 2;
    if (!(facts & 1) || !(facts & 2) || !(facts & 4) || !(facts & 8)) return 3;
    if (!(facts & 16) || witnessed != claimed || !(facts & 32) || !(facts & 64)) return 4;
    if (count == 0 || count > 2) return 5;
    int64_t credited{0}, fee{0};
    int credits{0}, fees{0};
    // Test generators keep both sums within int64_t, the old defined domain.
    for (uint64_t i = 0; i < count; ++i) {
        if (!(flags[i] & 1) || !(flags[i] & 2) || !(flags[i] & 4)) return 6;
        if (flags[i] & 8) { ++fees; fee += amounts[i]; }
        else {
            if (!(flags[i] & 16)) return 7;
            ++credits;
            credited += amounts[i];
        }
    }
    return credits != 1 || fees > 1 || credited <= 0 || fee < 0 || credited + fee != claimed ? 8 : 0;
}

extern "C" int32_t reference_wallet_issue_amount(const double* amount)
{
    return *amount <= 0;
}

extern "C" int32_t reference_depth(uint32_t deposit, uint32_t tip, uint32_t required)
{
    return required > 0 && deposit <= tip && tip - deposit >= required - 1;
}
extern "C" int32_t reference_slot(uint32_t script, uint32_t opcode)
{
    if ((opcode != 0xb4 && opcode != 0xb7) || (script & 0xff) != opcode ||
        ((script >> 8) & 0xff) != 1 || (script >> 24) != 0x51) return -1;
    return (script >> 16) & 0xff;
}
extern "C" int64_t reference_payout(int64_t burn, int64_t fee, int64_t maximum)
{
    if (burn <= 0 || burn > maximum) return -1;
    if (fee < 0 || fee > maximum) return -2;
    if (burn <= fee) return -3;
    return burn - fee;
}

extern "C" int32_t reference_legacy_frame(const unsigned char* bytes, uint32_t size)
{
    if (size < 124 || size > 251 || bytes[4] != 0 || bytes[5] != 3) return 0;
    size_t cursor{6};
    const auto consume = [&](size_t lo, size_t hi) {
        if (cursor > size || size - cursor < 9) return false;
        const size_t length = bytes[cursor + 8];
        if (length < lo || length > hi || size - cursor < 9 + length) return false;
        cursor += 9 + length;
        return true;
    };
    return consume(10,10) && consume(76,76) && consume(1,128) && cursor <= size && size - cursor == 4;
}

// A deterministic test double, not a Bitcoin parser. Native tests exercise the
// production upstream transaction decoder/hash through the same callback ABI.
extern "C" int32_t reference_transaction_hash(const unsigned char* bytes, uint32_t size, unsigned char* hash)
{
    if (size < 32 || bytes[0] == 255) return 0;
    std::memcpy(hash, bytes, 32);
    return 1;
}

extern "C" int32_t reference_accumulator_hash(const unsigned char*, uint32_t, unsigned char* hash)
{
    std::memset(hash, 42, 32);
    return 1;
}

extern "C" int32_t reference_deposit_witness(int64_t maximum, uint32_t maximum_tx,
    uint32_t mode, uint32_t count, const uint32_t* sizes, const unsigned char* const* stack,
    const unsigned char* asset, const unsigned char* genesis, const unsigned char* prevout,
    int32_t (*hash_transaction)(const unsigned char*,uint32_t,unsigned char*), int64_t* value)
{
    if (count != 6 && count != 8 && count != 11) return 0;
    const auto marker = [&](const char* expected) {
        return sizes[4] == std::strlen(expected) && std::memcmp(stack[4], expected, sizes[4]) == 0;
    };
    int kind{0};
    if (count == 6 && marker("drivechain-deposit-v1") && sizes[5] == 32) kind = 1;
    if (count == 8 && marker("drivechain-deposit-v2") && sizes[0] == 8 &&
        sizes[5] == 32 && sizes[6] == 32 && sizes[7] > 0 && sizes[7] <= 128) kind = 2;
    if (count == 11 && marker("drivechain-deposit-v2")) kind = 3;
    if (!kind || (mode == 1 && kind == 2) || (mode == 2 && kind != 2) || mode > 2) return 0;
    if (sizes[0] < 8 || sizes[1] != 32 || sizes[2] != 32 || sizes[3] > 100 ||
        std::memcmp(stack[1],asset,32) || std::memcmp(stack[2],genesis,32)) return 0;
    uint64_t encoded{0};
    for (unsigned i = 0; i < 8; ++i) encoded |= uint64_t{stack[0][i]} << (8*i);
    const int64_t amount = static_cast<int64_t>(encoded);
    if (amount <= 0 || amount > maximum) return 0;
    unsigned char txid[32];
    if (kind == 3) {
        if (sizes[5] > maximum_tx || hash_transaction(stack[5],sizes[5],txid) != 1) return 0;
    } else std::memcpy(txid,stack[5],32);
    if (std::memcmp(txid,prevout,32)) return 0;
    *value = amount;
    return kind;
}

extern "C" int32_t reference_deposit_outputs(uint32_t facts, int64_t value,
    uint32_t input_count, const unsigned char* inputs, uint32_t output_count,
    const unsigned char* flags, const int64_t* amounts)
{
    unsigned recognized{0}, recipients{0};
    for (unsigned i = 0; i < input_count; ++i) {
        if (inputs[i] & 1) ++recognized;
        else if (inputs[i] & 2) return 1;
    }
    if (recognized != 1) return 2;
    if (facts & 1) return 3;
    if (!(facts & 2)) return 4;
    if (!(facts & 4)) return 5;
    if (!(facts & 8)) return 6;
    for (unsigned i = 0; i < output_count; ++i) {
        if (!(flags[i] & 1)) continue;
        ++recipients;
        if (!(flags[i] & 2) || !(flags[i] & 4) || (flags[i] & 8) || amounts[i] != value) return 7;
    }
    return recipients == 1 ? 0 : 8;
}
