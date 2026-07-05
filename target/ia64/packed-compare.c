/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "insn.h"

/*
 * The current interpreter dispatch reaches major-opcode 0x8 ALU/MM-ALU slots
 * through ia64_slot_is_alu_add()/ia64_exec_alu_add().  insn-packed-wrapper.c
 * compiles the existing scalar implementation under *_scalar names, and this
 * file provides the public entry points with the packed compare subset layered
 * in front.
 */

bool ia64_slot_is_alu_add_scalar(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_add_scalar(CPUIA64State *env, uint64_t raw);

static unsigned ia64_packed_compare_width(uint64_t raw)
{
    uint8_t za = (raw >> 36) & 0x1;
    uint8_t zb = (raw >> 33) & 0x1;

    if (za == 0 && zb == 0) {
        return 1;
    }
    if (za == 0 && zb == 1) {
        return 2;
    }
    if (za == 1 && zb == 0) {
        return 4;
    }
    return 0;
}

static bool ia64_raw_is_packed_compare(uint64_t raw)
{
    uint8_t x2a;
    uint8_t x4;
    uint8_t x2b;

    if (ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;

    return x2a == 1 && x4 == 9 && x2b <= 1 &&
           ia64_packed_compare_width(raw) != 0;
}

static bool ia64_slot_is_packed_compare(IA64SlotType type, uint64_t raw)
{
    if (type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) {
        return false;
    }
    return ia64_raw_is_packed_compare(raw);
}

static int64_t ia64_packed_lane_i64(uint64_t value, unsigned width)
{
    unsigned bits = width * 8;
    uint64_t sign = UINT64_C(1) << (bits - 1);
    uint64_t mask = (width == 8) ? UINT64_MAX : ((UINT64_C(1) << bits) - 1);

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

static bool ia64_packed_compare_lane(uint64_t left, uint64_t right,
                                     unsigned width, bool greater_than)
{
    if (!greater_than) {
        return left == right;
    }

    return ia64_packed_lane_i64(left, width) >
           ia64_packed_lane_i64(right, width);
}

static bool ia64_exec_packed_compare(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    unsigned width;
    unsigned lane_bits;
    uint64_t lane_mask;
    uint64_t left;
    uint64_t right;
    uint64_t result = 0;
    bool greater_than;

    if (!env || !ia64_raw_is_packed_compare(raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    width = ia64_packed_compare_width(raw);
    lane_bits = width * 8;
    lane_mask = (UINT64_C(1) << lane_bits) - 1;
    greater_than = ((raw >> 27) & 0x3) == 1;
    left = ia64_read_gr(env, r2);
    right = ia64_read_gr(env, r3);

    for (unsigned shift = 0; shift < 64; shift += lane_bits) {
        uint64_t left_lane = (left >> shift) & lane_mask;
        uint64_t right_lane = (right >> shift) & lane_mask;

        if (ia64_packed_compare_lane(left_lane, right_lane, width,
                                     greater_than)) {
            result |= lane_mask << shift;
        }
    }

    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_slot_is_alu_add(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_packed_compare(type, raw) ||
           ia64_slot_is_alu_add_scalar(type, raw);
}

bool ia64_exec_alu_add(CPUIA64State *env, uint64_t raw)
{
    if (ia64_raw_is_packed_compare(raw)) {
        return ia64_exec_packed_compare(env, raw);
    }

    return ia64_exec_alu_add_scalar(env, raw);
}
