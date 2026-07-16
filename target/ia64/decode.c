/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Policy-free IA-64 instruction decoder.
 *
 * The opcode table and field decoder were derived from the GPL-2.0-or-later
 * implementation in:
 *   vibtanium/external-src/qemu-system-ia64-main/target/ia64/cpu.c
 *
 * This file intentionally has no TCG, CPU-state, firmware, trace, or fallback
 * dependencies.  It describes the instruction; consumers decide how to execute
 * it.
 */

#include "qemu/osdep.h"
#include "decode.h"

#define IA64_COVER_B_MASK  UINT64_C(0x1e1f8000000)
#define IA64_COVER_B_VALUE UINT64_C(0x10000000)

static bool ia64_cr_is_read_only(uint32_t cr);

typedef struct IA64A3AluPattern {
    uint8_t x4;
    uint8_t x2b;
    IA64Opcode opcode;
    bool immediate;
} IA64A3AluPattern;

static const IA64A3AluPattern ia64_a3_alu_patterns[] = {
    { 0x0, 0, IA64_OP_ADD, false },
    { 0x0, 1, IA64_OP_ADD_ONE, false },
    { 0x1, 0, IA64_OP_SUB_ONE, false },
    { 0x1, 1, IA64_OP_SUB, false },
    { 0x3, 0, IA64_OP_AND, false },
    { 0x3, 1, IA64_OP_ANDCM, false },
    { 0x3, 2, IA64_OP_OR, false },
    { 0x3, 3, IA64_OP_XOR, false },
    { 0x9, 1, IA64_OP_SUB_IMM, true },
    { 0xb, 0, IA64_OP_AND_IMM, true },
    { 0xb, 1, IA64_OP_ANDCM_IMM, true },
    { 0xb, 2, IA64_OP_OR_IMM, true },
    { 0xb, 3, IA64_OP_XOR_IMM, true },
};

static uint64_t ia64_bits(uint64_t value, unsigned low, unsigned width)
{
    return (value >> low) & ((1ULL << width) - 1);
}

static uint64_t ia64_b_op(uint64_t value)
{
    return ia64_bits(value, 37, 4);
}

static int64_t ia64_sign_extend(uint64_t value, unsigned width)
{
    const uint64_t sign = 1ULL << (width - 1);
    const uint64_t mask = (1ULL << width) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

static uint64_t ia64_immu21(uint64_t raw)
{
    return ia64_bits(raw, 6, 20) | (ia64_bits(raw, 36, 1) << 20);
}

static int64_t ia64_imm14(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 6) << 7) |
                            (ia64_bits(raw, 36, 1) << 13), 14);
}

static int64_t ia64_imm8(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 36, 1) << 7), 8);
}

static uint64_t ia64_pr_mask(uint64_t raw)
{
    uint64_t imm17 = (ia64_bits(raw, 6, 7) << 1) |
                     (ia64_bits(raw, 24, 8) << 8) |
                     (ia64_bits(raw, 36, 1) << 16);

    return ia64_sign_extend(imm17, 17) & ~1ULL;
}

static int64_t ia64_pr_rot_imm(uint64_t raw)
{
    uint64_t imm28 = ia64_bits(raw, 6, 7) |
                     (ia64_bits(raw, 13, 7) << 7) |
                     (ia64_bits(raw, 20, 4) << 14) |
                     (ia64_bits(raw, 24, 8) << 18) |
                     (ia64_bits(raw, 32, 1) << 26) |
                     (ia64_bits(raw, 36, 1) << 27);

    return ia64_sign_extend(imm28 << 16, 44);
}

static uint64_t ia64_psr_mask(uint64_t raw)
{
    return ia64_bits(raw, 6, 7) |
           (ia64_bits(raw, 13, 7) << 7) |
           (ia64_bits(raw, 20, 7) << 14) |
           (ia64_bits(raw, 31, 2) << 21) |
           (ia64_bits(raw, 36, 1) << 23);
}

static int64_t ia64_imm22(uint64_t raw)
{
    return ia64_sign_extend(ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 9) << 7) |
                            (ia64_bits(raw, 22, 5) << 16) |
                            (ia64_bits(raw, 36, 1) << 21), 22);
}

static int64_t ia64_branch_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static uint64_t ia64_mlx_x1_imm62(uint64_t l_slot, uint64_t x_slot)
{
    return ia64_immu21(x_slot) | (ia64_bits(l_slot, 0, 41) << 21);
}

static int64_t ia64_mlx_brl_disp(uint64_t l_slot, uint64_t x_slot)
{
    const uint64_t field = ia64_bits(x_slot, 13, 20) |
                           (ia64_bits(l_slot, 2, 39) << 20) |
                           (ia64_bits(x_slot, 36, 1) << 59);

    return ia64_sign_extend(field, 60) * 16;
}

static void ia64_fill_mlx_movl(IA64Instruction *insn,
                               uint64_t l_slot, uint64_t x_slot)
{
    uint64_t i     = (x_slot >> 36) & 1;
    uint64_t imm9d = (x_slot >> 27) & 0x1ff;
    uint64_t imm5c = (x_slot >> 22) & 0x1f;
    uint64_t ic    = (x_slot >> 21) & 1;
    uint64_t imm7b = (x_slot >> 13) & 0x7f;
    uint64_t imm41 = l_slot & 0x1ffffffffffULL;
    uint64_t imm64 = (imm7b)
                   | (imm9d << 7)
                   | (imm5c << 16)
                   | (ic << 21)
                   | (imm41 << 22)
                   | (i << 63);

    insn->qp = x_slot & 0x3f;
    insn->r1 = (x_slot >> 6) & 0x7f;
    insn->imm = (int64_t)imm64;
}

static int64_t ia64_chk_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 6, 7) |
                           (ia64_bits(raw, 20, 13) << 7) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static int64_t ia64_chk_a_disp(uint64_t raw)
{
    const uint64_t field = ia64_bits(raw, 13, 20) |
                           (ia64_bits(raw, 36, 1) << 20);

    return ia64_sign_extend(field, 21) * 16;
}

static IA64Opcode ia64_memory_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1;
    case 0x01:
        return IA64_OP_LD2;
    case 0x02:
        return IA64_OP_LD4;
    case 0x03:
        return IA64_OP_LD8;
    case 0x04:
        return IA64_OP_LD1S;
    case 0x05:
        return IA64_OP_LD2S;
    case 0x06:
        return IA64_OP_LD4S;
    case 0x07:
        return IA64_OP_LD8S;
    case 0x08:
        return IA64_OP_LD1A;
    case 0x09:
        return IA64_OP_LD2A;
    case 0x0a:
        return IA64_OP_LD4A;
    case 0x0b:
        return IA64_OP_LD8A;
    case 0x0c:
        return IA64_OP_LD1SA;
    case 0x0d:
        return IA64_OP_LD2SA;
    case 0x0e:
        return IA64_OP_LD4SA;
    case 0x0f:
        return IA64_OP_LD8SA;
    case 0x10:
        return IA64_OP_LD1;
    case 0x11:
        return IA64_OP_LD2;
    case 0x12:
        return IA64_OP_LD4;
    case 0x13:
        return IA64_OP_LD8;
    case 0x14:
        return IA64_OP_LD1;
    case 0x15:
        return IA64_OP_LD2;
    case 0x16:
        return IA64_OP_LD4;
    case 0x17:
        return IA64_OP_LD8;
    case 0x1b:
        return IA64_OP_LD8FILL;
    case 0x20:
        return IA64_OP_LD1C_CLR;
    case 0x21:
        return IA64_OP_LD2C_CLR;
    case 0x22:
        return IA64_OP_LD4C_CLR;
    case 0x23:
        return IA64_OP_LD8C_CLR;
    case 0x24:
        return IA64_OP_LD1C_NC;
    case 0x25:
        return IA64_OP_LD2C_NC;
    case 0x26:
        return IA64_OP_LD4C_NC;
    case 0x27:
        return IA64_OP_LD8C_NC;
    case 0x28:
        return IA64_OP_LD1C_CLR;
    case 0x29:
        return IA64_OP_LD2C_CLR;
    case 0x2a:
        return IA64_OP_LD4C_CLR;
    case 0x2b:
        return IA64_OP_LD8C_CLR;
    case 0x30:
        return IA64_OP_ST1;
    case 0x31:
        return IA64_OP_ST2;
    case 0x32:
        return IA64_OP_ST4;
    case 0x33:
        return IA64_OP_ST8;
    case 0x34:
        return IA64_OP_ST1REL;
    case 0x35:
        return IA64_OP_ST2REL;
    case 0x36:
        return IA64_OP_ST4REL;
    case 0x37:
        return IA64_OP_ST8REL;
    case 0x3b:
        return IA64_OP_ST8SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_memory_x6a_is_acquire_load(uint64_t x6a)
{
    return (x6a >= 0x14 && x6a <= 0x17) ||
           (x6a >= 0x28 && x6a <= 0x2b);
}

static IA64Opcode ia64_speculative_load_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x00:
        return IA64_OP_LD1S;
    case 0x01:
        return IA64_OP_LD2S;
    case 0x02:
        return IA64_OP_LD4S;
    case 0x03:
        return IA64_OP_LD8S;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static IA64Opcode ia64_fp_load_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f) || (x6a >= 0x20 && x6a <= 0x27)) {
        switch (x6a & 3) {
        case 0:
            return IA64_OP_LDFE;
        case 1:
            return IA64_OP_LDF8;
        case 2:
            return IA64_OP_LDFS;
        case 3:
            return IA64_OP_LDFD;
        }
    }

    switch (x6a) {
    case 0x1b:
        return IA64_OP_LDF_FILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static void ia64_fp_load_attrs_from_x6a(IA64Instruction *insn, uint64_t x6a)
{
    switch (x6a >> 2) {
    case 1:
        insn->fp_load_speculative = true;
        break;
    case 2:
        insn->fp_load_advanced = true;
        break;
    case 3:
        insn->fp_load_speculative = true;
        insn->fp_load_advanced = true;
        break;
    case 8:
        insn->fp_load_check = true;
        insn->fp_load_check_clear = true;
        break;
    case 9:
        insn->fp_load_check = true;
        break;
    default:
        break;
    }
}

static IA64Opcode ia64_fp_load_pair_opcode_from_x6a(uint64_t x6a)
{
    if ((x6a <= 0x0f || (x6a >= 0x20 && x6a <= 0x27)) &&
        (x6a & 3) != 0) {
        switch (x6a & 3) {
        case 1:
            return IA64_OP_LDFP8;
        case 2:
            return IA64_OP_LDFPS;
        case 3:
            return IA64_OP_LDFPD;
        }
    }

    return IA64_OP_ILLEGAL;
}

static IA64Opcode ia64_fp_store_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x30:
        return IA64_OP_STFE;
    case 0x31:
        return IA64_OP_STF8;
    case 0x32:
        return IA64_OP_STFS;
    case 0x33:
        return IA64_OP_STFD;
    case 0x3b:
        return IA64_OP_STF_SPILL;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static IA64Opcode ia64_check_load_opcode_from_x6a(uint64_t x6a, bool clr)
{
    switch (x6a) {
    case 0x00:
        return clr ? IA64_OP_LD1C_CLR : IA64_OP_LD1C_NC;
    case 0x01:
        return clr ? IA64_OP_LD2C_CLR : IA64_OP_LD2C_NC;
    case 0x02:
        return clr ? IA64_OP_LD4C_CLR : IA64_OP_LD4C_NC;
    case 0x03:
        return clr ? IA64_OP_LD8C_CLR : IA64_OP_LD8C_NC;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static IA64Opcode ia64_fetchadd_opcode_from_x6a(uint64_t x6a)
{
    switch (x6a) {
    case 0x12:
    case 0x16:
        return IA64_OP_FETCHADD4;
    case 0x13:
    case 0x17:
        return IA64_OP_FETCHADD8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static bool ia64_fetchadd_x6a_is_acquire(uint64_t x6a)
{
    return x6a == 0x12 || x6a == 0x13;
}

static bool ia64_fetchadd_x6a_is_release(uint64_t x6a)
{
    return x6a == 0x16 || x6a == 0x17;
}

static IA64Opcode ia64_cmpxchg_acqrel_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_CMPXCHG1;
    case 1:
        return IA64_OP_CMPXCHG2;
    case 2:
        return IA64_OP_CMPXCHG4;
    case 3:
        return IA64_OP_CMPXCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static IA64Opcode ia64_xchg_opcode_from_size(uint64_t size)
{
    switch (size) {
    case 0:
        return IA64_OP_XCHG1;
    case 1:
        return IA64_OP_XCHG2;
    case 2:
        return IA64_OP_XCHG4;
    case 3:
        return IA64_OP_XCHG8;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static IA64Opcode ia64_unpack_opcode_from_fields(uint64_t za, uint64_t zb,
                                                 uint64_t x2b)
{
    static const IA64Opcode high[4] = {
        IA64_OP_UNPACK1_H, IA64_OP_UNPACK2_H, IA64_OP_UNPACK4_H,
        IA64_OP_ILLEGAL,
    };
    static const IA64Opcode low[4] = {
        IA64_OP_UNPACK1_L, IA64_OP_UNPACK2_L, IA64_OP_UNPACK4_L,
        IA64_OP_ILLEGAL,
    };
    const unsigned size_code = (za << 1) | zb;

    if (x2b == 0) {
        return high[size_code];
    }
    if (x2b == 2) {
        return low[size_code];
    }
    return IA64_OP_ILLEGAL;
}

static int64_t ia64_fetchadd_imm(uint64_t inc3)
{
    static const int8_t values[8] = {
        16, 8, 4, 1, -16, -8, -4, -1,
    };

    return values[inc3 & 7];
}

static IA64Opcode ia64_f1_opcode_from_major(uint64_t major, uint64_t f2,
                                             uint64_t f4)
{
    switch (major) {
    case 8:
    case 9:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FADD;
        }
        return f2 == 0 ? IA64_OP_FMPY : IA64_OP_FMA;
    case 0xa:
    case 0xb:
        if (f4 == 1) {
            return f2 == 0 ? IA64_OP_FNORM : IA64_OP_FSUB;
        }
        return IA64_OP_FMS;
    case 0xc:
    case 0xd:
        return IA64_OP_FNMA;
    default:
        return IA64_OP_ILLEGAL;
    }
}

static const IA64A3AluPattern *ia64_lookup_a3_alu(uint64_t x4, uint64_t x2b)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ia64_a3_alu_patterns); ++i) {
        const IA64A3AluPattern *pattern = &ia64_a3_alu_patterns[i];
        if (pattern->x4 == x4 && pattern->x2b == x2b) {
            return pattern;
        }
    }
    return NULL;
}

static bool ia64_opcode_is_store(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST16:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
    case IA64_OP_ST8SPILL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_release_store(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
        return true;
    default:
        return false;
    }
}

static bool ia64_opcode_is_load(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1A:
    case IA64_OP_LD2A:
    case IA64_OP_LD4A:
    case IA64_OP_LD8A:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
    case IA64_OP_LD8FILL:
    case IA64_OP_LD1C_CLR:
    case IA64_OP_LD2C_CLR:
    case IA64_OP_LD4C_CLR:
    case IA64_OP_LD8C_CLR:
    case IA64_OP_LD1C_NC:
    case IA64_OP_LD2C_NC:
    case IA64_OP_LD4C_NC:
    case IA64_OP_LD8C_NC:
        return true;
    default:
        return false;
    }
}

static bool ia64_is_m_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31) |
                          (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_m_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0xfULL << 27) | (0x3ULL << 31);

    return (raw & mask) == 0;
}

static bool ia64_is_i_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27) | (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_i_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x7ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_b_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);
    const uint64_t value = 2ULL << 37;

    return (raw & mask) == value;
}

static bool ia64_is_b_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (0x3fULL << 27);

    return (raw & mask) == 0;
}

static bool ia64_is_f_nop(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27) | (1ULL << 26);
    const uint64_t value = 1ULL << 27;

    return (raw & mask) == value;
}

static bool ia64_is_f_hint(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27) | (1ULL << 26);
    const uint64_t value = (1ULL << 27) | (1ULL << 26);

    return (raw & mask) == value;
}

static bool ia64_is_f_break(uint64_t raw)
{
    const uint64_t mask = (0xfULL << 37) | (1ULL << 33) |
                          (0x3fULL << 27);

    return (raw & mask) == 0;
}

static IA64Instruction ia64_base_insn(IA64Opcode opcode, IA64InstructionUnit unit,
                                      uint64_t raw, uint64_t address,
                                      uint8_t slot)
{
    IA64Instruction insn = {
        .opcode = opcode,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
        .qp = ia64_bits(raw, 0, 6),
        .sf = unit == IA64_INSN_UNIT_F ? ia64_bits(raw, 34, 2) : 0,
        .valid = true,
    };

    return insn;
}

static IA64Instruction ia64_invalid_insn(IA64InstructionUnit unit, uint64_t raw,
                                         uint64_t address, uint8_t slot)
{
    IA64Instruction insn = {
        .opcode = IA64_OP_ILLEGAL,
        .unit = unit,
        .raw = raw,
        .address = address,
        .slot = slot,
        /*
         * Reserved encodings still carry the universal qualifying-predicate
         * field.  Keep it in the typed result so the architectural Illegal
         * Operation is suppressed when the instruction is predicated false;
         * decoder failure must not force an unqualified legacy fallback.
         */
        .qp = ia64_bits(raw, 0, 6),
    };

    return insn;
}

/* Intel SDM Vol. 3, formats A6, A7, and A8 (Tables 4-10 and 4-11). */
static IA64Instruction ia64_decode_integer_compare(IA64InstructionUnit unit,
                                                    uint64_t raw,
                                                    uint64_t address,
                                                    uint8_t slot)
{
    static const IA64Opcode normal_reg[2][3] = {
        { IA64_OP_CMP_LT, IA64_OP_CMP_LTU, IA64_OP_CMP_EQ },
        { IA64_OP_CMP4_LT, IA64_OP_CMP4_LTU, IA64_OP_CMP4_EQ },
    };
    static const IA64Opcode normal_imm[2][3] = {
        { IA64_OP_CMP_LT_IMM, IA64_OP_CMP_LTU_IMM,
          IA64_OP_CMP_EQ_IMM },
        { IA64_OP_CMP4_LT_IMM, IA64_OP_CMP4_LTU_IMM,
          IA64_OP_CMP4_EQ_IMM },
    };
    static const IA64Opcode update_reg[2][2][3] = {
        {
            { IA64_OP_CMP_EQ_AND, IA64_OP_CMP_EQ_OR,
              IA64_OP_CMP_EQ_OR_ANDCM },
            { IA64_OP_CMP_NE_AND, IA64_OP_CMP_NE_OR,
              IA64_OP_CMP_NE_OR_ANDCM },
        },
        {
            { IA64_OP_CMP4_EQ_AND, IA64_OP_CMP4_EQ_OR,
              IA64_OP_CMP4_EQ_OR_ANDCM },
            { IA64_OP_CMP4_NE_AND, IA64_OP_CMP4_NE_OR,
              IA64_OP_CMP4_NE_OR_ANDCM },
        },
    };
    static const IA64Opcode update_imm[2][2][3] = {
        {
            { IA64_OP_CMP_EQ_AND_IMM, IA64_OP_CMP_EQ_OR_IMM,
              IA64_OP_CMP_EQ_OR_ANDCM_IMM },
            { IA64_OP_CMP_NE_AND_IMM, IA64_OP_CMP_NE_OR_IMM,
              IA64_OP_CMP_NE_OR_ANDCM_IMM },
        },
        {
            { IA64_OP_CMP4_EQ_AND_IMM, IA64_OP_CMP4_EQ_OR_IMM,
              IA64_OP_CMP4_EQ_OR_ANDCM_IMM },
            { IA64_OP_CMP4_NE_AND_IMM, IA64_OP_CMP4_NE_OR_IMM,
              IA64_OP_CMP4_NE_OR_ANDCM_IMM },
        },
    };
    static const IA64Opcode update_zero[2][4][3] = {
        {
            { IA64_OP_CMP_GT_AND, IA64_OP_CMP_GT_OR,
              IA64_OP_CMP_GT_OR_ANDCM },
            { IA64_OP_CMP_LE_AND, IA64_OP_CMP_LE_OR,
              IA64_OP_CMP_LE_OR_ANDCM },
            { IA64_OP_CMP_GE_AND, IA64_OP_CMP_GE_OR,
              IA64_OP_CMP_GE_OR_ANDCM },
            { IA64_OP_CMP_LT_AND, IA64_OP_CMP_LT_OR,
              IA64_OP_CMP_LT_OR_ANDCM },
        },
        {
            { IA64_OP_CMP4_GT_AND, IA64_OP_CMP4_GT_OR,
              IA64_OP_CMP4_GT_OR_ANDCM },
            { IA64_OP_CMP4_LE_AND, IA64_OP_CMP4_LE_OR,
              IA64_OP_CMP4_LE_OR_ANDCM },
            { IA64_OP_CMP4_GE_AND, IA64_OP_CMP4_GE_OR,
              IA64_OP_CMP4_GE_OR_ANDCM },
            { IA64_OP_CMP4_LT_AND, IA64_OP_CMP4_LT_OR,
              IA64_OP_CMP4_LT_OR_ANDCM },
        },
    };
    static const IA64PredicateUpdate update_kind[3] = {
        IA64_PRED_UPDATE_AND,
        IA64_PRED_UPDATE_OR,
        IA64_PRED_UPDATE_OR_ANDCM,
    };
    const unsigned major = ia64_b_op(raw);
    const unsigned major_index = major - 0xc;
    const unsigned x2 = ia64_bits(raw, 34, 2);
    const unsigned width_index = x2 & 1;
    const bool ta = ia64_bits(raw, 33, 1);
    const bool c = ia64_bits(raw, 12, 1);
    const bool immediate = x2 >= 2;
    IA64Opcode opcode;
    IA64PredicateUpdate pred_update = IA64_PRED_UPDATE_NORMAL;
    bool compare_unc = false;

    g_assert(unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I);
    g_assert(major >= 0xc && major <= 0xe);

    if (!immediate && ia64_bits(raw, 36, 1)) {
        /* A7 reserves all seven bits of its zero r2 field. */
        if (ia64_bits(raw, 13, 7) != 0) {
            return ia64_invalid_insn(unit, raw, address, slot);
        }
        opcode = update_zero[width_index][(ta << 1) | c][major_index];
        pred_update = update_kind[major_index];
    } else if (ta) {
        opcode = immediate ? update_imm[width_index][c][major_index] :
                             update_reg[width_index][c][major_index];
        pred_update = update_kind[major_index];
    } else {
        opcode = immediate ? normal_imm[width_index][major_index] :
                             normal_reg[width_index][major_index];
        compare_unc = c;
    }

    IA64Instruction insn = ia64_base_insn(opcode, unit, raw, address, slot);

    insn.p1 = ia64_bits(raw, 6, 6);
    insn.p2 = ia64_bits(raw, 27, 6);
    insn.r3 = ia64_bits(raw, 20, 7);
    insn.compare_width = width_index ? 4 : 8;
    insn.compare_immediate = immediate;
    insn.compare_unc = compare_unc;
    insn.pred_update = pred_update;
    if (immediate) {
        insn.imm = ia64_imm8(raw);
    } else if (!ia64_bits(raw, 36, 1)) {
        insn.r2 = ia64_bits(raw, 13, 7);
    }
    return insn;
}

/*
 * MLX long forms are reported at slot 1.  The paired X slot carries the
 * opcode/predicate and low immediate bits, and must not execute separately.
 */
void ia64_decode_apply_mlx_fixup(uint8_t template_code,
                                      const uint64_t slots[3],
                                      int slot, IA64Instruction *insn,
                                      bool *skip_x_slot)
{
    if ((template_code != 4 && template_code != 5) || slot != 1) {
        return;
    }

    uint64_t x_slot = slots[2];
    uint64_t l_slot = slots[1];

    if (ia64_is_i_break(x_slot)) {
        *insn = ia64_base_insn(IA64_OP_BREAK, IA64_INSN_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xc &&
               ia64_bits(x_slot, 6, 3) == 0) {
        *insn = ia64_base_insn(IA64_OP_BRL_COND, IA64_INSN_UNIT_X,
                               x_slot, insn->address, slot);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0xd) {
        *insn = ia64_base_insn(IA64_OP_BRL_CALL, IA64_INSN_UNIT_X,
                               x_slot, insn->address, slot);
        insn->b1 = ia64_bits(x_slot, 6, 3);
        insn->imm = ia64_mlx_brl_disp(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (ia64_b_op(x_slot) == 0 &&
               ia64_bits(x_slot, 27, 6) == 1) {
        IA64Opcode opcode = ia64_bits(x_slot, 26, 1) ?
            IA64_OP_HINT_X : IA64_OP_NOP;
        *insn = ia64_base_insn(opcode, IA64_INSN_UNIT_X, x_slot,
                               insn->address, slot);
        insn->imm = ia64_mlx_x1_imm62(l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL && ia64_b_op(x_slot) == 6) {
        ia64_fill_mlx_movl(insn, l_slot, x_slot);
        *skip_x_slot = true;
    } else if (insn->opcode == IA64_OP_MOVL) {
        *insn = ia64_invalid_insn(IA64_INSN_UNIT_L, l_slot, insn->address, slot);
    }
}

IA64Instruction ia64_decode_instruction_raw(IA64InstructionUnit unit, uint64_t raw,
                                        uint64_t address, uint8_t slot)
{
    raw &= IA64_SLOT_MASK;

    if (unit == IA64_INSN_UNIT_RESERVED) {
        return ia64_invalid_insn(unit, raw, address, slot);
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) >= 0xc && ia64_b_op(raw) <= 0xe) {
        return ia64_decode_integer_compare(unit, raw, address, slot);
    }

    if (unit == IA64_INSN_UNIT_I &&
        ia64_b_op(raw) == 0 && ia64_bits(raw, 33, 3) == 7) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRBR, unit, raw, address, slot);

        /*
         * The btype/wh/ph/ih target-prediction fields are hints; the
         * architectural state update is still only BR[b1] = GR[r2].
         */
        insn.r2 = ia64_bits(raw, 6, 3);
        insn.r1 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M) {
        if (ia64_is_m_nop(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_m_break(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 6) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ALLOC, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.imm = (ia64_bits(raw, 13, 7) << 0) |
                       (ia64_bits(raw, 20, 7) << 7) |
                       (ia64_bits(raw, 27, 4) << 14);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x21) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_UMGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x29) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRUM, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x25) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2d) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPSR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.imm = 1;
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x24) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x2c) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRCR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 13, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRRR, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_RRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x1e) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_TPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x1a ||
             ia64_bits(raw, 27, 6) == 0x1b ||
             ia64_bits(raw, 27, 6) == 0x1f)) {
            IA64Opcode opcode;

            switch (ia64_bits(raw, 27, 6)) {
            case 0x1a:
                opcode = IA64_OP_THASH;
                break;
            case 0x1b:
                opcode = IA64_OP_TTAG;
                break;
            default:
                opcode = IA64_OP_TAK;
                break;
            }

            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x17) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_CPUID_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x20) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_DAHRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x16) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_MSRGR, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x06) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRMSR, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x11 ||
             ia64_bits(raw, 27, 6) == 0x12)) {
            IA64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x12 ?
                               IA64_OP_MOV_IBRGR_INDEXED :
                               IA64_OP_MOV_DBRGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x01 ||
             ia64_bits(raw, 27, 6) == 0x02)) {
            IA64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x02 ?
                               IA64_OP_MOV_GRIBR_INDEXED :
                               IA64_OP_MOV_GRDBR_INDEXED,
                               unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x03) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_GRPKR_INDEXED, unit, raw,
                               address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            ia64_bits(raw, 27, 6) == 0x13) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_MOV_PKRGR_INDEXED, unit, raw,
                               address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x04 ||
             ia64_bits(raw, 27, 6) == 0x05)) {
            IA64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x04 ?
                               IA64_OP_MOV_GRPMC_INDEXED :
                               IA64_OP_MOV_GRPMD_INDEXED,
                               unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 3) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x14 ||
             ia64_bits(raw, 27, 6) == 0x15)) {
            IA64Instruction insn =
                ia64_base_insn(ia64_bits(raw, 27, 6) == 0x14 ?
                               IA64_OP_MOV_PMCGR_INDEXED :
                               IA64_OP_MOV_PMDGR_INDEXED,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        if (ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            return ia64_base_insn(IA64_OP_HINT_M, unit, raw, address, slot);
        }
    }

    if (unit == IA64_INSN_UNIT_I || unit == IA64_INSN_UNIT_X) {
        if (unit == IA64_INSN_UNIT_I &&
            ia64_b_op(raw) == 0 &&
            ia64_bits(raw, 27, 6) == 0x01 &&
            ia64_bits(raw, 20, 7) == 64) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_nop(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_i_break(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 27, 2) == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_I, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (unit == IA64_INSN_UNIT_X && ia64_b_op(raw) == 1) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_X, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_B) {
        if (ia64_is_b_nop(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_b_break(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }

        if (ia64_b_op(raw) == 1 && ia64_bits(raw, 12, 1) == 0 &&
            ia64_bits(raw, 27, 2) == 0 && ia64_bits(raw, 32, 1) == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_B, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x2a = ia64_bits(raw, 34, 2);
        const uint64_t ve = ia64_bits(raw, 33, 1);

        if (x2a == 2 && ve == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ADDS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_imm14(raw);
            return insn;
        }

        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const unsigned size_code = ve | (ia64_bits(raw, 36, 1) << 1);
        if (x2a == 1 && (x4 == 0 || x4 == 1) &&
            ((size_code < 2 && x2b <= 3) ||
             (size_code == 2 && x2b == 0))) {
            IA64Opcode opcode = IA64_OP_ILLEGAL;
            if (x4 == 0) {
                if (size_code == 0) {
                    opcode = IA64_OP_PADD1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PADD2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PADD4;
                }
            } else {
                if (size_code == 0) {
                    opcode = IA64_OP_PSUB1;
                } else if (size_code == 1) {
                    opcode = IA64_OP_PSUB2;
                } else if (size_code == 2) {
                    opcode = IA64_OP_PSUB4;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                IA64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b;
                return insn;
            }
        }

        if (x2a == 1 && size_code == 1 && x4 == 4) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_PSHLADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 && size_code == 1 && x4 == 6 && x2b <= 2) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_PSHRADD2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = x2b + 1;
            return insn;
        }

        if (x2a == 1 &&
            (x4 == 2 || x4 == 3) &&
            (x2b == 2 || (x4 == 2 && x2b == 3)) &&
            ia64_bits(raw, 36, 1) == 0) {
            IA64Opcode opcode = IA64_OP_ILLEGAL;

            if (x4 == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVG1;
                } else {
                    opcode = IA64_OP_PAVG2;
                }
            } else if (x2b == 2) {
                if (ve == 0) {
                    opcode = IA64_OP_PAVGSUB1;
                } else {
                    opcode = IA64_OP_PAVGSUB2;
                }
            }
            if (opcode != IA64_OP_ILLEGAL) {
                IA64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.imm = x2b == 3;
                return insn;
            }
        }

        if ((x4 == 4 || x4 == 6) && x2a == 0 && ve == 0) {
            const uint64_t count = x2b;
            IA64Opcode shladd_op = (x4 == 6) ?
                IA64_OP_SHLADDP4 : IA64_OP_SHLADD;
            IA64Instruction insn =
                ia64_base_insn(shladd_op, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = count + 1;
            return insn;
        }

        if (x2a == 0 && ve == 0) {
            const IA64A3AluPattern *pattern = ia64_lookup_a3_alu(x4, x2b);

            if (pattern != NULL) {
                IA64Instruction insn =
                    ia64_base_insn(pattern->opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                if (pattern->immediate) {
                    insn.imm = ia64_imm8(raw);
                } else {
                    insn.r2 = ia64_bits(raw, 13, 7);
                }
                return insn;
            }
        }
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 9) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_ADDL, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 2);
        insn.imm = ia64_imm22(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 1 &&
        (ia64_bits(raw, 33, 3) == 1 || ia64_bits(raw, 33, 3) == 3)) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        insn.check_fp = ia64_bits(raw, 33, 3) == 3;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CHK_S, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_chk_disp(raw);
        return insn;
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 8 &&
        ia64_bits(raw, 29, 4) == 9 &&
        ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (x2b == 0 || x2b == 1) {
            if (za == 0 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP1_EQ : IA64_OP_PCMP1_GT;
            } else if (za == 0 && zb == 1) {
                opcode = x2b == 0 ? IA64_OP_PCMP2_EQ : IA64_OP_PCMP2_GT;
            } else if (za == 1 && zb == 0) {
                opcode = x2b == 0 ? IA64_OP_PCMP4_EQ : IA64_OP_PCMP4_GT;
            }
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0) {
            opcode = IA64_OP_SHRU;
        } else if ((x6 & ~1ULL) == 4) {
            opcode = IA64_OP_SHR;
        } else if ((x6 & ~1ULL) == 8) {
            opcode = IA64_OP_SHL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            if (opcode == IA64_OP_SHL) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if ((x6 & ~1ULL) == 0x1a) {
            opcode = IA64_OP_MPY4;
        } else if ((x6 & ~1ULL) == 0x1e) {
            opcode = IA64_OP_MPYSHL4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 0 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        (ia64_bits(raw, 27, 6) & ~1ULL) == 0x08) {
        IA64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = -1;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1 &&
        ia64_bits(raw, 28, 2) == 1 &&
        ((ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 33, 1) == 1) ||
         (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 33, 1) == 0)) &&
        ia64_bits(raw, 25, 2) == 0) {
        IA64Instruction insn =
            ia64_base_insn(ia64_bits(raw, 36, 1) ?
                           IA64_OP_PSHL4 : IA64_OP_PSHL2,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = 31 - ia64_bits(raw, 20, 5);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7) {
        const uint64_t pshr_sig = raw & 0x1fff0000000ULL;
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        bool fixed_count = false;

        switch (pshr_sig) {
        case 0xe220000000ULL:
            opcode = IA64_OP_PSHR2;
            break;
        case 0xe200000000ULL:
            opcode = IA64_OP_PSHR2_U;
            break;
        case 0xe630000000ULL:
            opcode = IA64_OP_PSHR2;
            fixed_count = true;
            break;
        case 0xe610000000ULL:
            opcode = IA64_OP_PSHR2_U;
            fixed_count = true;
            break;
        case 0xf020000000ULL:
            opcode = IA64_OP_PSHR4;
            break;
        case 0xf000000000ULL:
            opcode = IA64_OP_PSHR4_U;
            break;
        case 0xf430000000ULL:
            opcode = IA64_OP_PSHR4;
            fixed_count = true;
            break;
        case 0xf410000000ULL:
            opcode = IA64_OP_PSHR4_U;
            fixed_count = true;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (fixed_count) {
                insn.imm = ia64_bits(raw, 14, 5);
            } else {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = -1;
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 34, 2) == 3 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 28, 2) == 2) {
        bool two_byte_form = ia64_bits(raw, 33, 1) != 0;
        IA64Instruction insn =
            ia64_base_insn(two_byte_form ? IA64_OP_MUX2 : IA64_OP_MUX1,
                           unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = two_byte_form ? ia64_bits(raw, 20, 8) :
                                   ia64_bits(raw, 20, 4);
        if (!two_byte_form &&
            !(insn.imm == 0 || (insn.imm >= 8 && insn.imm <= 11))) {
            return ia64_invalid_insn(unit, raw, address, slot);
        }
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x12 &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_POPCNT, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 27, 6) == 0x1a &&
        ia64_bits(raw, 33, 3) == 3 &&
        ia64_bits(raw, 13, 7) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CLZ, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 5) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x1e) {
            opcode = IA64_OP_PMPY2_L;
        } else if (x6 == 0x1a) {
            opcode = IA64_OP_PMPY2_R;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        uint64_t shift = 0;

        switch (x6) {
        case 0x06:
            opcode = IA64_OP_PMPYSH2;
            shift = 0;
            break;
        case 0x0e:
            opcode = IA64_OP_PMPYSH2;
            shift = 7;
            break;
        case 0x16:
            opcode = IA64_OP_PMPYSH2;
            shift = 15;
            break;
        case 0x1e:
            opcode = IA64_OP_PMPYSH2;
            shift = 16;
            break;
        case 0x02:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 0;
            break;
        case 0x0a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 7;
            break;
        case 0x12:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 15;
            break;
        case 0x1a:
            opcode = IA64_OP_PMPYSH2_U;
            shift = 16;
            break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = shift;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ((ia64_bits(raw, 27, 6) & ~1ULL) == 0x10 ||
         (ia64_bits(raw, 27, 6) & ~1ULL) == 0x14)) {
        const uint64_t x6 = ia64_bits(raw, 27, 6) & ~1ULL;
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const bool right = x6 == 0x10;
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (x3 == 4 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX1_R : IA64_OP_MIX1_L;
        } else if (x3 == 5 && ia64_bits(raw, 36, 1) == 0) {
            opcode = right ? IA64_OP_MIX2_R : IA64_OP_MIX2_L;
        } else if (x3 == 4 && ia64_bits(raw, 36, 1) == 1) {
            opcode = right ? IA64_OP_MIX4_R : IA64_OP_MIX4_L;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 0) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (za == 0 && zb == 1 && x2b == 0) {
            opcode = IA64_OP_PACK2_USS;
        } else if (za == 0 && zb == 1 && x2b == 2) {
            opcode = IA64_OP_PACK2_SSS;
        } else if (za == 1 && zb == 0 && x2b == 2) {
            opcode = IA64_OP_PACK4_SSS;
        } else if (za == 0 && zb == 0 && x2b == 1) {
            opcode = IA64_OP_PMIN1_U;
        } else if (za == 0 && zb == 1 && x2b == 3) {
            opcode = IA64_OP_PMIN2;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        const uint64_t za = ia64_bits(raw, 36, 1);
        const uint64_t zb = ia64_bits(raw, 33, 1);
        const uint64_t x2b = ia64_bits(raw, 28, 2);

        if (za == 0 && zb == 0 && x2b == 1) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX1_U, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (za == 0 && zb == 1 && x2b == 3) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_PMAX2, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 2 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 3) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_PSAD1, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0x7 &&
        ia64_bits(raw, 34, 2) == 2 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 30, 2) == 1) {
        IA64Opcode opcode =
            ia64_unpack_opcode_from_fields(ia64_bits(raw, 36, 1),
                                           ia64_bits(raw, 33, 1),
                                           ia64_bits(raw, 28, 2));

        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 4) == 0) {
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x18: opcode = IA64_OP_CZX1_L; break;
        case 0x1c: opcode = IA64_OP_CZX1_R; break;
        case 0x19: opcode = IA64_OP_CZX2_L; break;
        case 0x1d: opcode = IA64_OP_CZX2_R; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 3) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_SHRP_IMM, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = ia64_bits(raw, 27, 6);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1 &&
        ia64_bits(raw, 20, 7) >= 64) {
        const uint64_t imm8 = ia64_bits(raw, 13, 7) |
                              (ia64_bits(raw, 36, 1) << 7);
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 127 - ia64_bits(raw, 20, 7);
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.imm = pos | (len << 6) | (imm8 << 13);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 1) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - ia64_bits(raw, 20, 7);
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_DEPZ, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = pos | (len << 6);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 4) {
        const uint64_t len = (ia64_bits(raw, 27, 4) + 1) & 0x3f;
        const uint64_t cpos = ia64_bits(raw, 31, 2) |
                              (ia64_bits(raw, 33, 1) << 2) |
                              (ia64_bits(raw, 34, 2) << 3) |
                              (ia64_bits(raw, 36, 1) << 5);
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_DEP, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = (63 - cpos) | (len << 6);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 33, 1) == 1 && ia64_bits(raw, 34, 2) == 3) {
        const uint64_t len = ia64_bits(raw, 27, 6) + 1;
        const uint64_t pos = 63 - (ia64_bits(raw, 13, 7) >> 1);
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_DEP_IMM, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.imm = pos | (len << 6) | (ia64_bits(raw, 36, 1) << 13);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 1) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);

        if (x3 == 2) {
            uint64_t pos_sign = ia64_bits(raw, 13, 7);
            IA64Instruction insn = ia64_base_insn(
                (pos_sign & 1) ? IA64_OP_EXTR : IA64_OP_EXTRU,
                unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = (pos_sign >> 1) |
                       ((ia64_bits(raw, 27, 6) + 1) << 6);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 1) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PR_ROT_IMM, unit, raw, address, slot);
        insn.imm = ia64_pr_rot_imm(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 0 && ia64_bits(raw, 27, 6) == 0x33 &&
        ia64_bits(raw, 13, 14) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_PRGR, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 6, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_I && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 3) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOV_GRPR, unit, raw, address, slot);

        insn.r1 = ia64_bits(raw, 13, 7);
        insn.imm = ia64_pr_mask(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 1) == 0 && ia64_bits(raw, 34, 2) == 0 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);

        if (x6 == 0x0a) {
            return ia64_base_insn(IA64_OP_LOADRS, unit, raw, address, slot);
        } else if (x6 == 0x0c) {
            return ia64_base_insn(IA64_OP_FLUSHRS, unit, raw, address, slot);
        } else if (x6 == 0x10) {
            return ia64_base_insn(IA64_OP_INVALA, unit, raw, address, slot);
        } else if (x6 == 0x12 || x6 == 0x13) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_INVALAT, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.check_fp = x6 == 0x13;
            return insn;
        }
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 0) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x31) {
            opcode = IA64_OP_MOV_BRGR;  /* mov r=b (BR to GR) */
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x30) {
            opcode = IA64_OP_MOV_CURRENT_IP;
        } else if (x3 == 0 && x6 == 0x32) {
            opcode = IA64_OP_MOV_ARGR;  /* mov r=ar (AR to GR) */
        } else if (x3 == 0 && x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov ar=r (GR to AR) */
        } else if (x3 == 0 && x6 == 0x0a) {
            opcode = IA64_OP_MOV_IMMAR; /* mov ar=imm */
        } else if (unit == IA64_INSN_UNIT_M && x3 == 0 && x6 == 0x28) {
            opcode = IA64_OP_MOV_IMMAR; /* mov.m ar=imm */
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x10) {
            opcode = IA64_OP_ZXT1;
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x11) {
            opcode = IA64_OP_ZXT2;
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x12) {
            opcode = IA64_OP_ZXT4;
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x14) {
            opcode = IA64_OP_SXT1;
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x15) {
            opcode = IA64_OP_SXT2;
        } else if (unit == IA64_INSN_UNIT_I && x3 == 0 && x6 == 0x16) {
            opcode = IA64_OP_SXT4;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SXT1 || opcode == IA64_OP_SXT2 ||
                opcode == IA64_OP_SXT4 || opcode == IA64_OP_ZXT1 ||
                opcode == IA64_OP_ZXT2 || opcode == IA64_OP_ZXT4) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_CURRENT_IP) {
                insn.r1 = ia64_bits(raw, 6, 7);
            } else if (opcode == IA64_OP_MOV_GRAR) {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else if (opcode == IA64_OP_MOV_IMMAR) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.imm = ia64_imm8(raw);
            } else if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                /*
                 * BR-to-GR: TCG emitter reads insn->r1 as GR destination
                 * and insn->r2 as BR source.
                 */
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 3);
            }
            return insn;
        }
    }

    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 1 && ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x22) {
            opcode = IA64_OP_MOV_ARGR;  /* mov.m r=ar */
        } else if (x6 == 0x2a) {
            opcode = IA64_OP_MOV_GRAR;  /* mov.m ar=r */
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);

            if (opcode == IA64_OP_MOV_ARGR) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            } else {
                insn.r1 = ia64_bits(raw, 13, 7);
                insn.r2 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_I &&
        ia64_b_op(raw) == 5 &&
        ia64_bits(raw, 34, 2) == 0) {
        const bool bit13 = ia64_bits(raw, 13, 1);
        const bool bit19 = ia64_bits(raw, 19, 1);
        const bool bit33 = ia64_bits(raw, 33, 1);
        const bool bit36 = ia64_bits(raw, 36, 1);
        const bool nz_form = ia64_bits(raw, 12, 1);
        const bool is_tf = bit13 && bit19 &&
                           ia64_bits(raw, 20, 7) == 0;
        const bool is_tnat = bit13 && !bit19 &&
                             ia64_bits(raw, 14, 5) == 0;
        const bool is_tbit = !bit13;

        if (is_tbit || is_tnat || is_tf) {
            IA64Instruction insn =
                ia64_base_insn(is_tf ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TF_NZ : IA64_OP_TF_Z) :
                               is_tnat ?
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TNAT_NZ : IA64_OP_TNAT_Z) :
                               (nz_form && (bit33 || bit36) ?
                                IA64_OP_TBIT_NZ : IA64_OP_TBIT_Z),
                               unit, raw, address, slot);

            insn.p1 = ia64_bits(raw, 6, 6);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (is_tbit) {
                insn.imm = ia64_bits(raw, 14, 6);
            } else if (is_tf) {
                insn.imm = 32 + ia64_bits(raw, 14, 5);
            }
            if (!bit33 && !bit36) {
                insn.compare_unc = nz_form;
            } else if (!bit33 && bit36) {
                insn.pred_update = IA64_PRED_UPDATE_AND;
            } else if (bit33 && !bit36) {
                insn.pred_update = IA64_PRED_UPDATE_OR;
            } else {
                insn.pred_update = IA64_PRED_UPDATE_OR_ANDCM;
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_B &&
        (raw & IA64_COVER_B_MASK) == IA64_COVER_B_VALUE) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_COVER, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && (raw & ~0x3fULL) == 0x20000000ULL) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && (raw & ~0x3fULL) == 0x28000000ULL) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CLRRRB_PR, unit, raw, address, slot);
        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 1) == 0 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
        if ((x6a >= 0x18 && x6a <= 0x1a) ||
            (x6a >= 0x38 && x6a <= 0x3a)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ILLEGAL, unit, raw, address, slot);

            insn.reserved_memory_width = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x28 ||
         ia64_bits(raw, 30, 6) == 0x2c)) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_LD16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 30, 6) == 0x2c;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 6 &&
        (ia64_bits(raw, 27, 6) & ~0x26ULL) == 0x01) {
        uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_ST16, unit, raw, address, slot);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_release = (x6 & 0x20) != 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 5) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            /* Cache hint bits do not affect the architectural load result. */
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
        if (ia64_opcode_is_store(opcode)) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
        if ((x6a >= 0x18 && x6a <= 0x1a) ||
            (x6a >= 0x38 && x6a <= 0x3a)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ILLEGAL, unit, raw, address, slot);

            insn.reserved_memory_width = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        (ia64_bits(raw, 30, 6) == 0x20 ||
         ia64_bits(raw, 30, 6) == 0x24)) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_CMP8XCHG16, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const IA64Opcode opcode = ia64_cmpxchg_acqrel_opcode_from_size(size);
        IA64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = ia64_bits(raw, 32, 1) == 0;
        insn.mem_release = ia64_bits(raw, 32, 1) != 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1 &&
        ia64_bits(raw, 32, 1) == 0 &&
        ia64_bits(raw, 33, 3) == 1) {
        const uint64_t size = ia64_bits(raw, 30, 1) |
                              (ia64_bits(raw, 31, 1) << 1);
        const IA64Opcode opcode = ia64_xchg_opcode_from_size(size);
        IA64Instruction insn =
            ia64_base_insn(opcode, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.r3 = ia64_bits(raw, 20, 7);
        insn.mem_acquire = true;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 2) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode =
            ia64_speculative_load_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            insn.mem_release = ia64_opcode_is_release_store(opcode);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 27, 2) == 3) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const bool is_nc = ia64_bits(raw, 29, 1);
        const IA64Opcode opcode =
            ia64_check_load_opcode_from_x6a(x6a, !is_nc);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode = ia64_memory_opcode_from_x6a(x6a);
        if (ia64_opcode_is_load(opcode)) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.reg_base_update = true;
            insn.mem_acquire = ia64_memory_x6a_is_acquire_load(x6a);
            return insn;
        }
        if (x6a >= 0x18 && x6a <= 0x1a) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ILLEGAL, unit, raw, address, slot);

            insn.reserved_memory_width = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 36, 1) == 0 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        const IA64Opcode opcode = ia64_fetchadd_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_fetchadd_imm(ia64_bits(raw, 13, 3));
            insn.mem_acquire = ia64_fetchadd_x6a_is_acquire(x6a);
            insn.mem_release = ia64_fetchadd_x6a_is_release(x6a);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 2 &&
        ia64_bits(raw, 36, 1) == 0 && ia64_bits(raw, 12, 1) == 0) {
        const uint64_t xhint = ia64_bits(raw, 27, 2);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && xhint == 0) {
            opcode = IA64_OP_XCHG1;
        } else if (xm == 0 && xhint == 1) {
            opcode = IA64_OP_XCHG2;
        } else if (xm == 1 && xhint == 0) {
            opcode = IA64_OP_XCHG4;
        } else if (xm == 1 && xhint == 1) {
            opcode = IA64_OP_XCHG8;
        } else if (xm == 2 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG1;
        } else if (xm == 2 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG2;
        } else if (xm == 3 && xhint == 0) {
            opcode = IA64_OP_CMPXCHG4;
        } else if (xm == 3 && xhint == 1) {
            opcode = IA64_OP_CMPXCHG8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 3 &&
        ia64_bits(raw, 36, 1) == 0) {
        const uint64_t x2 = ia64_bits(raw, 27, 1);
        const uint64_t xm = ia64_bits(raw, 29, 2);
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        if (xm == 0 && x2 == 0) {
            opcode = IA64_OP_FETCHADD4;
        } else if (xm == 1 && x2 == 0) {
            opcode = IA64_OP_FETCHADD8;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.mem_acquire = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_F) {
        if (ia64_is_f_nop(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_f_hint(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_HINT_F, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_is_f_break(raw)) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_BREAK, unit, raw, address, slot);
            insn.imm = ia64_immu21(raw);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x10 &&
            ia64_bits(raw, 13, 7) == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_FPABS, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0 &&
            ia64_bits(raw, 27, 6) == 0x11) {
            const uint64_t f2 = ia64_bits(raw, 13, 7);
            const uint64_t f3 = ia64_bits(raw, 20, 7);

            if (f2 == 0 || f2 == f3) {
                IA64Instruction insn =
                    ia64_base_insn(f2 == 0 ? IA64_OP_FPNEGABS :
                                             IA64_OP_FPNEG,
                                   unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = f3;
                return insn;
            }
        }
        if ((ia64_b_op(raw) == 0 || ia64_b_op(raw) == 1) &&
            ia64_bits(raw, 36, 1) == 1 &&
            ia64_bits(raw, 33, 1) == 1) {
            IA64Instruction insn =
                ia64_base_insn(ia64_b_op(raw) == 0 ? IA64_OP_FRSQRTA :
                                                     IA64_OP_FPRSQRTA,
                               unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.sf = ia64_bits(raw, 34, 2);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 36, 1) == 0 &&
            ia64_bits(raw, 33, 1) == 1) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_FPRCPA, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.p2 = ia64_bits(raw, 27, 6);
            insn.sf = ia64_bits(raw, 34, 2);
            insn.clear_p2_before_predicate = true;
            return insn;
        }
        if (ia64_b_op(raw) == 1 && ia64_bits(raw, 33, 1) == 0 &&
            (ia64_bits(raw, 27, 6) == 0x10 ||
             ia64_bits(raw, 27, 6) == 0x11 ||
             ia64_bits(raw, 27, 6) == 0x12)) {
            uint64_t form = ia64_bits(raw, 27, 6);
            IA64Instruction insn = ia64_base_insn(
                form == 0x10 ? IA64_OP_FPMERGE_S :
                form == 0x11 ? IA64_OP_FPMERGE : IA64_OP_FPMERGE_SE,
                unit, raw, address, slot);

            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
        if (ia64_b_op(raw) == 1 &&
            ia64_bits(raw, 33, 1) == 0) {
            uint64_t form = ia64_bits(raw, 27, 6);
            IA64Opcode opcode = IA64_OP_ILLEGAL;

            if (form >= 0x14 && form <= 0x17) {
                opcode = form == 0x14 ? IA64_OP_FPMIN :
                         form == 0x15 ? IA64_OP_FPMAX :
                         form == 0x16 ? IA64_OP_FPAMIN :
                                         IA64_OP_FPAMAX;
            } else if (form >= 0x18 && form <= 0x1b) {
                opcode = IA64_OP_FPCVT;
            } else if (form >= 0x30 && form <= 0x37) {
                opcode = IA64_OP_FPCMP;
            }

            if (opcode != IA64_OP_ILLEGAL) {
                IA64Instruction insn =
                    ia64_base_insn(opcode, unit, raw, address, slot);
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.sf = ia64_bits(raw, 34, 2);
                insn.imm = form & 7;
                return insn;
            }
        }
        const uint64_t x = ia64_bits(raw, 36, 1);
        const uint64_t x6 = ia64_bits(raw, 30, 6);
        const uint64_t form = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (ia64_b_op(raw) == 4) {
            opcode = IA64_OP_FCMP;
        } else if (ia64_b_op(raw) == 8 && x == 1 &&
                   (x6 == 0x00 || x6 == 0x02 || x6 == 0x04 ||
                    x6 == 0x08 || x6 == 0x0a || x6 == 0x0c ||
                    x6 == 0x0e)) {
            if (x6 == 0x00) {
                opcode = IA64_OP_FMA;
            } else if (x6 == 0x02) {
                opcode = IA64_OP_FMPY;
            } else if (x6 == 0x04) {
                opcode = IA64_OP_FCMP;
            } else if (x6 == 0x08) {
                opcode = IA64_OP_FMIN;
            } else if (x6 == 0x0a) {
                opcode = IA64_OP_FMAX;
            } else if (x6 == 0x0c) {
                opcode = IA64_OP_FAMIN;
            } else if (x6 == 0x0e) {
                opcode = IA64_OP_FAMAX;
            }
        } else if (x == 0 && ia64_b_op(raw) >= 8 &&
                   ia64_b_op(raw) <= 0xd) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x8 ||
                    ia64_b_op(raw) == 0xa ||
                    ia64_b_op(raw) == 0xc)) {
            opcode = ia64_f1_opcode_from_major(ia64_b_op(raw),
                                               ia64_bits(raw, 13, 7),
                                               ia64_bits(raw, 27, 7));
        } else if (x == 1 &&
                   (ia64_b_op(raw) == 0x9 ||
                    ia64_b_op(raw) == 0xb ||
                    ia64_b_op(raw) == 0xd)) {
            opcode = ia64_b_op(raw) == 0x9 ? IA64_OP_FPMA :
                     ia64_b_op(raw) == 0xb ? IA64_OP_FPMS :
                                             IA64_OP_FPNMA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x14 && form <= 0x17) {
            opcode = form == 0x14 ? IA64_OP_FMIN :
                     form == 0x15 ? IA64_OP_FMAX :
                     form == 0x16 ? IA64_OP_FAMIN :
                                    IA64_OP_FAMAX;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 && form == 0x1c) {
            opcode = IA64_OP_FCVT_XF;
        } else if (ia64_b_op(raw) == 0 && x == 0 &&
                   ia64_bits(raw, 33, 1) == 1) {
            opcode = IA64_OP_FRCPA;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ia64_bits(raw, 27, 6) == 0x28) {
            opcode = IA64_OP_FPACK;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   form >= 0x18 && form <= 0x1b) {
            opcode = (form & 1) ? IA64_OP_FCVT_FXU : IA64_OP_FCVT_FX;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   (ia64_bits(raw, 27, 6) == 0x10 ||
                    ia64_bits(raw, 27, 6) == 0x11 ||
                    ia64_bits(raw, 27, 6) == 0x12)) {
            opcode = form == 0x10 ? IA64_OP_FMERGE_S :
                     form == 0x11 ? IA64_OP_FMERGE :
                                      IA64_OP_FMERGE_SE;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   (ia64_bits(raw, 27, 6) == 0x04 ||
                    ia64_bits(raw, 27, 6) == 0x05 ||
                    ia64_bits(raw, 27, 6) == 0x08)) {
            opcode = form == 0x04 ? IA64_OP_FSETC :
                     form == 0x05 ? IA64_OP_FCLRF :
                                     IA64_OP_FCHKF;
        } else if (ia64_b_op(raw) == 0 &&
                   ia64_bits(raw, 33, 1) == 0 &&
                   ((form >= 0x2c && form <= 0x2f) ||
                    (form >= 0x34 && form <= 0x36) ||
                    (form >= 0x39 && form <= 0x3d))) {
            switch (ia64_bits(raw, 27, 6)) {
            case 0x2c:
                opcode = IA64_OP_FAND;
                break;
            case 0x2d:
                opcode = IA64_OP_FANDCM;
                break;
            case 0x2e:
                opcode = IA64_OP_FOR;
                break;
            case 0x2f:
                opcode = IA64_OP_FXOR;
                break;
            case 0x34:
                opcode = IA64_OP_FSWAP;
                break;
            case 0x35:
                opcode = IA64_OP_FSWAP_NL;
                break;
            case 0x36:
                opcode = IA64_OP_FSWAP_NR;
                break;
            case 0x39:
                opcode = IA64_OP_FMIX_LR;
                break;
            case 0x3a:
                opcode = IA64_OP_FMIX_R;
                break;
            case 0x3b:
                opcode = IA64_OP_FMIX_L;
                break;
            case 0x3c:
                opcode = IA64_OP_FSXT_R;
                break;
            case 0x3d:
                opcode = IA64_OP_FSXT_L;
                break;
            }
        } else if (ia64_b_op(raw) == 0xe && x == 0) {
            opcode = IA64_OP_FSELECT;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 0) {
            opcode = IA64_OP_XMA_L;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 3) {
            opcode = IA64_OP_XMA_H;
        } else if (ia64_b_op(raw) == 0xe && x == 1 &&
                   ia64_bits(raw, 34, 2) == 2) {
            opcode = ia64_bits(raw, 13, 7) == 0 ?
                IA64_OP_XMPY_HU : IA64_OP_XMA_HU;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.sf = ia64_bits(raw, 34, 2);
            if (opcode == IA64_OP_FCMP) {
                insn.p1 = ia64_bits(raw, 6, 6);
                insn.p2 = ia64_bits(raw, 27, 6);
                insn.imm = (ia64_bits(raw, 33, 1) << 1) |
                           ia64_bits(raw, 36, 1);
                insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
            } else if (opcode == IA64_OP_FSETC) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.sf = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCLRF) {
                insn.sf = ia64_bits(raw, 34, 2);
            } else if (opcode == IA64_OP_FCHKF) {
                insn.sf = ia64_bits(raw, 34, 2);
                uint64_t imm20b = ia64_bits(raw, 6, 20);
                uint64_t sign = ia64_bits(raw, 36, 1);
                insn.imm = ia64_sign_extend((sign << 20) | imm20b, 21) * 16;
            }
            if (opcode == IA64_OP_FMA ||
                opcode == IA64_OP_FMS ||
                opcode == IA64_OP_FNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.r4 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FPMA ||
                       opcode == IA64_OP_FPMS ||
                       opcode == IA64_OP_FPNMA) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.r3 = ia64_bits(raw, 20, 7);
                insn.r4 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSELECT) {
                insn.r4 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_XMA_L ||
                       opcode == IA64_OP_XMA_H ||
                       opcode == IA64_OP_XMA_HU ||
                       opcode == IA64_OP_XMPY_HU) {
                insn.r4 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FMPY) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 27, 7);
            } else if (opcode == IA64_OP_FSUB) {
                insn.r2 = ia64_bits(raw, 20, 7);
                insn.r3 = ia64_bits(raw, 13, 7);
            } else if (opcode == IA64_OP_FCVT_FX ||
                       opcode == IA64_OP_FCVT_FXU) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.imm = form & 3;
            } else if (opcode == IA64_OP_FRCPA) {
                insn.p2 = ia64_bits(raw, 27, 6);
                insn.clear_p2_before_predicate = true;
            }
            if (ia64_b_op(raw) >= 8 && ia64_b_op(raw) <= 0xd) {
                insn.fp_precision = (ia64_b_op(raw) & 1) ? 2 :
                                    ia64_bits(raw, 36, 1) ? 1 : 0;
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        IA64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);
        bool is_store = opcode == IA64_OP_ILLEGAL;

        if (is_store) {
            opcode = ia64_fp_store_opcode_from_x6a(x6a);
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            if (is_store) {
                insn.r2 = ia64_bits(raw, 13, 7);
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                if (ia64_bits(raw, 36, 1) == 1) {
                    insn.r2 = ia64_bits(raw, 13, 7);
                    insn.reg_base_update = true;
                }
            }
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 6) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            IA64Instruction insn =
                ia64_base_insn(x6a >= 0x2e ? IA64_OP_LFETCH_FAULT :
                                              IA64_OP_LFETCH,
                               unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1 && ia64_bits(raw, 27, 1) == 0) {
                insn.r2 = ia64_bits(raw, 13, 7);
                insn.reg_base_update = true;
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        if (x6a >= 0x2c && x6a <= 0x2f) {
            uint64_t imm9 = (ia64_bits(raw, 36, 1) << 8) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            ia64_bits(raw, 13, 7);
            IA64Instruction insn =
                ia64_base_insn(x6a >= 0x2e ? IA64_OP_LFETCH_FAULT :
                                              IA64_OP_LFETCH,
                               unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        IA64Opcode opcode = ia64_fp_load_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 13, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 7) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        IA64Opcode opcode = ia64_fp_store_opcode_from_x6a(x6a);

        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 6 &&
        ia64_bits(raw, 27, 1) == 1) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        IA64Opcode opcode = ia64_fp_load_pair_opcode_from_x6a(x6a);
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            ia64_fp_load_attrs_from_x6a(&insn, x6a);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (ia64_bits(raw, 36, 1) == 1) {
                insn.imm = opcode == IA64_OP_LDFPS ? 8 : 16;
                insn.imm_base_update = true;
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 7 &&
        ia64_bits(raw, 28, 2) == 0) {
        const uint64_t x6a = ia64_bits(raw, 30, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6a == 0x02) {
            opcode = IA64_OP_STFD;
        } else if (x6a == 0x03) {
            opcode = IA64_OP_STFS;
        } else if (x6a == 0x3b) {
            opcode = IA64_OP_STF_SPILL;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            uint64_t imm9 = ia64_bits(raw, 6, 7) |
                            (ia64_bits(raw, 27, 1) << 7) |
                            (ia64_bits(raw, 36, 1) << 8);
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            insn.imm = ia64_sign_extend(imm9, 9);
            insn.imm_base_update = true;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x4 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_GETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe1 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_SIG, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xe9 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_EXP, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf1 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_S, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M &&
        ia64_b_op(raw) == 0x6 &&
        (ia64_bits(raw, 27, 9) & ~0x06ULL) == 0xf9 &&
        ia64_bits(raw, 36, 1) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_SETF_D, unit, raw, address, slot);
        insn.r1 = ia64_bits(raw, 6, 7);
        insn.r2 = ia64_bits(raw, 13, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) >= 4) {
        const uint64_t x3 = ia64_bits(raw, 33, 3);
        IA64Instruction insn =
            ia64_base_insn((x3 == 4 || x3 == 6) ?
                           IA64_OP_CHK_A : IA64_OP_CHK_A_CLR,
                           unit, raw, address, slot);

        insn.r2 = ia64_bits(raw, 6, 7);
        insn.imm = ia64_chk_a_disp(raw);
        insn.check_fp = x3 >= 6;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        if (x6 == 0x18) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x19) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x31) {
            opcode = IA64_OP_PROBE_RW;
        } else if (x6 == 0x32) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_PROBE_W;
        } else if (x6 == 0x38) {
            opcode = IA64_OP_PROBE_R;
        } else if (x6 == 0x39) {
            opcode = IA64_OP_PROBE_W;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.r3 = ia64_bits(raw, 20, 7);
            if (x6 == 0x18 || x6 == 0x19) {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_imm = true;
            } else if (x6 == 0x31 || x6 == 0x32 || x6 == 0x33) {
                insn.imm = ia64_bits(raw, 13, 2);
                insn.probe_fault = true;
                insn.probe_imm = true;
            } else {
                insn.r1 = ia64_bits(raw, 6, 7);
                insn.r2 = ia64_bits(raw, 13, 7);
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0 &&
        ia64_bits(raw, 27, 6) == 0x30) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_FC, unit, raw, address, slot);
        insn.r3 = ia64_bits(raw, 20, 7);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 2) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 3) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_WTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 6 && ia64_bits(raw, 0, 6) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CEXIT, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 7 && ia64_bits(raw, 0, 6) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CTOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B &&
        ((ia64_b_op(raw) == 2 &&
          (ia64_bits(raw, 27, 6) == 0x10 ||
           ia64_bits(raw, 27, 6) == 0x11)) ||
         ia64_b_op(raw) == 7)) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BRP, unit, raw, address, slot);

        insn.qp = 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_F && ia64_b_op(raw) == 5) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_FCLASS, unit, raw, address, slot);
        insn.p1 = ia64_bits(raw, 6, 6);
        insn.p2 = ia64_bits(raw, 27, 6);
        insn.r2 = ia64_bits(raw, 13, 7);
        insn.imm = (ia64_bits(raw, 20, 7) << 2) |
                   ia64_bits(raw, 33, 2);
        insn.compare_unc = ia64_bits(raw, 12, 1) != 0;
        return insn;
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        const uint64_t x4 = x6 & 0xf;
        IA64Opcode opcode = IA64_OP_ILLEGAL;
        if (x6 == 0x31) {
            opcode = IA64_OP_SRLZ;
        } else if (x6 == 0x30) {
            opcode = IA64_OP_SRLZ_D;
        } else if (x6 == 0x33) {
            opcode = IA64_OP_SYNC_I;
        } else if (x6 == 0x20) {
            opcode = IA64_OP_FWB;
        } else if (x4 == 0x04) {
            opcode = IA64_OP_SUM_UM;
        } else if (x4 == 0x05) {
            opcode = IA64_OP_RUM;
        } else if (x4 == 0x06) {
            opcode = IA64_OP_SSM;
        } else if (x4 == 0x07) {
            opcode = IA64_OP_RSM;
        } else if (x6 == 0x22) {
            opcode = IA64_OP_MF;
        } else if (x6 == 0x23) {
            opcode = IA64_OP_MF_A;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            if (opcode == IA64_OP_SUM_UM || opcode == IA64_OP_RUM ||
                opcode == IA64_OP_SSM || opcode == IA64_OP_RSM) {
                insn.imm = ia64_psr_mask(raw);
            }
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_L) {
        /*
         * movl r1 = imm64 (X2 format, MLX template).
         * In MLX, the L-slot carries imm41 (bits 62:22), and the X-slot
         * carries opcode(6), r1 and the remaining immediate fields.
         * r1/imm are completed during the MLX fixup pass.
         */
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_INSN_UNIT_X && ia64_b_op(raw) == 6) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_MOVL, unit, raw, address, slot);
        insn.r1 = 0;   /* filled by MLX fixup */
        insn.imm = 0;  /* filled by MLX fixup */
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_COND, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 4 &&
        ia64_bits(raw, 6, 3) == 5 && ia64_bits(raw, 0, 6) == 0) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CLOOP, unit, raw, address, slot);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x20) {
        const uint64_t btype = ia64_bits(raw, 6, 3);

        if (btype == 0 || (btype == 1 && ia64_bits(raw, 0, 6) == 0)) {
            IA64Instruction insn =
                ia64_base_insn(btype == 0 ? IA64_OP_BR_INDIRECT :
                               IA64_OP_BR_IA,
                               unit, raw, address, slot);
            insn.b2 = ia64_bits(raw, 13, 3);
            return insn;
        }
    }

    /* Indirect call: br.call bRet=bTarget, B5. Completers are hints. */
    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 32, 1) == 1) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL_INDIRECT, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);  /* target branch register */
        insn.b1 = ia64_bits(raw, 6, 3);   /* return branch register */
        return insn;
    }

    /* B5 even-wh table entries are white ignored instructions, not faults. */
    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 1) {
        return ia64_base_insn(IA64_OP_NOP, unit, raw, address, slot);
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 5) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_CALL, unit, raw, address, slot);
        insn.b1 = ia64_bits(raw, 6, 3);
        insn.imm = ia64_branch_disp(raw);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 0 &&
        ia64_bits(raw, 27, 6) == 0x21 && ia64_bits(raw, 6, 3) == 4) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_BR_RET, unit, raw, address, slot);
        insn.b2 = ia64_bits(raw, 13, 3);
        return insn;
    }

    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 0) {
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        switch (ia64_bits(raw, 27, 6)) {
        case 0x02: opcode = IA64_OP_COVER; break;
        case 0x04: opcode = IA64_OP_CLRRRB; break;
        case 0x05: opcode = IA64_OP_CLRRRB_PR; break;
        case 0x08: opcode = IA64_OP_RFI; break;
        case 0x0c: opcode = IA64_OP_BSW0; break;
        case 0x0d: opcode = IA64_OP_BSW1; break;
        case 0x10: opcode = IA64_OP_EPC; break;
        }

        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);
            insn.qp = 0;
            return insn;
        }
    }

    if (unit == IA64_INSN_UNIT_M && ia64_b_op(raw) == 1 &&
        ia64_bits(raw, 33, 3) == 0) {
        const uint64_t x6 = ia64_bits(raw, 27, 6);
        IA64Opcode opcode = IA64_OP_ILLEGAL;

        switch (x6) {
        case 0x09: opcode = IA64_OP_PTC_L; break;
        case 0x0a: opcode = IA64_OP_PTC_G; break;
        case 0x0b: opcode = IA64_OP_PTC_GA; break;
        case 0x0c: opcode = IA64_OP_PTR_D; break;
        case 0x0d: opcode = IA64_OP_PTR_I; break;
        case 0x0e: opcode = IA64_OP_ITR_D; break;
        case 0x0f: opcode = IA64_OP_ITR_I; break;
        case 0x2e: opcode = IA64_OP_ITC_D; break;
        case 0x2f: opcode = IA64_OP_ITC_I; break;
        case 0x34: opcode = IA64_OP_PTC_E; break;
        }
        if (opcode != IA64_OP_ILLEGAL) {
            IA64Instruction insn =
                ia64_base_insn(opcode, unit, raw, address, slot);

            if (opcode != IA64_OP_PTC_E) {
                insn.r2 = ia64_bits(raw, 13, 7);
            }
            if (opcode != IA64_OP_ITC_D && opcode != IA64_OP_ITC_I) {
                insn.r3 = ia64_bits(raw, 20, 7);
            }
            return insn;
        }
    }

    /* VMSW.0 / VMSW.1: B-unit, opcode 0, x6 0x18/0x19. */
    if (unit == IA64_INSN_UNIT_B && ia64_b_op(raw) == 0 &&
        (ia64_bits(raw, 27, 6) == 0x18 ||
         ia64_bits(raw, 27, 6) == 0x19)) {
        IA64Instruction insn =
            ia64_base_insn(IA64_OP_VMSW, unit, raw, address, slot);
        insn.imm = ia64_bits(raw, 27, 6) & 1;
        insn.qp = 0;
        return insn;
    }

    /* H. ADDP4 / ADDS-imm: M/I-unit, b_op == 8
     *
     * Register form (addp4 r1=r2,r3): x3=0, x4=2, x2b=0.
     * Immediate form (addp4/adds r1=imm,r3): bits 34:33 may carry
     * immediate value bits (up to 3), so we accept any x3 for the
     * I-unit path and decode it as an ADDP4/adds immediate.
     */
    if ((unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) &&
        ia64_b_op(raw) == 8) {
        const uint64_t x4 = ia64_bits(raw, 29, 4);
        const uint64_t x2b = ia64_bits(raw, 27, 2);
        const uint64_t x3 = ia64_bits(raw, 33, 3);

        /* register form — a clean {0,2,0} */
        if (x3 == 0 && x4 == 2 && x2b == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4, unit, raw, address, slot);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r2 = ia64_bits(raw, 13, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }

        /*
         * A4 addp4 immediate uses x2a=3/ve=0; bits 36 and 32:27 are part
         * of the 14-bit signed immediate, not register-form extensions.
         */
        if (ia64_bits(raw, 34, 2) == 3 && ia64_bits(raw, 33, 1) == 0) {
            IA64Instruction insn =
                ia64_base_insn(IA64_OP_ADDP4_IMM, unit, raw, address, slot);
            insn.imm = ia64_imm14(raw);
            insn.r1 = ia64_bits(raw, 6, 7);
            insn.r3 = ia64_bits(raw, 20, 7);
            return insn;
        }
    }

    return ia64_invalid_insn(unit, raw, address, slot);
}
bool ia64_instruction_must_start_group(const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_ALLOC:
    case IA64_OP_FLUSHRS:
    case IA64_OP_LOADRS:
        return true;
    default:
        return false;
    }
}

bool ia64_instruction_must_end_group(const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_BSW0:
    case IA64_OP_BSW1:
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
    case IA64_OP_COVER:
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
    case IA64_OP_PTC_G:
    case IA64_OP_PTC_GA:
    case IA64_OP_RFI:
        return true;
    default:
        return false;
    }
}

bool ia64_instruction_requires_slot2(const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_BR_CEXIT:
    case IA64_OP_BR_CLOOP:
    case IA64_OP_BR_CTOP:
    case IA64_OP_BR_WEXIT:
    case IA64_OP_BR_WTOP:
        return true;
    default:
        return false;
    }
}

bool ia64_instruction_has_invalid_fp_pair(const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_LDFP8:
    case IA64_OP_LDFPD:
    case IA64_OP_LDFPS:
        /* Pair-bank parity is a physical-FR rule.  Logical operands can
           change parity after RRB.FR rotation, so decode may reject only
           the architecturally fixed f0/f1 destinations; the typed runtime
           check validates the mapped pair before any other operand fault. */
        return insn->r1 <= 1 || insn->r2 <= 1;
    default:
        return false;
    }
}
static bool ia64_reserved_ar_for_unit(uint8_t ar, IA64InstructionUnit unit,
                                      bool write)
{
    if (unit == IA64_INSN_UNIT_I) {
        return ar <= 47 || (ar >= 67 && ar <= 111);
    }

    if ((ar >= 8 && ar <= 15) || ar == 20 ||
        (ar >= 22 && ar <= 23) || ar == 31 ||
        (ar >= 33 && ar <= 35) || (ar >= 37 && ar <= 39) ||
        (ar >= 41 && ar <= 43) || (ar >= 45 && ar <= 47) ||
        (ar >= 64 && ar <= 111)) {
        return true;
    }
    return write && ar == 17;
}

static bool ia64_insn_has_reserved_ar(const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_MOV_ARGR:
        return ia64_reserved_ar_for_unit(insn->r2, insn->unit, false);
    case IA64_OP_MOV_GRAR:
    case IA64_OP_MOV_IMMAR:
        return ia64_reserved_ar_for_unit(insn->r2, insn->unit, true);
    default:
        return false;
    }
}

static bool ia64_reserved_cr(uint8_t cr)
{
    return (cr >= 3 && cr <= 7) || (cr >= 10 && cr <= 15) ||
           cr == 18 || (cr >= 26 && cr <= 63) ||
           (cr >= 75 && cr <= 79) || (cr >= 82);
}

bool ia64_instruction_has_illegal_register(const IA64Instruction *insn)
{
    if (ia64_insn_has_reserved_ar(insn)) {
        return true;
    }
    switch (insn->opcode) {
    case IA64_OP_MOV_CRGR:
        return ia64_reserved_cr(insn->r2);
    case IA64_OP_MOV_GRCR:
        return ia64_reserved_cr(insn->r2) ||
               ia64_cr_is_read_only(insn->r2);
    default:
        return false;
    }
}

bool ia64_instruction_has_reserved_mask_field(const IA64Instruction *insn)
{
    uint64_t allowed;

    switch (insn->opcode) {
    case IA64_OP_RUM:
    case IA64_OP_SUM_UM:
        return insn->imm & ~0x3eULL;
    case IA64_OP_RSM:
    case IA64_OP_SSM:
        allowed = 0x3eULL |
                  (0x7ULL << 13) |
                  (0x7ffULL << 17) |
                  (0x1fffULL << 32);
        return insn->imm & ~allowed;
    default:
        return false;
    }
}


static bool ia64_cr_is_read_only(uint32_t cr)
{
    return cr == 65 || (cr >= 68 && cr <= 71);
}

IA64InstructionUnit ia64_instruction_unit_from_slot_type(IA64SlotType type)
{
    switch (type) {
    case IA64_SLOT_TYPE_M:
        return IA64_INSN_UNIT_M;
    case IA64_SLOT_TYPE_I:
        return IA64_INSN_UNIT_I;
    case IA64_SLOT_TYPE_B:
        return IA64_INSN_UNIT_B;
    case IA64_SLOT_TYPE_F:
        return IA64_INSN_UNIT_F;
    case IA64_SLOT_TYPE_L:
        return IA64_INSN_UNIT_L;
    case IA64_SLOT_TYPE_X:
        return IA64_INSN_UNIT_X;
    case IA64_SLOT_TYPE_INVALID:
    default:
        return IA64_INSN_UNIT_RESERVED;
    }
}

const char *ia64_decode_status_name(IA64DecodeStatus status)
{
    switch (status) {
    case IA64_DECODE_OK:
        return "ok";
    case IA64_DECODE_RESERVED_TEMPLATE:
        return "reserved-template";
    case IA64_DECODE_RESERVED_ENCODING:
        return "reserved-encoding";
    case IA64_DECODE_ILLEGAL_UNIT:
        return "illegal-unit";
    case IA64_DECODE_ILLEGAL_REGISTER:
        return "illegal-register";
    case IA64_DECODE_ILLEGAL_PLACEMENT:
        return "illegal-placement";
    case IA64_DECODE_RESERVED_FIELD:
        return "reserved-field";
    default:
        return "unknown";
    }
}

static IA64DecodeStatus ia64_validate_instruction(IA64Instruction *insn,
                                                  bool group_start)
{
    if (insn->slot_span != 2) {
        insn->slot_span = insn->unit == IA64_INSN_UNIT_X ? 2 : 1;
    }
    insn->must_start_group = ia64_instruction_must_start_group(insn);
    insn->must_end_group = ia64_instruction_must_end_group(insn);
    insn->requires_slot2 = ia64_instruction_requires_slot2(insn);
    insn->placement = IA64_PLACE_NONE;
    if (insn->must_start_group) {
        insn->placement |= IA64_PLACE_MUST_START_GROUP;
    }
    if (insn->must_end_group) {
        insn->placement |= IA64_PLACE_MUST_END_GROUP;
    }
    if (insn->requires_slot2) {
        insn->placement |= IA64_PLACE_SLOT2_ONLY;
    }
    if (insn->slot_span == 2) {
        insn->placement |= IA64_PLACE_LONG_PAIR;
    }

    if (!insn->valid || insn->opcode == IA64_OP_ILLEGAL) {
        return IA64_DECODE_RESERVED_ENCODING;
    }
    if (insn->unit == IA64_INSN_UNIT_RESERVED) {
        return IA64_DECODE_ILLEGAL_UNIT;
    }
    if (ia64_instruction_has_illegal_register(insn) ||
        ia64_instruction_has_invalid_fp_pair(insn)) {
        return IA64_DECODE_ILLEGAL_REGISTER;
    }
    if (ia64_instruction_has_reserved_mask_field(insn)) {
        insn->reserved_field = true;
        return IA64_DECODE_RESERVED_FIELD;
    }
    if ((insn->must_start_group && !group_start) ||
        (insn->must_end_group && !insn->stop_after) ||
        (insn->requires_slot2 && insn->slot != 2)) {
        insn->placement_illegal = true;
        return IA64_DECODE_ILLEGAL_PLACEMENT;
    }
    return IA64_DECODE_OK;
}

bool ia64_decode_instruction_bundle(const IA64DecodedBundle *bundle,
                                    uint64_t address,
                                    bool starts_at_group_boundary,
                                    uint8_t start_slot,
                                    IA64DecodedInstructionBundle *decoded)
{
    bool group_start = starts_at_group_boundary;
    bool skip_x_slot = false;

    g_return_val_if_fail(decoded != NULL, false);
    memset(decoded, 0, sizeof(*decoded));
    decoded->error_slot = -1;
    decoded->starts_at_group_boundary = starts_at_group_boundary;
    decoded->start_slot = start_slot;

    if (start_slot >= IA64_SLOT_COUNT) {
        decoded->status = IA64_DECODE_ILLEGAL_PLACEMENT;
        return false;
    }

    if (bundle == NULL || !bundle->valid) {
        decoded->status = IA64_DECODE_RESERVED_TEMPLATE;
        decoded->template_code = bundle ? bundle->tmpl : 0;
        decoded->valid_template = false;
        return false;
    }

    decoded->template_code = bundle->tmpl;
    decoded->valid_template = true;
    decoded->status = IA64_DECODE_OK;

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64Instruction *insn;
        bool stop_after;

        if (skip_x_slot && slot == 2) {
            continue;
        }

        insn = &decoded->instruction[slot];
        *insn = ia64_decode_instruction_raw(
            ia64_instruction_unit_from_slot_type(bundle->info->slot_type[slot]),
            bundle->slot[slot], address, slot);
        ia64_decode_apply_mlx_fixup(bundle->tmpl, bundle->slot, slot,
                                    insn, &skip_x_slot);

        stop_after = bundle->info->stop_after_slot[
            skip_x_slot && slot == 1 ? 2 : slot];
        insn->stop_after = stop_after;
        if (skip_x_slot && slot == 1) {
            insn->slot_span = 2;
            insn->placement |= IA64_PLACE_LONG_PAIR;
        }
        decoded->instruction_mask |= 1U << slot;

        /*
         * A restarted TB begins at PSR.ri, so skipped physical slots must not
         * influence issue-group placement or the group state at the executed
         * suffix.  An MLX instruction is one logical instruction beginning in
         * slot 1; PSR.ri == 2 cannot restart in its X half.
         */
        if (slot < start_slot) {
            if (start_slot == 2 && slot == 1 && insn->slot_span == 2) {
                insn->placement_illegal = true;
                insn->status = IA64_DECODE_ILLEGAL_PLACEMENT;
                decoded->status = insn->status;
                decoded->error_slot = slot;
            }
            continue;
        }

        insn->starts_group = group_start;
        insn->status = ia64_validate_instruction(insn, group_start);

        if (decoded->status == IA64_DECODE_OK &&
            insn->status != IA64_DECODE_OK) {
            decoded->status = insn->status;
            decoded->error_slot = slot;
        }
        group_start = stop_after;
    }

    decoded->ends_at_group_boundary = group_start;
    return true;
}
