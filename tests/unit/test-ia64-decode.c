/*
 * IA-64 policy-free instruction decoder tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/decode.h"

#define IA64_TEST_NOP_RAW UINT64_C(0x08000000)
#define IA64_TEST_B_NOP_RAW (UINT64_C(2) << 37)

static IA64DecodedBundle make_bundle(uint8_t tmpl,
                                     uint64_t slot0,
                                     uint64_t slot1,
                                     uint64_t slot2)
{
    IA64DecodedBundle bundle = {
        .tmpl = tmpl & 0x1f,
        .slot = {
            slot0 & IA64_SLOT_MASK,
            slot1 & IA64_SLOT_MASK,
            slot2 & IA64_SLOT_MASK,
        },
    };

    bundle.info = ia64_template_info(bundle.tmpl);
    bundle.valid = bundle.info->valid;
    return bundle;
}

static void assert_raw_illegal(IA64InstructionUnit unit, uint64_t raw)
{
    IA64Instruction insn =
        ia64_decode_instruction_raw(unit, raw, 0x1060, 0);

    g_assert_false(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_ILLEGAL);
}

static void assert_raw_i_only(uint64_t raw, IA64Opcode opcode)
{
    for (IA64InstructionUnit unit = IA64_INSN_UNIT_RESERVED;
         unit <= IA64_INSN_UNIT_X; unit++) {
        IA64Instruction insn;

        if (unit == IA64_INSN_UNIT_I) {
            continue;
        }
        insn = ia64_decode_instruction_raw(unit, raw, 0x1060, 0);
        g_assert_cmpint(insn.opcode, !=, opcode);
    }
}

static void test_unit_mapping_is_total(void)
{
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_M),
                    ==, IA64_INSN_UNIT_M);
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_I),
                    ==, IA64_INSN_UNIT_I);
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_B),
                    ==, IA64_INSN_UNIT_B);
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_F),
                    ==, IA64_INSN_UNIT_F);
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_L),
                    ==, IA64_INSN_UNIT_L);
    g_assert_cmpint(ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_X),
                    ==, IA64_INSN_UNIT_X);
    g_assert_cmpint(
        ia64_instruction_unit_from_slot_type(IA64_SLOT_TYPE_INVALID),
        ==, IA64_INSN_UNIT_RESERVED);
}

static void test_core_integer_fields(void)
{
    const uint64_t add_r1_r2_r3 =
        (UINT64_C(8) << 37) | (UINT64_C(3) << 20) |
        (UINT64_C(2) << 13) | (UINT64_C(1) << 6);
    const uint64_t adds_r6_minus1_r7 =
        (UINT64_C(8) << 37) | (UINT64_C(1) << 36) |
        (UINT64_C(2) << 34) | (UINT64_C(0x3f) << 27) |
        (UINT64_C(7) << 20) | (UINT64_C(0x7f) << 13) |
        (UINT64_C(6) << 6);
    IA64Instruction insn;

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_I, add_r1_r2_r3,
                                       0x1000, 1);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_ADD);
    g_assert_cmpuint(insn.r1, ==, 1);
    g_assert_cmpuint(insn.r2, ==, 2);
    g_assert_cmpuint(insn.r3, ==, 3);
    g_assert_cmpuint(insn.qp, ==, 0);
    g_assert_cmpuint(insn.slot, ==, 1);
    g_assert_cmphex(insn.address, ==, 0x1000);

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_I,
                                       adds_r6_minus1_r7, 0x1010, 2);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_ADDS);
    g_assert_cmpuint(insn.r1, ==, 6);
    g_assert_cmpuint(insn.r3, ==, 7);
    g_assert_cmpint(insn.imm, ==, -1);
}

static void test_psr_ic_serialization_decode(void)
{
    static const struct {
        uint64_t raw;
        IA64Opcode opcode;
    } serialization[] = {
        { UINT64_C(0x00180000000), IA64_OP_SRLZ_D },
        { UINT64_C(0x00188000000), IA64_OP_SRLZ },
        { UINT64_C(0x00198000000), IA64_OP_SYNC_I },
    };
    IA64Instruction insn;

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_M,
                                       UINT64_C(0x00030080000),
                                       0x1020, 0);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_SSM);
    g_assert_cmphex(insn.imm, ==, UINT64_C(0x2000));

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_M,
                                       UINT64_C(0x00038080000),
                                       0x1020, 0);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_RSM);
    g_assert_cmphex(insn.imm, ==, UINT64_C(0x2000));

    for (unsigned i = 0; i < ARRAY_SIZE(serialization); i++) {
        insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_M,
                                           serialization[i].raw,
                                           0x1030, 0);
        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, serialization[i].opcode);
    }

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_M,
                                       UINT64_C(0x02168014000),
                                       0x1040, 0);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_GRPSR);
    g_assert_cmpuint(insn.r1, ==, 10);
    g_assert_cmpint(insn.imm, ==, 1);
}

static void test_m24_serialization_reserved_fields(void)
{
    static const uint64_t serialization[] = {
        UINT64_C(0x00180000000),
        UINT64_C(0x00188000000),
        UINT64_C(0x00198000000),
    };
    static const unsigned reserved_bits[] = { 6, 26, 36 };

    for (unsigned i = 0; i < ARRAY_SIZE(serialization); i++) {
        for (unsigned j = 0; j < ARRAY_SIZE(reserved_bits); j++) {
            uint64_t raw = serialization[i] |
                           (UINT64_C(1) << reserved_bits[j]);
            IA64DecodedBundle bundle =
                make_bundle(0x00, raw,
                            IA64_TEST_NOP_RAW, IA64_TEST_NOP_RAW);
            IA64Instruction insn = ia64_decode_instruction_raw(
                IA64_INSN_UNIT_M, raw, 0x1050, 0);
            IA64DecodedInstructionBundle decoded;

            g_assert_false(insn.valid);
            g_assert_cmpint(insn.opcode, ==, IA64_OP_ILLEGAL);
            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, 0x1050, true, 0, &decoded));
            g_assert_cmpint(decoded.status, ==,
                            IA64_DECODE_RESERVED_ENCODING);
            g_assert_cmpint(decoded.error_slot, ==, 0);
            g_assert_false(decoded.instruction[0].valid);
            g_assert_cmpint(decoded.instruction[0].opcode, ==,
                            IA64_OP_ILLEGAL);
        }
    }
}

static void test_i25_mov_from_predicates(void)
{
    const uint64_t base = UINT64_C(0x33) << 27;

    for (unsigned r1 = 0; r1 < 128; r1++) {
        const unsigned qp = (r1 * 13) & 0x3f;
        const uint64_t raw = base | ((uint64_t)r1 << 6) | qp;
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, raw, 0x1060, 1);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_PRGR);
        g_assert_cmpuint(insn.r1, ==, r1);
        g_assert_cmpuint(insn.qp, ==, qp);
        g_assert_cmpuint(insn.r2, ==, 0);
        g_assert_cmpuint(insn.r3, ==, 0);
        g_assert_cmpint(insn.imm, ==, 0);
    }

    assert_raw_i_only(base | (UINT64_C(37) << 6), IA64_OP_MOV_PRGR);
    for (unsigned bit = 13; bit <= 26; bit++) {
        assert_raw_illegal(IA64_INSN_UNIT_I,
                           base | (UINT64_C(1) << bit));
    }
}

static void test_i23_mov_to_predicates(void)
{
    const uint64_t base = (UINT64_C(3) << 33) | (UINT64_C(1) << 32);

    for (unsigned r1 = 0; r1 < 128; r1++) {
        const unsigned qp = (r1 * 29) & 0x3f;
        const uint64_t raw = base | ((uint64_t)r1 << 13) | qp;
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, raw, 0x1070, 2);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_GRPR);
        g_assert_cmpuint(insn.r1, ==, r1);
        g_assert_cmpuint(insn.qp, ==, qp);
        g_assert_cmpuint(insn.r2, ==, 0);
        g_assert_cmpuint(insn.r3, ==, 0);
        g_assert_cmpint(insn.imm, ==, 0);
    }

    for (unsigned bit = 6; bit <= 12; bit++) {
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, base | (UINT64_C(1) << bit),
            0x1070, 0);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_GRPR);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(1) << (bit - 5));
    }
    for (unsigned bit = 24; bit <= 31; bit++) {
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, base | (UINT64_C(1) << bit),
            0x1070, 0);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_GRPR);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(1) << (bit - 16));
    }

    {
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, base | (UINT64_C(1) << 36),
            0x1070, 0);

        g_assert_true(insn.valid);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(0xffffffffffff0000));
    }

    assert_raw_i_only(base | (UINT64_C(41) << 13), IA64_OP_MOV_GRPR);
    assert_raw_illegal(IA64_INSN_UNIT_I,
                       base & ~(UINT64_C(1) << 32));
    for (unsigned bit = 20; bit <= 23; bit++) {
        assert_raw_illegal(IA64_INSN_UNIT_I,
                           base | (UINT64_C(1) << bit));
    }
}

static void test_i24_mov_to_rotating_predicates(void)
{
    const uint64_t base = UINT64_C(2) << 33;

    for (unsigned bit = 6; bit <= 32; bit++) {
        const uint64_t raw = base | (UINT64_C(1) << bit) | 23;
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, raw, 0x1080, 0);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_PR_ROT_IMM);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(1) << (bit + 10));
        g_assert_cmpuint(insn.qp, ==, 23);
        g_assert_cmpuint(insn.r1, ==, 0);
        g_assert_cmpuint(insn.r2, ==, 0);
        g_assert_cmpuint(insn.r3, ==, 0);
    }

    {
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I, base | (UINT64_C(1) << 36),
            0x1080, 0);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_MOV_PR_ROT_IMM);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(0xfffff80000000000));
    }

    {
        const uint64_t imm27a = (UINT64_C(1) << 27) - 1;
        IA64Instruction insn = ia64_decode_instruction_raw(
            IA64_INSN_UNIT_I,
            base | (UINT64_C(1) << 36) | (imm27a << 6),
            0x1080, 0);

        g_assert_true(insn.valid);
        g_assert_cmphex((uint64_t)insn.imm, ==,
                        UINT64_C(0xffffffffffff0000));
    }

    assert_raw_i_only(base | (UINT64_C(0x1234567) << 6),
                      IA64_OP_MOV_PR_ROT_IMM);
}

typedef struct IA64CompareOperands {
    uint8_t p1;
    uint8_t p2;
    uint8_t r2;
    uint8_t r3;
    uint8_t qp;
} IA64CompareOperands;

static const IA64CompareOperands compare_operands[] = {
    { 0, 0, 0, 0, 0 },
    { 7, 9, 12, 13, 5 },
    { 63, 63, 127, 127, 63 },
};

static uint64_t make_compare_raw(unsigned major, unsigned bit36,
                                 unsigned x2, unsigned ta, unsigned c,
                                 const IA64CompareOperands *operands,
                                 unsigned r2_or_imm7)
{
    return ((uint64_t)major << 37) |
           ((uint64_t)bit36 << 36) |
           ((uint64_t)x2 << 34) |
           ((uint64_t)ta << 33) |
           ((uint64_t)operands->p2 << 27) |
           ((uint64_t)operands->r3 << 20) |
           ((uint64_t)r2_or_imm7 << 13) |
           ((uint64_t)c << 12) |
           ((uint64_t)operands->p1 << 6) |
           operands->qp;
}

/* Intel SDM Vol. 3 Tables 4-10 and 4-11 are the independent golden. */
static IA64Opcode expected_compare_opcode(unsigned major, unsigned bit36,
                                           unsigned x2, unsigned ta,
                                           unsigned c)
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
    const unsigned major_index = major - 0xc;
    const unsigned width_index = x2 & 1;

    if (x2 < 2 && bit36) {
        return update_zero[width_index][(ta << 1) | c][major_index];
    }
    if (ta) {
        return x2 >= 2 ? update_imm[width_index][c][major_index] :
                         update_reg[width_index][c][major_index];
    }
    return x2 >= 2 ? normal_imm[width_index][major_index] :
                     normal_reg[width_index][major_index];
}

static IA64PredicateUpdate expected_compare_update(unsigned major,
                                                    unsigned bit36,
                                                    unsigned x2,
                                                    unsigned ta)
{
    static const IA64PredicateUpdate updates[3] = {
        IA64_PRED_UPDATE_AND,
        IA64_PRED_UPDATE_OR,
        IA64_PRED_UPDATE_OR_ANDCM,
    };

    if ((x2 < 2 && bit36) || ta) {
        return updates[major - 0xc];
    }
    return IA64_PRED_UPDATE_NORMAL;
}

static void assert_compare_fields(const IA64Instruction *insn,
                                  IA64InstructionUnit unit,
                                  unsigned major, unsigned bit36,
                                  unsigned x2, unsigned ta, unsigned c,
                                  const IA64CompareOperands *operands,
                                  unsigned r2_or_imm7)
{
    const bool immediate = x2 >= 2;
    const bool a7 = !immediate && bit36;

    g_assert_true(insn->valid);
    g_assert_cmpint(insn->unit, ==, unit);
    g_assert_cmpint(insn->opcode, ==,
                    expected_compare_opcode(major, bit36, x2, ta, c));
    g_assert_cmpuint(insn->p1, ==, operands->p1);
    g_assert_cmpuint(insn->p2, ==, operands->p2);
    g_assert_cmpuint(insn->r2, ==, a7 || immediate ? 0 : r2_or_imm7);
    g_assert_cmpuint(insn->r3, ==, operands->r3);
    g_assert_cmpuint(insn->qp, ==, operands->qp);
    g_assert_cmpuint(insn->compare_width, ==, (x2 & 1) ? 4 : 8);
    g_assert_cmpint(insn->compare_immediate, ==, immediate);
    g_assert_cmpint(insn->pred_update, ==,
                    expected_compare_update(major, bit36, x2, ta));
    g_assert_cmpint(insn->compare_unc, ==,
                    !a7 && !ta && c);
    if (immediate) {
        g_assert_cmpint(insn->imm, ==,
                        (int8_t)((bit36 << 7) | r2_or_imm7));
    } else {
        g_assert_cmpint(insn->imm, ==, 0);
    }
}

static void test_integer_compare_matrix(void)
{
    for (unsigned unit = IA64_INSN_UNIT_M; unit <= IA64_INSN_UNIT_I; unit++) {
        for (unsigned major = 0xc; major <= 0xe; major++) {
            for (unsigned x2 = 0; x2 <= 3; x2++) {
                for (unsigned ta = 0; ta <= 1; ta++) {
                    for (unsigned c = 0; c <= 1; c++) {
                        if (x2 < 2) {
                            for (unsigned tb = 0; tb <= 1; tb++) {
                                for (size_t i = 0;
                                     i < G_N_ELEMENTS(compare_operands); i++) {
                                    const IA64CompareOperands *operands =
                                        &compare_operands[i];
                                    unsigned r2 = tb ? 0 : operands->r2;
                                    uint64_t raw = make_compare_raw(
                                        major, tb, x2, ta, c, operands, r2);
                                    IA64Instruction insn =
                                        ia64_decode_instruction_raw(
                                            unit, raw, 0x1070,
                                            unit - IA64_INSN_UNIT_M);

                                    assert_compare_fields(
                                        &insn, unit, major, tb, x2, ta, c,
                                        operands, r2);
                                }
                            }
                        } else {
                            /* Every signed imm8 bit-pattern is architected. */
                            for (unsigned imm8 = 0; imm8 <= 0xff; imm8++) {
                                unsigned s = imm8 >> 7;
                                unsigned imm7 = imm8 & 0x7f;

                                for (size_t i = 0;
                                     i < G_N_ELEMENTS(compare_operands); i++) {
                                    const IA64CompareOperands *operands =
                                        &compare_operands[i];
                                    uint64_t raw = make_compare_raw(
                                        major, s, x2, ta, c, operands, imm7);
                                    IA64Instruction insn =
                                        ia64_decode_instruction_raw(
                                            unit, raw, 0x1078,
                                            unit - IA64_INSN_UNIT_M);

                                    assert_compare_fields(
                                        &insn, unit, major, s, x2, ta, c,
                                        operands, imm7);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

static void test_a7_compare_reserved_r2_matrix(void)
{
    const IA64CompareOperands *operands = &compare_operands[1];

    for (unsigned unit = IA64_INSN_UNIT_M; unit <= IA64_INSN_UNIT_I; unit++) {
        for (unsigned major = 0xc; major <= 0xe; major++) {
            for (unsigned x2 = 0; x2 <= 1; x2++) {
                for (unsigned ta = 0; ta <= 1; ta++) {
                    for (unsigned c = 0; c <= 1; c++) {
                        for (unsigned r2 = 1; r2 <= 0x7f; r2++) {
                            uint64_t raw = make_compare_raw(
                                major, 1, x2, ta, c, operands, r2);
                            IA64Instruction insn = ia64_decode_instruction_raw(
                                unit, raw, 0x1080,
                                unit - IA64_INSN_UNIT_M);

                            g_assert_false(insn.valid);
                            g_assert_cmpint(insn.opcode, ==, IA64_OP_ILLEGAL);
                            g_assert_cmpuint(insn.compare_width, ==, 0);
                            g_assert_false(insn.compare_immediate);
                        }
                    }
                }
            }
        }
    }
}

static void test_integer_compare_unit_gate(void)
{
    const IA64CompareOperands *operands = &compare_operands[1];

    for (unsigned unit = IA64_INSN_UNIT_RESERVED;
         unit <= IA64_INSN_UNIT_X; unit++) {
        if (unit == IA64_INSN_UNIT_M || unit == IA64_INSN_UNIT_I) {
            continue;
        }
        for (unsigned major = 0xc; major <= 0xe; major++) {
            for (unsigned x2 = 0; x2 <= 3; x2++) {
                for (unsigned bit36 = 0; bit36 <= 1; bit36++) {
                    for (unsigned ta = 0; ta <= 1; ta++) {
                        for (unsigned c = 0; c <= 1; c++) {
                            unsigned payload = x2 < 2 && bit36 ? 0 : 12;
                            uint64_t raw = make_compare_raw(
                                major, bit36, x2, ta, c, operands, payload);
                            IA64Instruction insn = ia64_decode_instruction_raw(
                                unit, raw, 0x1088, 0);

                            g_assert_cmpint(
                                insn.opcode, !=,
                                expected_compare_opcode(major, bit36,
                                                        x2, ta, c));
                            g_assert_cmpuint(insn.compare_width, ==, 0);
                            g_assert_false(insn.compare_immediate);
                        }
                    }
                }
            }
        }
    }
}

typedef enum IA64PredicateTestKind {
    IA64_PREDICATE_TEST_TBIT,
    IA64_PREDICATE_TEST_TNAT,
    IA64_PREDICATE_TEST_TF,
} IA64PredicateTestKind;

typedef struct IA64PredicateTestForm {
    uint8_t c;
    uint8_t ta;
    uint8_t tb;
    bool nz;
    bool unc;
    IA64PredicateUpdate update;
} IA64PredicateTestForm;

/*
 * Intel SDM Vol. 3 predicate-test encodings.  Keep this as a literal list:
 * it is the independent golden for the decoder's c/ta/tb policy.
 */
static const IA64PredicateTestForm predicate_test_forms[] = {
    /* c  ta tb  relation/update */
    { 0, 0, 0, false, false, IA64_PRED_UPDATE_NORMAL },    /* .z */
    { 1, 0, 0, false, true,  IA64_PRED_UPDATE_NORMAL },    /* .z.unc */
    { 0, 0, 1, false, false, IA64_PRED_UPDATE_AND },       /* .z.and */
    { 1, 0, 1, true,  false, IA64_PRED_UPDATE_AND },       /* .nz.and */
    { 0, 1, 0, false, false, IA64_PRED_UPDATE_OR },        /* .z.or */
    { 1, 1, 0, true,  false, IA64_PRED_UPDATE_OR },        /* .nz.or */
    { 0, 1, 1, false, false, IA64_PRED_UPDATE_OR_ANDCM },  /* .z.or.andcm */
    { 1, 1, 1, true,  false, IA64_PRED_UPDATE_OR_ANDCM },  /* .nz.or.andcm */
};

static const IA64Opcode predicate_test_opcodes[3][2] = {
    { IA64_OP_TBIT_Z, IA64_OP_TBIT_NZ },
    { IA64_OP_TNAT_Z, IA64_OP_TNAT_NZ },
    { IA64_OP_TF_Z, IA64_OP_TF_NZ },
};

static uint64_t make_predicate_test_raw(
    IA64PredicateTestKind kind, const IA64PredicateTestForm *form,
    unsigned qp, unsigned p1, unsigned p2, unsigned r3, unsigned imm)
{
    uint64_t raw = (UINT64_C(5) << 37) |
                   ((uint64_t)form->tb << 36) |
                   ((uint64_t)form->ta << 33) |
                   ((uint64_t)p2 << 27) |
                   ((uint64_t)form->c << 12) |
                   ((uint64_t)p1 << 6) | qp;

    switch (kind) {
    case IA64_PREDICATE_TEST_TBIT:
        return raw | ((uint64_t)r3 << 20) | ((uint64_t)imm << 14);
    case IA64_PREDICATE_TEST_TNAT:
        return raw | ((uint64_t)r3 << 20) | (UINT64_C(1) << 13);
    case IA64_PREDICATE_TEST_TF:
        return raw | (UINT64_C(1) << 19) |
               ((uint64_t)(imm - 32) << 14) | (UINT64_C(1) << 13);
    default:
        g_assert_not_reached();
    }
}

static void assert_predicate_test_fields(
    const IA64Instruction *insn, IA64PredicateTestKind kind,
    const IA64PredicateTestForm *form, unsigned qp, unsigned p1,
    unsigned p2, unsigned r3, unsigned imm)
{
    g_assert_true(insn->valid);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_I);
    g_assert_cmpint(insn->opcode, ==,
                    predicate_test_opcodes[kind][form->nz]);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpuint(insn->p1, ==, p1);
    g_assert_cmpuint(insn->p2, ==, p2);
    g_assert_cmpuint(insn->r3, ==, r3);
    g_assert_cmpint(insn->imm, ==, imm);
    g_assert_cmpint(insn->pred_update, ==, form->update);
    g_assert_cmpint(insn->compare_unc, ==, form->unc);
    g_assert_cmpuint(insn->compare_width, ==, 0);
    g_assert_false(insn->compare_immediate);
}

static void assert_predicate_test_decodes(
    IA64PredicateTestKind kind, const IA64PredicateTestForm *form,
    unsigned qp, unsigned p1, unsigned p2, unsigned r3, unsigned imm)
{
    const uint64_t raw = make_predicate_test_raw(
        kind, form, qp, p1, p2, r3, imm);
    IA64Instruction insn = ia64_decode_instruction_raw(
        IA64_INSN_UNIT_I, raw, 0x1090, 1);

    assert_predicate_test_fields(&insn, kind, form,
                                 qp, p1, p2, r3, imm);
}

static void test_tbit_decode_matrix(void)
{
    for (size_t f = 0; f < G_N_ELEMENTS(predicate_test_forms); f++) {
        const IA64PredicateTestForm *form = &predicate_test_forms[f];

        /*
         * Vary one field at a time so extraction bugs cannot hide behind
         * correlations between adjacent fields in the raw instruction.
         */
        for (unsigned qp = 0; qp < 64; qp++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TBIT, form, qp, 7, 9, 13, 11);
        }
        for (unsigned p1 = 0; p1 < 64; p1++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TBIT, form, 5, p1, 9, 13, 11);
        }
        for (unsigned p2 = 0; p2 < 64; p2++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TBIT, form, 5, 7, p2, 13, 11);
        }
        for (unsigned r3 = 0; r3 < 128; r3++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TBIT, form, 5, 7, 9, r3, 11);
        }
        for (unsigned pos = 0; pos < 64; pos++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TBIT, form, 5, 7, 9, 13, pos);
        }
    }
}

static void test_tnat_decode_matrix(void)
{
    for (size_t f = 0; f < G_N_ELEMENTS(predicate_test_forms); f++) {
        const IA64PredicateTestForm *form = &predicate_test_forms[f];

        for (unsigned qp = 0; qp < 64; qp++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TNAT, form, qp, 7, 9, 13, 0);
        }
        for (unsigned p1 = 0; p1 < 64; p1++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TNAT, form, 5, p1, 9, 13, 0);
        }
        for (unsigned p2 = 0; p2 < 64; p2++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TNAT, form, 5, 7, p2, 13, 0);
        }
        for (unsigned r3 = 0; r3 < 128; r3++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TNAT, form, 5, 7, 9, r3, 0);
        }
    }
}

static void test_tf_decode_matrix(void)
{
    for (size_t f = 0; f < G_N_ELEMENTS(predicate_test_forms); f++) {
        const IA64PredicateTestForm *form = &predicate_test_forms[f];

        for (unsigned qp = 0; qp < 64; qp++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TF, form, qp, 7, 9, 0, 33);
        }
        for (unsigned p1 = 0; p1 < 64; p1++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TF, form, 5, p1, 9, 0, 33);
        }
        for (unsigned p2 = 0; p2 < 64; p2++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TF, form, 5, 7, p2, 0, 33);
        }
        for (unsigned imm = 32; imm < 64; imm++) {
            assert_predicate_test_decodes(
                IA64_PREDICATE_TEST_TF, form, 5, 7, 9, 0, imm);
        }
    }
}

static bool is_predicate_test_opcode(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_TBIT_Z:
    case IA64_OP_TBIT_NZ:
    case IA64_OP_TBIT_Z_OR_ANDCM:
    case IA64_OP_TBIT_NZ_OR_ANDCM:
    case IA64_OP_TNAT_Z:
    case IA64_OP_TNAT_NZ:
    case IA64_OP_TNAT_NZ_AND:
    case IA64_OP_TF_Z:
    case IA64_OP_TF_NZ:
        return true;
    default:
        return false;
    }
}

static void test_predicate_test_unit_gate(void)
{
    for (unsigned kind = IA64_PREDICATE_TEST_TBIT;
         kind <= IA64_PREDICATE_TEST_TF; kind++) {
        for (size_t f = 0; f < G_N_ELEMENTS(predicate_test_forms); f++) {
            const IA64PredicateTestForm *form = &predicate_test_forms[f];
            const unsigned r3 = kind == IA64_PREDICATE_TEST_TF ? 0 : 77;
            const unsigned imm = kind == IA64_PREDICATE_TEST_TBIT ? 43 :
                                 kind == IA64_PREDICATE_TEST_TF ? 53 : 0;
            const uint64_t raw = make_predicate_test_raw(
                kind, form, 61, 27, 38, r3, imm);

            for (unsigned unit = IA64_INSN_UNIT_RESERVED;
                 unit <= IA64_INSN_UNIT_X; unit++) {
                IA64Instruction insn;

                if (unit == IA64_INSN_UNIT_I) {
                    continue;
                }
                insn = ia64_decode_instruction_raw(unit, raw, 0x1090, 1);
                g_assert_false(is_predicate_test_opcode(insn.opcode));
            }
        }
    }
}

static void assert_i_reserved_encoding(uint64_t raw)
{
    IA64DecodedBundle bundle = make_bundle(
        0x00, IA64_TEST_NOP_RAW, raw, IA64_TEST_NOP_RAW);
    IA64DecodedInstructionBundle decoded;

    assert_raw_illegal(IA64_INSN_UNIT_I, raw);
    g_assert_true(ia64_decode_instruction_bundle(
        &bundle, 0x1090, true, 0, &decoded));
    g_assert_true(decoded.valid_template);
    g_assert_cmpint(decoded.status, ==, IA64_DECODE_RESERVED_ENCODING);
    g_assert_cmpint(decoded.error_slot, ==, 1);
    g_assert_cmpint(decoded.instruction[1].status, ==,
                    IA64_DECODE_RESERVED_ENCODING);
    g_assert_false(decoded.instruction[1].valid);
    g_assert_cmpint(decoded.instruction[1].opcode, ==, IA64_OP_ILLEGAL);
}

static void test_predicate_test_reserved_encodings(void)
{
    for (size_t f = 0; f < G_N_ELEMENTS(predicate_test_forms); f++) {
        const IA64PredicateTestForm *form = &predicate_test_forms[f];

        /*
         * Cross every nonzero reserved tnat imm5 with the complete r3
         * domain.  qp/p1/p2 cannot affect recognition and are held distinct.
         */
        for (unsigned r3 = 0; r3 < 128; r3++) {
            const uint64_t tnat = make_predicate_test_raw(
                IA64_PREDICATE_TEST_TNAT, form, 5, 7, 9, r3, 0);

            for (unsigned reserved = 1; reserved < 32; reserved++) {
                assert_i_reserved_encoding(
                    tnat | ((uint64_t)reserved << 14));
            }
        }

        /* Cross every reserved tf r3 with the complete imm5 domain. */
        for (unsigned imm = 32; imm < 64; imm++) {
            const uint64_t tf = make_predicate_test_raw(
                IA64_PREDICATE_TEST_TF, form, 5, 7, 9, 0, imm);

            for (unsigned r3 = 1; r3 < 128; r3++) {
                assert_i_reserved_encoding(tf | ((uint64_t)r3 << 20));
            }
        }
    }
}

static void test_reserved_a3_patterns_stay_illegal(void)
{
    static const struct {
        uint8_t x4;
        uint8_t x2b;
    } reserved[] = {
        { 0x0, 3 }, /* not mux */
        { 0x5, 0 }, /* not variable shr */
        { 0x7, 0 }, /* not extr */
        { 0x7, 1 }, /* not extr.u */
        { 0x8, 0 }, /* not mpy4 */
        { 0x8, 1 }, /* not mpysh */
        { 0x8, 2 }, /* not mpyuh */
        { 0xa, 1 }, /* not popcnt */
    };

    for (unsigned unit = IA64_INSN_UNIT_M; unit <= IA64_INSN_UNIT_I; unit++) {
        for (unsigned i = 0; i < G_N_ELEMENTS(reserved); i++) {
            uint64_t raw = (UINT64_C(8) << 37) |
                           ((uint64_t)reserved[i].x4 << 29) |
                           ((uint64_t)reserved[i].x2b << 27);
            IA64Instruction insn = ia64_decode_instruction_raw(
                unit, raw, 0x1080, unit - IA64_INSN_UNIT_M);
            IA64DecodedBundle bundle = unit == IA64_INSN_UNIT_M
                ? make_bundle(0x00, raw,
                              IA64_TEST_NOP_RAW, IA64_TEST_NOP_RAW)
                : make_bundle(0x00, IA64_TEST_NOP_RAW,
                              raw, IA64_TEST_NOP_RAW);
            IA64DecodedInstructionBundle decoded;

            g_assert_false(insn.valid);
            g_assert_cmpint(insn.opcode, ==, IA64_OP_ILLEGAL);
            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, 0x1080, true, 0, &decoded));
            g_assert_cmpint(decoded.status, ==,
                            IA64_DECODE_RESERVED_ENCODING);
            g_assert_cmpint(decoded.error_slot, ==,
                            unit - IA64_INSN_UNIT_M);
        }
    }
}

static void test_immediate_shifts_are_canonical_bitfields(void)
{
    const uint64_t shl_r8_r3_32 =
        (UINT64_C(5) << 37) | (UINT64_C(1) << 34) |
        (UINT64_C(1) << 33) | (UINT64_C(31) << 27) |
        (UINT64_C(31) << 20) | (UINT64_C(3) << 13) |
        (UINT64_C(8) << 6);
    const uint64_t shru_r9_r4_8 =
        (UINT64_C(5) << 37) | (UINT64_C(1) << 34) |
        (UINT64_C(55) << 27) | (UINT64_C(4) << 20) |
        (UINT64_C(16) << 13) | (UINT64_C(9) << 6);
    IA64Instruction insn;

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_I, shl_r8_r3_32,
                                       0x1090, 1);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_DEPZ);
    g_assert_cmpuint(insn.r1, ==, 8);
    g_assert_cmpuint(insn.r2, ==, 3);
    g_assert_cmpuint((uint64_t)insn.imm & 0x3f, ==, 32);
    g_assert_cmpuint(((uint64_t)insn.imm >> 6) & 0x7f, ==, 32);

    insn = ia64_decode_instruction_raw(IA64_INSN_UNIT_I, shru_r9_r4_8,
                                       0x1090, 2);
    g_assert_true(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_EXTRU);
    g_assert_cmpuint(insn.r1, ==, 9);
    g_assert_cmpuint(insn.r3, ==, 4);
    g_assert_cmpuint((uint64_t)insn.imm & 0x3f, ==, 8);
    g_assert_cmpuint(((uint64_t)insn.imm >> 6) & 0x7f, ==, 56);
}

typedef struct IA64TestX3BranchEncoding {
    uint64_t l_raw;
    uint64_t x_raw;
} IA64TestX3BranchEncoding;

/*
 * Independent literal encoders for Intel SDM formats B1 and X3.  These are
 * deliberately expressed in terms of the published bit layout instead of
 * calling decoder/fixup helpers: the tests must remain a separate golden for
 * immediate placement and sign handling.
 */
static uint64_t encode_test_b1_br_cond(int64_t displacement, unsigned qp)
{
    int64_t scaled;
    uint64_t field;

    g_assert_cmpint(displacement % 16, ==, 0);
    g_assert_cmpint(displacement, >=, -INT64_C(0x1000000));
    g_assert_cmpint(displacement, <=, INT64_C(0x0fffff0));
    g_assert_cmpuint(qp, <, 64);

    scaled = displacement / 16;
    field = (uint64_t)scaled & ((UINT64_C(1) << 21) - 1);
    return (UINT64_C(4) << 37) |
           ((field & UINT64_C(0xfffff)) << 13) |
           (((field >> 20) & 1) << 36) |
           qp;
}

static IA64TestX3BranchEncoding encode_test_x3_brl_cond(
    int64_t displacement, unsigned qp)
{
    const uint64_t field_mask = (UINT64_C(1) << 60) - 1;
    const uint64_t imm39_mask = (UINT64_C(1) << 39) - 1;
    IA64TestX3BranchEncoding encoding;
    int64_t scaled;
    uint64_t field;

    g_assert_cmpint(displacement % 16, ==, 0);
    g_assert_cmpuint(qp, <, 64);

    scaled = displacement / 16;
    field = (uint64_t)scaled & field_mask;
    encoding.l_raw = ((field >> 20) & imm39_mask) << 2;
    encoding.x_raw = (UINT64_C(0xc) << 37) |
                     ((field & UINT64_C(0xfffff)) << 13) |
                     (((field >> 59) & 1) << 36) |
                     qp;
    return encoding;
}

static uint64_t encode_test_b3_br_call(int64_t displacement, unsigned qp,
                                       unsigned b1)
{
    uint64_t raw = encode_test_b1_br_cond(displacement, qp);

    g_assert_cmpuint(b1, <, 8);
    raw &= ~(UINT64_C(7) << 6);
    raw &= ~(UINT64_C(0xf) << 37);
    return raw | ((uint64_t)b1 << 6) | (UINT64_C(5) << 37);
}

static uint64_t encode_test_b4_br_ret(unsigned qp, unsigned b2)
{
    g_assert_cmpuint(qp, <, 64);
    g_assert_cmpuint(b2, <, 8);

    return (UINT64_C(0x21) << 27) |
           ((uint64_t)b2 << 13) |
           (UINT64_C(4) << 6) |
           qp;
}

static IA64TestX3BranchEncoding encode_test_x4_brl_call(
    int64_t displacement, unsigned qp, unsigned b1)
{
    IA64TestX3BranchEncoding encoding =
        encode_test_x3_brl_cond(displacement, qp);

    g_assert_cmpuint(b1, <, 8);
    encoding.x_raw &= ~(UINT64_C(0xf) << 37);
    encoding.x_raw |= (UINT64_C(0xd) << 37) | ((uint64_t)b1 << 6);
    return encoding;
}

/*
 * Ignored encoding bits may change raw, but no decoded semantic, placement, or
 * fault metadata.  Keep this deliberately exhaustive so newly added decoder
 * fields cannot silently escape the format closure tests below.
 */
static void assert_instruction_metadata_invariant(
    const IA64Instruction *actual, const IA64Instruction *control)
{
#define ASSERT_META_INT(field) \
    g_assert_cmpint(actual->field, ==, control->field)
#define ASSERT_META_UINT(field) \
    g_assert_cmpuint(actual->field, ==, control->field)

    ASSERT_META_INT(opcode);
    ASSERT_META_INT(unit);
    g_assert_cmphex(actual->address, ==, control->address);
    ASSERT_META_UINT(slot);
    ASSERT_META_UINT(qp);
    ASSERT_META_UINT(r1);
    ASSERT_META_UINT(r2);
    ASSERT_META_UINT(r3);
    ASSERT_META_UINT(p1);
    ASSERT_META_UINT(p2);
    ASSERT_META_UINT(b1);
    ASSERT_META_UINT(b2);
    ASSERT_META_UINT(sf);
    ASSERT_META_UINT(fp_precision);
    ASSERT_META_UINT(compare_width);
    g_assert_cmpint(actual->imm, ==, control->imm);
    ASSERT_META_INT(pred_update);
    ASSERT_META_INT(hint_m_reg_increment);
    ASSERT_META_INT(reg_base_update);
    ASSERT_META_INT(imm_base_update);
    ASSERT_META_INT(mem_acquire);
    ASSERT_META_INT(mem_release);
    ASSERT_META_INT(compare_immediate);
    ASSERT_META_INT(compare_unc);
    ASSERT_META_INT(clear_p2_before_predicate);
    ASSERT_META_INT(check_fp);
    ASSERT_META_INT(fp_load_speculative);
    ASSERT_META_INT(fp_load_advanced);
    ASSERT_META_INT(fp_load_check);
    ASSERT_META_INT(fp_load_check_clear);
    ASSERT_META_INT(probe_fault);
    ASSERT_META_INT(probe_imm);
    ASSERT_META_INT(placement_illegal);
    ASSERT_META_INT(reserved_field);
    ASSERT_META_INT(valid);
    ASSERT_META_INT(starts_group);
    ASSERT_META_INT(stop_after);
    ASSERT_META_INT(must_start_group);
    ASSERT_META_INT(must_end_group);
    ASSERT_META_INT(requires_slot2);
    ASSERT_META_UINT(slot_span);
    ASSERT_META_UINT(placement);
    ASSERT_META_INT(status);

#undef ASSERT_META_UINT
#undef ASSERT_META_INT
}

static void assert_decoded_metadata_invariant(
    const IA64DecodedInstructionBundle *actual,
    const IA64DecodedInstructionBundle *control,
    unsigned raw_slot, uint64_t expected_raw)
{
    g_assert_cmphex(actual->instruction_mask, ==,
                    control->instruction_mask);
    g_assert_cmpuint(actual->template_code, ==, control->template_code);
    g_assert_cmpuint(actual->start_slot, ==, control->start_slot);
    g_assert_cmpint(actual->error_slot, ==, control->error_slot);
    g_assert_cmpint(actual->status, ==, control->status);
    g_assert_cmpint(actual->valid_template, ==, control->valid_template);
    g_assert_cmpint(actual->starts_at_group_boundary, ==,
                    control->starts_at_group_boundary);
    g_assert_cmpint(actual->ends_at_group_boundary, ==,
                    control->ends_at_group_boundary);

    for (unsigned slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        assert_instruction_metadata_invariant(&actual->instruction[slot],
                                              &control->instruction[slot]);
        g_assert_cmphex(actual->instruction[slot].raw, ==,
                        slot == raw_slot ? expected_raw :
                        control->instruction[slot].raw);
    }
}

static void assert_b1_br_cond_metadata(const IA64Instruction *insn,
                                       uint64_t raw, uint64_t address,
                                       unsigned slot, unsigned qp,
                                       int64_t displacement,
                                       bool starts_group, bool stop_after)
{
    g_assert_true(insn->valid);
    g_assert_cmpint(insn->opcode, ==, IA64_OP_BR_COND);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
    g_assert_cmphex(insn->raw, ==, raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, slot);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpint(insn->imm, ==, displacement);
    g_assert_cmpuint(insn->slot_span, ==, 1);
    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_NONE);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_cmpint(insn->starts_group, ==, starts_group);
    g_assert_cmpint(insn->stop_after, ==, stop_after);
    g_assert_false(insn->must_start_group);
    g_assert_false(insn->must_end_group);
    g_assert_false(insn->requires_slot2);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void assert_x3_brl_cond_metadata(const IA64Instruction *insn,
                                        uint64_t x_raw, uint64_t address,
                                        unsigned qp, int64_t displacement,
                                        bool stop_after)
{
    g_assert_true(insn->valid);
    g_assert_cmpint(insn->opcode, ==, IA64_OP_BRL_COND);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_X);
    g_assert_cmphex(insn->raw, ==, x_raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, 1);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpint(insn->imm, ==, displacement);
    g_assert_cmpuint(insn->slot_span, ==, 2);
    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_LONG_PAIR);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_false(insn->starts_group);
    g_assert_cmpint(insn->stop_after, ==, stop_after);
    g_assert_false(insn->must_start_group);
    g_assert_false(insn->must_end_group);
    g_assert_false(insn->requires_slot2);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void assert_x4_brl_call_metadata(const IA64Instruction *insn,
                                        uint64_t x_raw, uint64_t address,
                                        unsigned qp, unsigned b1,
                                        int64_t displacement,
                                        bool stop_after)
{
    g_assert_true(insn->valid);
    g_assert_cmpint(insn->opcode, ==, IA64_OP_BRL_CALL);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_X);
    g_assert_cmphex(insn->raw, ==, x_raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, 1);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpuint(insn->b1, ==, b1);
    g_assert_cmpint(insn->imm, ==, displacement);
    g_assert_cmpuint(insn->slot_span, ==, 2);
    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_LONG_PAIR);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_false(insn->starts_group);
    g_assert_cmpint(insn->stop_after, ==, stop_after);
    g_assert_false(insn->must_start_group);
    g_assert_false(insn->must_end_group);
    g_assert_false(insn->requires_slot2);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void test_b1_br_cond_boundary_matrix(void)
{
    static const int64_t displacements[] = {
        -INT64_C(0x1000000),
        -INT64_C(0x10),
        0,
        INT64_C(0x10),
        INT64_C(0x0fffff0),
    };
    const uint64_t address = UINT64_C(0x123456789abcde00);

    /*
     * Five signed boundaries times the complete qp and ignored 11:9 domains.
     */
    for (size_t d = 0; d < G_N_ELEMENTS(displacements); d++) {
        for (unsigned qp = 0; qp < 64; qp++) {
            uint64_t control_slots[IA64_SLOT_COUNT] = {
                IA64_TEST_B_NOP_RAW,
                IA64_TEST_B_NOP_RAW,
                IA64_TEST_B_NOP_RAW,
            };
            const unsigned slot = qp % IA64_SLOT_COUNT;
            const uint64_t control_raw = encode_test_b1_br_cond(
                displacements[d], qp);
            IA64DecodedInstructionBundle control;
            IA64DecodedBundle control_bundle;

            control_slots[slot] = control_raw;
            control_bundle = make_bundle(
                0x17, control_slots[0], control_slots[1], control_slots[2]);
            g_assert_true(ia64_decode_instruction_bundle(
                &control_bundle, address, true, 0, &control));

            for (unsigned ignored = 0; ignored < 8; ignored++) {
                uint64_t slots[IA64_SLOT_COUNT] = {
                    IA64_TEST_B_NOP_RAW,
                    IA64_TEST_B_NOP_RAW,
                    IA64_TEST_B_NOP_RAW,
                };
                const uint64_t raw = control_raw |
                                     ((uint64_t)ignored << 9);
                IA64DecodedInstructionBundle decoded;
                IA64DecodedBundle bundle;

                slots[slot] = raw;
                bundle = make_bundle(0x17, slots[0], slots[1], slots[2]);
                g_assert_true(ia64_decode_instruction_bundle(
                    &bundle, address, true, 0, &decoded));

                assert_decoded_metadata_invariant(
                    &decoded, &control, slot, raw);
                assert_b1_br_cond_metadata(
                    &decoded.instruction[slot], raw, address, slot, qp,
                    displacements[d], slot == 0, slot == 2);
            }
        }
    }
}

static void test_b1_br_cond_btype_rejection(void)
{
    static const unsigned reserved_btypes[] = { 1, 4 };
    const uint64_t address = UINT64_C(0x1234567800001000);
    const unsigned qp = 0x2d;

    for (size_t i = 0; i < G_N_ELEMENTS(reserved_btypes); i++) {
        const uint64_t control_raw = encode_test_b1_br_cond(0x10, qp) |
                                     ((uint64_t)reserved_btypes[i] << 6);
        IA64DecodedBundle control_bundle = make_bundle(
            0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, control_raw);
        IA64DecodedInstructionBundle control;

        g_assert_true(ia64_decode_instruction_bundle(
            &control_bundle, address, true, 0, &control));

        for (unsigned ignored = 0; ignored < 8; ignored++) {
            const uint64_t raw = control_raw |
                                 ((uint64_t)ignored << 9);
            IA64DecodedBundle bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
            IA64DecodedInstructionBundle decoded;
            const IA64Instruction *insn;

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            insn = &decoded.instruction[2];
            assert_decoded_metadata_invariant(
                &decoded, &control, 2, raw);

            g_assert_cmpint(insn->opcode, !=, IA64_OP_BR_COND);
            g_assert_cmpint(insn->opcode, ==, IA64_OP_ILLEGAL);
            g_assert_false(insn->valid);
            g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
            g_assert_cmphex(insn->raw, ==, raw);
            g_assert_cmphex(insn->address, ==, address);
            g_assert_cmpuint(insn->slot, ==, 2);
            g_assert_cmpuint(insn->slot_span, ==, 1);
            g_assert_false(insn->starts_group);
            g_assert_true(insn->stop_after);
            g_assert_cmphex(decoded.instruction_mask, ==, 0x7);
            g_assert_true(decoded.ends_at_group_boundary);
            g_assert_false(insn->requires_slot2);
            g_assert_cmpuint(insn->placement, ==, IA64_PLACE_NONE);
            g_assert_cmpint(insn->status, ==,
                            IA64_DECODE_RESERVED_ENCODING);
            g_assert_cmpint(decoded.status, ==,
                            IA64_DECODE_RESERVED_ENCODING);
            g_assert_cmpint(decoded.error_slot, ==, 2);
        }
    }
}

static void test_b1_while_branch_qp_matrix(void)
{
    static const struct {
        unsigned btype;
        IA64Opcode opcode;
    } cases[] = {
        { 2, IA64_OP_BR_WEXIT },
        { 3, IA64_OP_BR_WTOP  },
    };
    const uint64_t address = UINT64_C(0x1234567800001100);

    /* B1 while branches use qp; bits 11:9 remain ignored for all qp values. */
    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        for (unsigned qp = 0; qp < 64; qp++) {
            const uint64_t control_raw =
                encode_test_b1_br_cond(-0x10, qp) |
                ((uint64_t)cases[i].btype << 6);
            IA64DecodedBundle control_bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW,
                control_raw);
            IA64DecodedInstructionBundle control;

            g_assert_true(ia64_decode_instruction_bundle(
                &control_bundle, address, true, 0, &control));

            for (unsigned ignored = 0; ignored < 8; ignored++) {
                const uint64_t raw = control_raw |
                                     ((uint64_t)ignored << 9);
                IA64DecodedBundle bundle = make_bundle(
                    0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
                IA64DecodedInstructionBundle decoded;
                const IA64Instruction *insn;

                g_assert_true(ia64_decode_instruction_bundle(
                    &bundle, address, true, 0, &decoded));
                insn = &decoded.instruction[2];

                assert_decoded_metadata_invariant(
                    &decoded, &control, 2, raw);
                g_assert_true(insn->valid);
                g_assert_cmpint(insn->opcode, ==, cases[i].opcode);
                g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
                g_assert_cmphex(insn->raw, ==, raw);
                g_assert_cmphex(insn->address, ==, address);
                g_assert_cmpuint(insn->slot, ==, 2);
                g_assert_cmpuint(insn->slot_span, ==, 1);
                g_assert_cmpuint(insn->qp, ==, qp);
                g_assert_cmpint(insn->imm, ==, -0x10);
                g_assert_false(insn->starts_group);
                g_assert_true(insn->stop_after);
                g_assert_true(insn->requires_slot2);
                g_assert_cmpuint(insn->placement, ==,
                                 IA64_PLACE_SLOT2_ONLY);
                g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
                g_assert_false(insn->placement_illegal);
                g_assert_false(insn->reserved_field);
            }
        }
    }
}

static void test_b2_counted_branch_qp_matrix(void)
{
    static const struct {
        unsigned btype;
        IA64Opcode opcode;
    } cases[] = {
        { 5, IA64_OP_BR_CLOOP },
        { 6, IA64_OP_BR_CEXIT },
        { 7, IA64_OP_BR_CTOP  },
    };
    const uint64_t address = UINT64_C(0x1234567800001200);

    /*
     * B2 fixes bits 5:0 to zero, while bits 11:9 stay ignored for both the
     * legal zero value and every precisely rejected nonzero low-six value.
     */
    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        for (unsigned low6 = 0; low6 < 64; low6++) {
            const uint64_t control_raw =
                encode_test_b1_br_cond(0x10, low6) |
                ((uint64_t)cases[i].btype << 6);
            IA64DecodedBundle control_bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW,
                control_raw);
            IA64DecodedInstructionBundle control;

            g_assert_true(ia64_decode_instruction_bundle(
                &control_bundle, address, true, 0, &control));

            for (unsigned ignored = 0; ignored < 8; ignored++) {
                const uint64_t raw = control_raw |
                                     ((uint64_t)ignored << 9);
                IA64DecodedBundle bundle = make_bundle(
                    0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
                IA64DecodedInstructionBundle decoded;
                const IA64Instruction *insn;

                g_assert_true(ia64_decode_instruction_bundle(
                    &bundle, address, true, 0, &decoded));
                insn = &decoded.instruction[2];
                assert_decoded_metadata_invariant(
                    &decoded, &control, 2, raw);

                g_assert_true(decoded.valid_template);
                g_assert_cmpuint(decoded.template_code, ==, 0x17);
                g_assert_cmphex(decoded.instruction_mask, ==, 0x7);
                g_assert_true(decoded.starts_at_group_boundary);
                g_assert_true(decoded.ends_at_group_boundary);
                g_assert_cmphex(insn->raw, ==, raw);
                g_assert_cmphex(insn->address, ==, address);
                g_assert_cmpuint(insn->slot, ==, 2);
                g_assert_cmpuint(insn->slot_span, ==, 1);
                g_assert_false(insn->starts_group);
                g_assert_true(insn->stop_after);

                if (low6 == 0) {
                    g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
                    g_assert_cmpint(decoded.error_slot, ==, -1);
                    g_assert_true(insn->valid);
                    g_assert_cmpint(insn->opcode, ==, cases[i].opcode);
                    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
                    g_assert_cmpuint(insn->qp, ==, 0);
                    g_assert_cmpint(insn->imm, ==, 0x10);
                    g_assert_true(insn->requires_slot2);
                    g_assert_cmpuint(insn->placement, ==,
                                     IA64_PLACE_SLOT2_ONLY);
                    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
                    g_assert_false(insn->placement_illegal);
                    g_assert_false(insn->reserved_field);
                } else {
                    g_assert_cmpint(decoded.status, ==,
                                    IA64_DECODE_RESERVED_ENCODING);
                    g_assert_cmpint(decoded.error_slot, ==, 2);
                    g_assert_false(insn->valid);
                    g_assert_cmpint(insn->opcode, ==, IA64_OP_ILLEGAL);
                    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
                    g_assert_false(insn->requires_slot2);
                    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_NONE);
                    g_assert_cmpint(insn->status, ==,
                                    IA64_DECODE_RESERVED_ENCODING);
                    g_assert_false(insn->placement_illegal);
                    g_assert_false(insn->reserved_field);
                }
            }
        }
    }
}

static void assert_ignored_branch_encoding(
    const IA64DecodedInstructionBundle *decoded, uint64_t raw,
    uint64_t address, IA64Opcode opcode, unsigned qp, unsigned b1,
    unsigned b2)
{
    const IA64Instruction *insn = &decoded->instruction[2];

    g_assert_true(decoded->valid_template);
    g_assert_cmpuint(decoded->template_code, ==, 0x17);
    g_assert_cmpuint(decoded->start_slot, ==, 0);
    g_assert_cmphex(decoded->instruction_mask, ==, 0x7);
    g_assert_cmpint(decoded->status, ==, IA64_DECODE_OK);
    g_assert_cmpint(decoded->error_slot, ==, -1);
    g_assert_true(decoded->starts_at_group_boundary);
    g_assert_true(decoded->ends_at_group_boundary);

    g_assert_true(insn->valid);
    g_assert_cmpint(insn->opcode, ==, opcode);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
    g_assert_cmphex(insn->raw, ==, raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, 2);
    g_assert_cmpuint(insn->slot_span, ==, 1);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpuint(insn->b1, ==, b1);
    g_assert_cmpuint(insn->b2, ==, b2);
    g_assert_false(insn->starts_group);
    g_assert_true(insn->stop_after);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void assert_b5_even_wh_no_effect(
    const IA64DecodedInstructionBundle *decoded, uint64_t raw,
    uint64_t address, unsigned qp)
{
    const IA64Instruction *insn = &decoded->instruction[2];

    g_assert_true(decoded->valid_template);
    g_assert_cmpuint(decoded->template_code, ==, 0x17);
    g_assert_cmpuint(decoded->start_slot, ==, 0);
    g_assert_cmphex(decoded->instruction_mask, ==, 0x7);
    g_assert_cmpint(decoded->status, ==, IA64_DECODE_OK);
    g_assert_cmpint(decoded->error_slot, ==, -1);
    g_assert_true(decoded->starts_at_group_boundary);
    g_assert_true(decoded->ends_at_group_boundary);

    g_assert_true(insn->valid);
    g_assert_true(insn->opcode == IA64_OP_HINT_B ||
                  insn->opcode == IA64_OP_NOP);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
    g_assert_cmphex(insn->raw, ==, raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, 2);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpuint(insn->b1, ==, 0);
    g_assert_cmpuint(insn->b2, ==, 0);
    g_assert_cmpuint(insn->slot_span, ==, 1);
    g_assert_false(insn->starts_group);
    g_assert_true(insn->stop_after);
    g_assert_false(insn->must_start_group);
    g_assert_false(insn->must_end_group);
    g_assert_false(insn->requires_slot2);
    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_NONE);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void decode_and_assert_b5_call(
    uint64_t raw, uint64_t address,
    const IA64DecodedInstructionBundle *control)
{
    IA64DecodedBundle bundle = make_bundle(
        0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(
        &bundle, address, true, 0, &decoded));
    assert_decoded_metadata_invariant(&decoded, control, 2, raw);
    assert_ignored_branch_encoding(
        &decoded, raw, address, IA64_OP_BR_CALL_INDIRECT, 0x2a, 3, 5);
}

static void decode_and_assert_b5_no_effect(uint64_t raw, uint64_t address)
{
    IA64DecodedBundle bundle = make_bundle(
        0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(
        &bundle, address, true, 0, &decoded));
    assert_b5_even_wh_no_effect(&decoded, raw, address, 0x2a);
}

static void test_b4_ignored_field_matrix(void)
{
    static const struct {
        uint64_t raw;
        IA64Opcode opcode;
        unsigned qp;
        unsigned b2;
    } cases[] = {
        {
            (UINT64_C(0x20) << 27) | (UINT64_C(5) << 13) | 0x2d,
            IA64_OP_BR_INDIRECT, 0x2d, 5,
        },
        {
            (UINT64_C(0x20) << 27) | (UINT64_C(6) << 13) |
            (UINT64_C(1) << 6),
            IA64_OP_BR_IA, 0, 6,
        },
        {
            (UINT64_C(0x21) << 27) | (UINT64_C(7) << 13) |
            (UINT64_C(4) << 6) | 0x25,
            IA64_OP_BR_RET, 0x25, 7,
        },
    };
    const uint64_t address = UINT64_C(0x1234567800001300);

    /*
     * Exhaust the complete ignored 11:9 and 26:16 fields independently,
     * cover bit 36 both ways, then cover their all-ones interaction.
     */
    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        IA64DecodedBundle control_bundle = make_bundle(
            0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, cases[i].raw);
        IA64DecodedInstructionBundle control;
        const IA64Instruction *insn;

        g_assert_true(ia64_decode_instruction_bundle(
            &control_bundle, address, true, 0, &control));
        insn = &control.instruction[2];
        g_assert_cmpint(control.status, ==, IA64_DECODE_OK);
        g_assert_cmpint(control.error_slot, ==, -1);
        g_assert_true(insn->valid);
        g_assert_cmpint(insn->opcode, ==, cases[i].opcode);
        g_assert_cmpuint(insn->qp, ==, cases[i].qp);
        g_assert_cmpuint(insn->b2, ==, cases[i].b2);
        g_assert_cmpuint(insn->slot_span, ==, 1);
        g_assert_false(insn->starts_group);
        g_assert_true(insn->stop_after);
        g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);

        for (unsigned ignored = 0; ignored < 8; ignored++) {
            const uint64_t raw = cases[i].raw |
                                 ((uint64_t)ignored << 9);
            IA64DecodedBundle bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
            IA64DecodedInstructionBundle decoded;

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            assert_decoded_metadata_invariant(&decoded, &control, 2, raw);
            assert_ignored_branch_encoding(
                &decoded, raw, address, cases[i].opcode,
                cases[i].qp, 0, cases[i].b2);
        }

        for (unsigned ignored = 0; ignored < (1U << 11); ignored++) {
            const uint64_t raw = cases[i].raw |
                                 ((uint64_t)ignored << 16);
            IA64DecodedBundle bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
            IA64DecodedInstructionBundle decoded;

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            assert_decoded_metadata_invariant(&decoded, &control, 2, raw);
            assert_ignored_branch_encoding(
                &decoded, raw, address, cases[i].opcode,
                cases[i].qp, 0, cases[i].b2);
        }

        for (unsigned ignored = 0; ignored < 2; ignored++) {
            const uint64_t raw = cases[i].raw |
                                 ((uint64_t)ignored << 36);
            IA64DecodedBundle bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
            IA64DecodedInstructionBundle decoded;

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            assert_decoded_metadata_invariant(&decoded, &control, 2, raw);
            assert_ignored_branch_encoding(
                &decoded, raw, address, cases[i].opcode,
                cases[i].qp, 0, cases[i].b2);
        }

        {
            const uint64_t raw = cases[i].raw |
                                 (UINT64_C(7) << 9) |
                                 (UINT64_C(0x7ff) << 16) |
                                 (UINT64_C(1) << 36);
            IA64DecodedBundle bundle = make_bundle(
                0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, raw);
            IA64DecodedInstructionBundle decoded;

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            assert_decoded_metadata_invariant(&decoded, &control, 2, raw);
            assert_ignored_branch_encoding(
                &decoded, raw, address, cases[i].opcode,
                cases[i].qp, 0, cases[i].b2);
        }
    }
}

static void assert_b4_br_ret_metadata(const IA64Instruction *insn,
                                      uint64_t raw, uint64_t address,
                                      unsigned slot, unsigned qp,
                                      unsigned b2, bool starts_group,
                                      bool stop_after)
{
    g_assert_true(insn->valid);
    g_assert_cmpint(insn->opcode, ==, IA64_OP_BR_RET);
    g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_B);
    g_assert_cmphex(insn->raw, ==, raw);
    g_assert_cmphex(insn->address, ==, address);
    g_assert_cmpuint(insn->slot, ==, slot);
    g_assert_cmpuint(insn->qp, ==, qp);
    g_assert_cmpuint(insn->b1, ==, 0);
    g_assert_cmpuint(insn->b2, ==, b2);
    g_assert_cmpuint(insn->slot_span, ==, 1);
    g_assert_cmpint(insn->starts_group, ==, starts_group);
    g_assert_cmpint(insn->stop_after, ==, stop_after);
    g_assert_false(insn->must_start_group);
    g_assert_false(insn->must_end_group);
    g_assert_false(insn->requires_slot2);
    g_assert_cmpuint(insn->placement, ==, IA64_PLACE_NONE);
    g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);
    g_assert_false(insn->placement_illegal);
    g_assert_false(insn->reserved_field);
}

static void test_b4_br_ret_qp_b2_matrix(void)
{
    static const uint64_t ignored_masks[] = {
        UINT64_C(7) << 9,
        UINT64_C(0x7ff) << 16,
        UINT64_C(1) << 36,
        (UINT64_C(7) << 9) |
        (UINT64_C(0x7ff) << 16) |
        (UINT64_C(1) << 36),
    };
    const uint64_t address = UINT64_C(0x1234567800001380);

    /*
     * Cross the complete predicate and target-BR domains.  The exhaustive B4
     * test above closes each ignored field for one br.ret encoding; here one
     * maximal value per field plus their interaction proves that those bits
     * remain metadata-inert for every architectural qp/b2 combination.
     */
    for (unsigned qp = 0; qp < 64; qp++) {
        for (unsigned b2 = 0; b2 < 8; b2++) {
            const uint64_t control_raw = encode_test_b4_br_ret(qp, b2);
            const unsigned slot = (qp + b2) % IA64_SLOT_COUNT;
            IA64Instruction control = ia64_decode_instruction_raw(
                IA64_INSN_UNIT_B, control_raw, address, slot);

            g_assert_true(control.valid);
            g_assert_cmpint(control.opcode, ==, IA64_OP_BR_RET);
            g_assert_cmpint(control.unit, ==, IA64_INSN_UNIT_B);
            g_assert_cmphex(control.raw, ==, control_raw);
            g_assert_cmphex(control.address, ==, address);
            g_assert_cmpuint(control.slot, ==, slot);
            g_assert_cmpuint(control.qp, ==, qp);
            g_assert_cmpuint(control.b1, ==, 0);
            g_assert_cmpuint(control.b2, ==, b2);

            for (size_t i = 0; i < G_N_ELEMENTS(ignored_masks); i++) {
                const uint64_t raw = control_raw | ignored_masks[i];
                IA64Instruction insn = ia64_decode_instruction_raw(
                    IA64_INSN_UNIT_B, raw, address, slot);

                assert_instruction_metadata_invariant(&insn, &control);
                g_assert_cmphex(insn.raw, ==, raw);
            }
        }
    }
}

static void test_b4_br_ret_bundle_placement_matrix(void)
{
    static const struct {
        uint8_t template_code;
        unsigned b_slot_mask;
        bool final_stop;
    } cases[] = {
        { 0x10, 1U << 2, false }, /* MIB  */
        { 0x11, 1U << 2, true  }, /* MIB; */
        { 0x12, (1U << 1) | (1U << 2), false }, /* MBB  */
        { 0x13, (1U << 1) | (1U << 2), true  }, /* MBB; */
        { 0x16, (1U << 0) | (1U << 1) | (1U << 2), false }, /* BBB  */
        { 0x17, (1U << 0) | (1U << 1) | (1U << 2), true  }, /* BBB; */
        { 0x18, 1U << 2, false }, /* MMB  */
        { 0x19, 1U << 2, true  }, /* MMB; */
        { 0x1c, 1U << 2, false }, /* MFB  */
        { 0x1d, 1U << 2, true  }, /* MFB; */
    };
    const uint64_t address = UINT64_C(0x1234567800001390);

    /* br.ret has no slot-2 restriction: cover every B slot in every template. */
    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        const IA64TemplateInfo *info =
            ia64_template_info(cases[i].template_code);
        unsigned actual_b_slot_mask = 0;

        g_assert_true(info->valid);
        g_assert_false(info->long_immediate);
        for (unsigned slot = 0; slot < IA64_SLOT_COUNT; slot++) {
            if (info->slot_type[slot] == IA64_SLOT_TYPE_B) {
                actual_b_slot_mask |= 1U << slot;
            }
        }
        g_assert_cmphex(actual_b_slot_mask, ==, cases[i].b_slot_mask);
        g_assert_false(info->stop_after_slot[0]);
        g_assert_false(info->stop_after_slot[1]);
        g_assert_cmpint(info->stop_after_slot[2], ==, cases[i].final_stop);

        for (unsigned branch_slot = 0; branch_slot < IA64_SLOT_COUNT;
             branch_slot++) {
            uint64_t slots[IA64_SLOT_COUNT];
            IA64DecodedInstructionBundle decoded;
            IA64DecodedBundle bundle;
            uint64_t raw;
            unsigned qp;
            unsigned b2;

            if (!(cases[i].b_slot_mask & (1U << branch_slot))) {
                continue;
            }

            for (unsigned slot = 0; slot < IA64_SLOT_COUNT; slot++) {
                slots[slot] = info->slot_type[slot] == IA64_SLOT_TYPE_B ?
                    IA64_TEST_B_NOP_RAW : IA64_TEST_NOP_RAW;
            }
            qp = (unsigned)(i * 13 + branch_slot) & 0x3f;
            b2 = ((unsigned)i + branch_slot) & 7;
            raw = encode_test_b4_br_ret(qp, b2);
            slots[branch_slot] = raw;
            bundle = make_bundle(cases[i].template_code,
                                 slots[0], slots[1], slots[2]);

            g_assert_true(ia64_decode_instruction_bundle(
                &bundle, address, true, 0, &decoded));
            g_assert_true(decoded.valid_template);
            g_assert_cmpuint(decoded.template_code, ==,
                             cases[i].template_code);
            g_assert_cmpuint(decoded.start_slot, ==, 0);
            g_assert_cmphex(decoded.instruction_mask, ==, 0x7);
            g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
            g_assert_cmpint(decoded.error_slot, ==, -1);
            g_assert_true(decoded.starts_at_group_boundary);
            g_assert_cmpint(decoded.ends_at_group_boundary, ==,
                            cases[i].final_stop);
            assert_b4_br_ret_metadata(
                &decoded.instruction[branch_slot], raw, address,
                branch_slot, qp, b2, branch_slot == 0,
                cases[i].final_stop && branch_slot == 2);
        }
    }
}

static void test_b4_br_ret_unit_placement_gate(void)
{
    const uint64_t address = UINT64_C(0x12345678000013a0);
    const uint64_t raw = encode_test_b4_br_ret(0x2d, 5);

    for (IA64InstructionUnit unit = IA64_INSN_UNIT_RESERVED;
         unit <= IA64_INSN_UNIT_X; unit++) {
        IA64Instruction insn;

        if (unit == IA64_INSN_UNIT_B) {
            continue;
        }
        insn = ia64_decode_instruction_raw(unit, raw, address, 1);
        g_assert_cmpint(insn.opcode, !=, IA64_OP_BR_RET);
        g_assert_cmpint(insn.unit, ==, unit);
        g_assert_cmphex(insn.raw, ==, raw);
        g_assert_cmphex(insn.address, ==, address);
        g_assert_cmpuint(insn.slot, ==, 1);
    }

    /*
     * A B4 bit pattern placed in either non-B slot of MIB must likewise not
     * acquire br.ret semantics through bundle decoding.  There is no illegal
     * B-slot placement to test: the complete legal B-slot set is closed above.
     */
    for (unsigned wrong_slot = 0; wrong_slot < 2; wrong_slot++) {
        uint64_t slots[IA64_SLOT_COUNT] = {
            IA64_TEST_NOP_RAW,
            IA64_TEST_NOP_RAW,
            IA64_TEST_B_NOP_RAW,
        };
        IA64DecodedBundle bundle;
        IA64DecodedInstructionBundle decoded;
        const IA64Instruction *insn;

        slots[wrong_slot] = raw;
        bundle = make_bundle(0x10, slots[0], slots[1], slots[2]);
        g_assert_true(ia64_decode_instruction_bundle(
            &bundle, address, true, 0, &decoded));
        insn = &decoded.instruction[wrong_slot];
        g_assert_cmpint(insn->opcode, !=, IA64_OP_BR_RET);
        g_assert_cmpint(insn->unit, ==,
                        wrong_slot == 0 ? IA64_INSN_UNIT_M :
                        IA64_INSN_UNIT_I);
        g_assert_cmphex(insn->raw, ==, raw);
        g_assert_cmpuint(insn->slot, ==, wrong_slot);
    }
}

static void test_b5_ignored_field_matrix(void)
{
    const uint64_t address = UINT64_C(0x1234567800001400);
    const uint64_t base_raw =
        (UINT64_C(1) << 37) | (UINT64_C(1) << 32) |
        (UINT64_C(5) << 13) | (UINT64_C(3) << 6) | 0x2a;

    /*
     * Every odd wh row is the same indirect call.  Exhaust each complete
     * ignored field independently and also their all-ones interaction.
     */
    for (unsigned wh = 1; wh < 8; wh += 2) {
        const uint64_t control_raw =
            (base_raw & ~(UINT64_C(7) << 32)) | ((uint64_t)wh << 32);
        IA64DecodedBundle control_bundle = make_bundle(
            0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW, control_raw);
        IA64DecodedInstructionBundle control;
        const IA64Instruction *insn;

        g_assert_true(ia64_decode_instruction_bundle(
            &control_bundle, address, true, 0, &control));
        insn = &control.instruction[2];
        g_assert_cmpint(control.status, ==, IA64_DECODE_OK);
        g_assert_cmpint(control.error_slot, ==, -1);
        g_assert_true(insn->valid);
        g_assert_cmpint(insn->opcode, ==, IA64_OP_BR_CALL_INDIRECT);
        g_assert_cmpuint(insn->qp, ==, 0x2a);
        g_assert_cmpuint(insn->b1, ==, 3);
        g_assert_cmpuint(insn->b2, ==, 5);
        g_assert_cmpuint(insn->slot_span, ==, 1);
        g_assert_false(insn->starts_group);
        g_assert_true(insn->stop_after);
        g_assert_cmpint(insn->status, ==, IA64_DECODE_OK);

        for (unsigned ignored = 0; ignored < 8; ignored++) {
            decode_and_assert_b5_call(
                control_raw | ((uint64_t)ignored << 9), address, &control);
        }
        for (unsigned ignored = 0; ignored < (1U << 16); ignored++) {
            decode_and_assert_b5_call(
                control_raw | ((uint64_t)ignored << 16), address, &control);
        }
        for (unsigned ignored = 0; ignored < 2; ignored++) {
            decode_and_assert_b5_call(
                control_raw | ((uint64_t)ignored << 36), address, &control);
        }
        decode_and_assert_b5_call(control_raw |
                                  (UINT64_C(7) << 9) |
                                  (UINT64_C(0xffff) << 16) |
                                  (UINT64_C(1) << 36),
                                  address, &control);
    }

    /* Even wh table rows are architectural no-effect encodings. */
    for (unsigned wh = 0; wh < 8; wh += 2) {
        const uint64_t control_raw =
            (base_raw & ~(UINT64_C(7) << 32)) | ((uint64_t)wh << 32);

        for (unsigned ignored = 0; ignored < 8; ignored++) {
            decode_and_assert_b5_no_effect(
                control_raw | ((uint64_t)ignored << 9), address);
        }
        for (unsigned ignored = 0; ignored < (1U << 16); ignored++) {
            decode_and_assert_b5_no_effect(
                control_raw | ((uint64_t)ignored << 16), address);
        }
        for (unsigned ignored = 0; ignored < 2; ignored++) {
            decode_and_assert_b5_no_effect(
                control_raw | ((uint64_t)ignored << 36), address);
        }
        decode_and_assert_b5_no_effect(control_raw |
                                       (UINT64_C(7) << 9) |
                                       (UINT64_C(0xffff) << 16) |
                                       (UINT64_C(1) << 36),
                                       address);
    }
}

static void test_b1_br_cond_non_b_unit_gate(void)
{
    const uint64_t raw = encode_test_b1_br_cond(-0x10, 0x3f);
    const uint64_t address = UINT64_C(0x1234567800002000);

    for (IA64InstructionUnit unit = IA64_INSN_UNIT_RESERVED;
         unit <= IA64_INSN_UNIT_X; unit++) {
        IA64Instruction insn;

        if (unit == IA64_INSN_UNIT_B) {
            continue;
        }
        insn = ia64_decode_instruction_raw(unit, raw, address, 2);
        g_assert_cmpint(insn.opcode, !=, IA64_OP_BR_COND);
        g_assert_cmpint(insn.unit, ==, unit);
        g_assert_cmphex(insn.raw, ==, raw);
        g_assert_cmphex(insn.address, ==, address);
        g_assert_cmpuint(insn.slot, ==, 2);
    }
}

static void test_x3_brl_cond_boundary_matrix(void)
{
    static const int64_t displacements[] = {
        INT64_MIN,
        -INT64_C(0x10),
        0,
        INT64_C(0x10),
        INT64_MAX - 15,
    };
    const uint64_t address = UINT64_C(0xfedcba9876543200);

    /* Five signed boundaries times complete qp and ignored X[11:9] domains. */
    for (size_t d = 0; d < G_N_ELEMENTS(displacements); d++) {
        for (unsigned qp = 0; qp < 64; qp++) {
            const IA64TestX3BranchEncoding encoding =
                encode_test_x3_brl_cond(displacements[d], qp);
            IA64DecodedBundle control_bundle = make_bundle(
                0x04, IA64_TEST_NOP_RAW,
                encoding.l_raw, encoding.x_raw);
            IA64DecodedInstructionBundle control;

            g_assert_true(ia64_decode_instruction_bundle(
                &control_bundle, address, true, 0, &control));

            for (unsigned ignored = 0; ignored < 8; ignored++) {
                const uint64_t x_raw = encoding.x_raw |
                                       ((uint64_t)ignored << 9);
                IA64DecodedBundle bundle = make_bundle(
                    0x04, IA64_TEST_NOP_RAW, encoding.l_raw, x_raw);
                IA64DecodedInstructionBundle decoded;

                g_assert_true(ia64_decode_instruction_bundle(
                    &bundle, address, true, 0, &decoded));
                assert_decoded_metadata_invariant(
                    &decoded, &control, 1, x_raw);
                g_assert_true(decoded.valid_template);
                g_assert_cmpuint(decoded.template_code, ==, 0x04);
                g_assert_cmpuint(decoded.start_slot, ==, 0);
                g_assert_cmphex(decoded.instruction_mask, ==, 0x3);
                g_assert_cmpint(decoded.error_slot, ==, -1);
                g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
                g_assert_true(decoded.starts_at_group_boundary);
                g_assert_false(decoded.ends_at_group_boundary);
                assert_x3_brl_cond_metadata(
                    &decoded.instruction[1], x_raw, address, qp,
                    displacements[d], false);
            }
        }
    }
}

static void test_x3_brl_cond_stop_policy(void)
{
    static const struct {
        uint8_t template_code;
        bool stop_after;
    } cases[] = {
        { 0x04, false },
        { 0x05, true  },
    };
    const uint64_t address = UINT64_C(0xfedcba9800001000);
    const int64_t displacement = -INT64_C(0x10);
    const unsigned qp = 0x3f;
    const IA64TestX3BranchEncoding encoding =
        encode_test_x3_brl_cond(displacement, qp);

    for (size_t i = 0; i < G_N_ELEMENTS(cases); i++) {
        IA64DecodedBundle bundle = make_bundle(
            cases[i].template_code, IA64_TEST_NOP_RAW,
            encoding.l_raw, encoding.x_raw);
        IA64DecodedInstructionBundle decoded;

        g_assert_true(ia64_decode_instruction_bundle(
            &bundle, address, true, 0, &decoded));
        g_assert_cmpuint(decoded.template_code, ==, cases[i].template_code);
        g_assert_cmphex(decoded.instruction_mask, ==, 0x3);
        g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
        g_assert_cmpint(decoded.error_slot, ==, -1);
        g_assert_cmpint(decoded.ends_at_group_boundary, ==,
                        cases[i].stop_after);
        assert_x3_brl_cond_metadata(
            &decoded.instruction[1], encoding.x_raw, address, qp,
            displacement, cases[i].stop_after);
    }
}

static void test_x3_x4_brl_ignored_fields(void)
{
    static const uint8_t templates[] = { 0x04, 0x05 };
    const uint64_t address = UINT64_C(0xfedcba9800002000);
    const IA64TestX3BranchEncoding x3_encoding =
        encode_test_x3_brl_cond(0x10, 0x35);

    /* X3 ignores L[1:0], including interaction with ignored X[11:9]. */
    for (size_t t = 0; t < G_N_ELEMENTS(templates); t++) {
        IA64DecodedBundle control_bundle = make_bundle(
            templates[t], IA64_TEST_NOP_RAW,
            x3_encoding.l_raw, x3_encoding.x_raw);
        IA64DecodedInstructionBundle control;

        g_assert_true(ia64_decode_instruction_bundle(
            &control_bundle, address, true, 0, &control));

        for (unsigned x_ignored = 0; x_ignored < 8; x_ignored++) {
            for (unsigned l_ignored = 0; l_ignored < 4; l_ignored++) {
                const uint64_t x_raw = x3_encoding.x_raw |
                                       ((uint64_t)x_ignored << 9);
                IA64DecodedBundle bundle = make_bundle(
                    templates[t], IA64_TEST_NOP_RAW,
                    x3_encoding.l_raw | l_ignored, x_raw);
                IA64DecodedInstructionBundle decoded;

                g_assert_true(ia64_decode_instruction_bundle(
                    &bundle, address, true, 0, &decoded));
                assert_decoded_metadata_invariant(
                    &decoded, &control, 1, x_raw);
                g_assert_true(decoded.valid_template);
                g_assert_cmpuint(decoded.template_code, ==, templates[t]);
                g_assert_cmphex(decoded.instruction_mask, ==, 0x3);
                g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
                g_assert_cmpint(decoded.error_slot, ==, -1);
                g_assert_cmpint(decoded.ends_at_group_boundary, ==,
                                templates[t] == 0x05);
                assert_x3_brl_cond_metadata(
                    &decoded.instruction[1], x_raw, address,
                    0x35, 0x10, templates[t] == 0x05);
            }
        }
    }

    /* X4 has the same ignored fields; exhaust qp and return BR as well. */
    for (size_t t = 0; t < G_N_ELEMENTS(templates); t++) {
        for (unsigned qp = 0; qp < 64; qp++) {
            for (unsigned b1 = 0; b1 < 8; b1++) {
                const IA64TestX3BranchEncoding control_encoding =
                    encode_test_x4_brl_call(-INT64_C(0x123450), qp, b1);
                IA64DecodedBundle control_bundle = make_bundle(
                    templates[t], IA64_TEST_NOP_RAW,
                    control_encoding.l_raw, control_encoding.x_raw);
                IA64DecodedInstructionBundle control;

                g_assert_true(ia64_decode_instruction_bundle(
                    &control_bundle, address, true, 0, &control));

                for (unsigned x_ignored = 0; x_ignored < 8;
                     x_ignored++) {
                    for (unsigned l_ignored = 0; l_ignored < 4;
                         l_ignored++) {
                        const uint64_t x_raw = control_encoding.x_raw |
                            ((uint64_t)x_ignored << 9);
                        IA64DecodedBundle bundle = make_bundle(
                            templates[t], IA64_TEST_NOP_RAW,
                            control_encoding.l_raw | l_ignored, x_raw);
                        IA64DecodedInstructionBundle decoded;

                        g_assert_true(ia64_decode_instruction_bundle(
                            &bundle, address, true, 0, &decoded));
                        assert_decoded_metadata_invariant(
                            &decoded, &control, 1, x_raw);
                        assert_x4_brl_call_metadata(
                            &decoded.instruction[1], x_raw, address,
                            qp, b1, -INT64_C(0x123450),
                            templates[t] == 0x05);
                    }
                }
            }
        }
    }
}

static void test_x3_brl_cond_restart_rejects_x_half(void)
{
    static const uint8_t templates[] = { 0x04, 0x05 };
    const uint64_t address = UINT64_C(0xfedcba9800003000);
    const int64_t displacement = -INT64_C(0x123450);
    const unsigned qp = 0x3d;
    const IA64TestX3BranchEncoding encoding =
        encode_test_x3_brl_cond(displacement, qp);

    for (size_t t = 0; t < G_N_ELEMENTS(templates); t++) {
        IA64DecodedBundle bundle = make_bundle(
            templates[t], IA64_TEST_NOP_RAW,
            encoding.l_raw, encoding.x_raw);
        IA64DecodedInstructionBundle decoded;
        const IA64Instruction *insn;

        g_assert_true(ia64_decode_instruction_bundle(
            &bundle, address, true, 2, &decoded));
        insn = &decoded.instruction[1];

        g_assert_true(decoded.valid_template);
        g_assert_cmpuint(decoded.template_code, ==, templates[t]);
        g_assert_cmpuint(decoded.start_slot, ==, 2);
        g_assert_cmphex(decoded.instruction_mask, ==, 0x3);
        g_assert_cmpint(decoded.status, ==,
                        IA64_DECODE_ILLEGAL_PLACEMENT);
        g_assert_cmpint(decoded.error_slot, ==, 1);

        /* The encoding is valid; only RI=2 entry into its X half is illegal. */
        g_assert_true(insn->valid);
        g_assert_cmpint(insn->opcode, ==, IA64_OP_BRL_COND);
        g_assert_cmpint(insn->unit, ==, IA64_INSN_UNIT_X);
        g_assert_cmphex(insn->raw, ==, encoding.x_raw);
        g_assert_cmphex(insn->address, ==, address);
        g_assert_cmpuint(insn->slot, ==, 1);
        g_assert_cmpuint(insn->qp, ==, qp);
        g_assert_cmpint(insn->imm, ==, displacement);
        g_assert_cmpuint(insn->slot_span, ==, 2);
        g_assert_cmpuint(insn->placement, ==, IA64_PLACE_LONG_PAIR);
        g_assert_false(insn->starts_group);
        g_assert_cmpint(insn->stop_after, ==, templates[t] == 0x05);
        g_assert_cmpint(insn->status, ==,
                        IA64_DECODE_ILLEGAL_PLACEMENT);
        g_assert_true(insn->placement_illegal);
        g_assert_false(insn->reserved_field);
    }
}

static void test_b3_call_ignored_field_matrix(void)
{
    static const int64_t displacements[] = {
        -INT64_C(0x1000000),
        -INT64_C(0x10),
        0,
        INT64_C(0x10),
        INT64_C(0x0fffff0),
    };
    const uint64_t address = UINT64_C(0x1234567800001500);

    /* Complete B3 qp, b1, and ignored 11:9 domains at signed boundaries. */
    for (size_t d = 0; d < G_N_ELEMENTS(displacements); d++) {
        for (unsigned qp = 0; qp < 64; qp++) {
            for (unsigned b1 = 0; b1 < 8; b1++) {
                const uint64_t control_raw = encode_test_b3_br_call(
                    displacements[d], qp, b1);
                IA64DecodedBundle control_bundle = make_bundle(
                    0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW,
                    control_raw);
                IA64DecodedInstructionBundle control;

                g_assert_true(ia64_decode_instruction_bundle(
                    &control_bundle, address, true, 0, &control));

                for (unsigned ignored = 0; ignored < 8; ignored++) {
                    const uint64_t raw = control_raw |
                                         ((uint64_t)ignored << 9);
                    IA64DecodedBundle bundle = make_bundle(
                        0x17, IA64_TEST_B_NOP_RAW, IA64_TEST_B_NOP_RAW,
                        raw);
                    IA64DecodedInstructionBundle decoded;
                    const IA64Instruction *insn;

                    g_assert_true(ia64_decode_instruction_bundle(
                        &bundle, address, true, 0, &decoded));
                    insn = &decoded.instruction[2];
                    assert_decoded_metadata_invariant(
                        &decoded, &control, 2, raw);
                    assert_ignored_branch_encoding(
                        &decoded, raw, address, IA64_OP_BR_CALL,
                        qp, b1, 0);
                    g_assert_cmpint(insn->imm, ==, displacements[d]);
                }
            }
        }
    }

    /* Raw decoding remains architecture-only, independent of TCG policy. */
    {
        const uint64_t br_cond = UINT64_C(0x0800001a006);
        IA64Instruction insn =
            ia64_decode_instruction_raw(IA64_INSN_UNIT_B, br_cond,
                                        0x1036da0, 2);

        g_assert_true(insn.valid);
        g_assert_cmpint(insn.opcode, ==, IA64_OP_BR_COND);
        g_assert_cmpint(insn.imm, ==, 208);
        g_assert_cmpuint(insn.qp, ==, 6);
        g_assert_cmpuint(insn.slot, ==, 2);
    }
}

static void test_mlx_movl_is_one_typed_instruction(void)
{
    const uint64_t l_raw = UINT64_C(0x1ffffffffff);
    const uint64_t x_raw = UINT64_C(0x0d807000900);
    IA64DecodedBundle bundle =
        make_bundle(0x05, IA64_TEST_NOP_RAW, l_raw, x_raw);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(&bundle, 0x2000, true, 0,
                                                 &decoded));
    g_assert_true(decoded.valid_template);
    g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
    g_assert_cmphex(decoded.instruction_mask, ==, 0x3);
    g_assert_cmpint(decoded.instruction[1].opcode, ==, IA64_OP_MOVL);
    g_assert_cmpuint(decoded.instruction[1].slot, ==, 1);
    g_assert_cmpuint(decoded.instruction[1].slot_span, ==, 2);
    g_assert_true(decoded.instruction[1].placement & IA64_PLACE_LONG_PAIR);
    g_assert_cmpuint(decoded.instruction[1].r1, ==, 36);
    g_assert_cmphex((uint64_t)decoded.instruction[1].imm,
                    ==, UINT64_C(0xffffffffffdc8000));
    g_assert_true(decoded.ends_at_group_boundary);
}

static void test_reserved_template_has_precise_status(void)
{
    IA64DecodedBundle bundle = make_bundle(0x06, 1, 2, 3);
    IA64DecodedInstructionBundle decoded;

    g_assert_false(ia64_decode_instruction_bundle(&bundle, 0x3000, true, 0,
                                                  &decoded));
    g_assert_false(decoded.valid_template);
    g_assert_cmpint(decoded.status, ==, IA64_DECODE_RESERVED_TEMPLATE);
    g_assert_cmpstr(ia64_decode_status_name(decoded.status), ==,
                    "reserved-template");
}

static void test_alloc_group_placement_is_reported(void)
{
    const uint64_t alloc_r34 =
        (UINT64_C(1) << 37) | (UINT64_C(6) << 33) |
        (UINT64_C(34) << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, alloc_r34,
                    IA64_TEST_NOP_RAW, IA64_TEST_NOP_RAW);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(&bundle, 0x4000, false, 0,
                                                 &decoded));
    g_assert_cmpint(decoded.instruction[0].opcode, ==, IA64_OP_ALLOC);
    g_assert_true(decoded.instruction[0].must_start_group);
    g_assert_true(decoded.instruction[0].placement_illegal);
    g_assert_cmpint(decoded.instruction[0].status,
                    ==, IA64_DECODE_ILLEGAL_PLACEMENT);
    g_assert_cmpint(decoded.error_slot, ==, 0);
}

static void test_reserved_unit_is_not_an_execution_fallback(void)
{
    IA64Instruction insn =
        ia64_decode_instruction_raw(IA64_INSN_UNIT_RESERVED, 0,
                                    0x5000, 0);

    g_assert_false(insn.valid);
    g_assert_cmpint(insn.opcode, ==, IA64_OP_ILLEGAL);
}

static void test_restart_suffix_ignores_skipped_placement(void)
{
    const uint64_t alloc_r34 =
        (UINT64_C(1) << 37) | (UINT64_C(6) << 33) |
        (UINT64_C(34) << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, alloc_r34,
                    IA64_TEST_NOP_RAW, IA64_TEST_NOP_RAW);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(&bundle, 0x6000, false, 1,
                                                 &decoded));
    g_assert_cmpuint(decoded.start_slot, ==, 1);
    g_assert_cmpint(decoded.status, ==, IA64_DECODE_OK);
    g_assert_cmpint(decoded.error_slot, ==, -1);
}

static void test_restart_cannot_enter_mlx_x_half(void)
{
    const uint64_t l_raw = UINT64_C(0x1ffffffffff);
    const uint64_t x_raw = UINT64_C(0x0d807000900);
    IA64DecodedBundle bundle =
        make_bundle(0x05, IA64_TEST_NOP_RAW, l_raw, x_raw);
    IA64DecodedInstructionBundle decoded;

    g_assert_true(ia64_decode_instruction_bundle(&bundle, 0x7000, true, 2,
                                                 &decoded));
    g_assert_cmpint(decoded.status, ==, IA64_DECODE_ILLEGAL_PLACEMENT);
    g_assert_cmpint(decoded.error_slot, ==, 1);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-decode/unit-mapping", test_unit_mapping_is_total);
    g_test_add_func("/ia64-decode/core-integer-fields",
                    test_core_integer_fields);
    g_test_add_func("/ia64-decode/psr-ic-serialization",
                    test_psr_ic_serialization_decode);
    g_test_add_func("/ia64-decode/m24-serialization-reserved-fields",
                    test_m24_serialization_reserved_fields);
    g_test_add_func("/ia64-decode/i25-mov-from-predicates",
                    test_i25_mov_from_predicates);
    g_test_add_func("/ia64-decode/i23-mov-to-predicates",
                    test_i23_mov_to_predicates);
    g_test_add_func("/ia64-decode/i24-mov-to-rotating-predicates",
                    test_i24_mov_to_rotating_predicates);
    g_test_add_func("/ia64-decode/integer-compare-matrix",
                    test_integer_compare_matrix);
    g_test_add_func("/ia64-decode/a7-reserved-r2-matrix",
                    test_a7_compare_reserved_r2_matrix);
    g_test_add_func("/ia64-decode/integer-compare-unit-gate",
                    test_integer_compare_unit_gate);
    g_test_add_func("/ia64-decode/tbit-matrix",
                    test_tbit_decode_matrix);
    g_test_add_func("/ia64-decode/tnat-matrix",
                    test_tnat_decode_matrix);
    g_test_add_func("/ia64-decode/tf-matrix",
                    test_tf_decode_matrix);
    g_test_add_func("/ia64-decode/predicate-test-unit-gate",
                    test_predicate_test_unit_gate);
    g_test_add_func("/ia64-decode/predicate-test-reserved-encodings",
                    test_predicate_test_reserved_encodings);
    g_test_add_func("/ia64-decode/reserved-a3-patterns",
                    test_reserved_a3_patterns_stay_illegal);
    g_test_add_func("/ia64-decode/immediate-shift-canonicalization",
                    test_immediate_shifts_are_canonical_bitfields);
    g_test_add_func("/ia64-decode/b1-br-cond-boundary-matrix",
                    test_b1_br_cond_boundary_matrix);
    g_test_add_func("/ia64-decode/b1-br-cond-btype-rejection",
                    test_b1_br_cond_btype_rejection);
    g_test_add_func("/ia64-decode/b1-while-branch-qp-matrix",
                    test_b1_while_branch_qp_matrix);
    g_test_add_func("/ia64-decode/b2-counted-branch-qp-matrix",
                    test_b2_counted_branch_qp_matrix);
    g_test_add_func("/ia64-decode/b4-ignored-field-matrix",
                    test_b4_ignored_field_matrix);
    g_test_add_func("/ia64-decode/b4-br-ret-qp-b2-matrix",
                    test_b4_br_ret_qp_b2_matrix);
    g_test_add_func("/ia64-decode/b4-br-ret-bundle-placement-matrix",
                    test_b4_br_ret_bundle_placement_matrix);
    g_test_add_func("/ia64-decode/b4-br-ret-unit-placement-gate",
                    test_b4_br_ret_unit_placement_gate);
    g_test_add_func("/ia64-decode/b5-ignored-field-matrix",
                    test_b5_ignored_field_matrix);
    g_test_add_func("/ia64-decode/b1-br-cond-non-b-unit-gate",
                    test_b1_br_cond_non_b_unit_gate);
    g_test_add_func("/ia64-decode/x3-brl-cond-boundary-matrix",
                    test_x3_brl_cond_boundary_matrix);
    g_test_add_func("/ia64-decode/x3-brl-cond-stop-policy",
                    test_x3_brl_cond_stop_policy);
    g_test_add_func("/ia64-decode/x3-x4-brl-ignored-fields",
                    test_x3_x4_brl_ignored_fields);
    g_test_add_func("/ia64-decode/x3-brl-cond-restart-x-half",
                    test_x3_brl_cond_restart_rejects_x_half);
    g_test_add_func("/ia64-decode/b3-call-ignored-field-matrix",
                    test_b3_call_ignored_field_matrix);
    g_test_add_func("/ia64-decode/mlx-movl",
                    test_mlx_movl_is_one_typed_instruction);
    g_test_add_func("/ia64-decode/reserved-template",
                    test_reserved_template_has_precise_status);
    g_test_add_func("/ia64-decode/alloc-placement",
                    test_alloc_group_placement_is_reported);
    g_test_add_func("/ia64-decode/reserved-unit",
                    test_reserved_unit_is_not_an_execution_fallback);
    g_test_add_func("/ia64-decode/restart-suffix-placement",
                    test_restart_suffix_ignores_skipped_placement);
    g_test_add_func("/ia64-decode/restart-mlx-x-half",
                    test_restart_cannot_enter_mlx_x_half);

    return g_test_run();
}
