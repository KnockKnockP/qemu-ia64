/*
 * IA-64 TCG skeleton boundary-policy tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "target/ia64/exec-smoke.h"
#include "target/ia64/perf.h"
#include "target/ia64/tcg-skeleton.h"
#include "tcg/tcg.h"

enum {
    IA64_TEST_EFI_SERVICE_DESCRIPTOR_COUNT =
        VIBTANIUM_EFI_BOOT_SERVICE_COUNT +
        VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT +
        VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT +
        VIBTANIUM_EFI_CON_IN_SERVICE_COUNT +
        VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT +
        VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT +
        VIBTANIUM_EFI_FILE_SERVICE_COUNT,
};

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

static void assert_boundary(IA64TcgTbBoundary expected,
                            const IA64DecodedBundle *bundle,
                            uint64_t pc)
{
    IA64TcgTbBoundary actual =
        ia64_tcg_tb_boundary_for_bundle(bundle, pc);

    g_assert_cmpint(actual, ==, expected);
    g_assert_cmpint(ia64_tcg_tb_boundary_ends_tb(actual),
                    ==, expected != IA64_TCG_TB_BOUNDARY_NONE);
    g_assert_cmpstr(ia64_tcg_tb_boundary_name(actual), !=, "unknown");
}

typedef struct IA64HelperFlagInfo {
    const char *name;
    unsigned flags;
} IA64HelperFlagInfo;

static const IA64HelperFlagInfo helper_flag_info[] = {
#define DEF_HELPER_0(name, ret) { #name, 0 },
#define DEF_HELPER_1(name, ret, t1) { #name, 0 },
#define DEF_HELPER_2(name, ret, t1, t2) { #name, 0 },
#define DEF_HELPER_3(name, ret, t1, t2, t3) { #name, 0 },
#define DEF_HELPER_4(name, ret, t1, t2, t3, t4) { #name, 0 },
#define DEF_HELPER_5(name, ret, t1, t2, t3, t4, t5) { #name, 0 },
#define DEF_HELPER_6(name, ret, t1, t2, t3, t4, t5, t6) { #name, 0 },
#define DEF_HELPER_FLAGS_0(name, flags, ret) { #name, flags },
#define DEF_HELPER_FLAGS_1(name, flags, ret, t1) { #name, flags },
#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) { #name, flags },
#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3) { #name, flags },
#define DEF_HELPER_FLAGS_4(name, flags, ret, t1, t2, t3, t4) { #name, flags },
#define DEF_HELPER_FLAGS_5(name, flags, ret, t1, t2, t3, t4, t5) \
    { #name, flags },
#define DEF_HELPER_FLAGS_6(name, flags, ret, t1, t2, t3, t4, t5, t6) \
    { #name, flags },
#include "target/ia64/helper.h"
#undef DEF_HELPER_FLAGS_6
#undef DEF_HELPER_FLAGS_5
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_6
#undef DEF_HELPER_5
#undef DEF_HELPER_4
#undef DEF_HELPER_3
#undef DEF_HELPER_2
#undef DEF_HELPER_1
#undef DEF_HELPER_0
};

static unsigned helper_flags_for(const char *name)
{
    for (unsigned i = 0; i < ARRAY_SIZE(helper_flag_info); i++) {
        if (g_str_equal(helper_flag_info[i].name, name)) {
            return helper_flag_info[i].flags;
        }
    }

    g_assert_not_reached();
}

static void test_helper_flags_are_conservative(void)
{
    g_assert_cmphex(helper_flags_for("exec_bundle"), ==, 0);
    g_assert_cmphex(helper_flags_for("firmware_call_gate"), ==, 0);
    g_assert_cmphex(helper_flags_for("start_fast_bundle"), ==, 0);
    g_assert_cmphex(helper_flags_for("finish_fast_bundle"), ==, 0);
    g_assert_cmphex(helper_flags_for("finish_fast_store"), ==, 0);
    g_assert_cmphex(helper_flags_for("finish_direct_branch_bundle"), ==, 0);

    g_assert_cmphex(helper_flags_for("perf_direct_branch_fallback"),
                    ==, TCG_CALL_NO_RWG);
    g_assert_cmphex(helper_flags_for("perf_tcg_ldst_fallback"),
                    ==, TCG_CALL_NO_RWG);
    g_assert_cmphex(helper_flags_for("perf_tb_exit_chained"),
                    ==, TCG_CALL_NO_RWG);
    g_assert_cmphex(helper_flags_for("perf_tb_exit_main_loop"),
                    ==, TCG_CALL_NO_RWG);
    g_assert_cmphex(helper_flags_for("perf_tb_exec"), ==, TCG_CALL_NO_RWG);
}

static void test_fallthrough_bundle_does_not_end_tb(void)
{
    IA64DecodedBundle bundle = make_bundle(0x16, 0, 0, 0);

    assert_boundary(IA64_TCG_TB_BOUNDARY_NONE, &bundle, 0x1000);
}

static void test_invalid_template_ends_tb(void)
{
    IA64DecodedBundle bundle = make_bundle(0x06, 1, 2, 3);

    assert_boundary(IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE, &bundle, 0x1000);
}

static void test_efi_call_gate_ends_tb(void)
{
    IA64DecodedBundle bundle = make_bundle(0x16, 0, 0, 0);
    uint64_t region4_pal_alias = UINT64_C(0x4000000000000000) |
                                 VIBTANIUM_EFI_PAL_PROC;
    uint64_t region4_service_alias = UINT64_C(0x4000000000000000) |
                                     VIBTANIUM_EFI_CALL_GATE_BASE;
    uint64_t region7_pal_alias = UINT64_C(0xe000000000000000) |
                                 VIBTANIUM_EFI_PAL_PROC;
    uint64_t region7_service_alias = UINT64_C(0xe000000000000000) |
                                     VIBTANIUM_EFI_CALL_GATE_BASE;
    uint64_t last_service_gate =
        VIBTANIUM_EFI_CALL_GATE_BASE +
        (IA64_TEST_EFI_SERVICE_DESCRIPTOR_COUNT - 1) * IA64_BUNDLE_SIZE;
    uint64_t after_last_service_gate = last_service_gate + IA64_BUNDLE_SIZE;

    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, VIBTANIUM_EFI_PAL_PROC);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, VIBTANIUM_EFI_SAL_PROC);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, VIBTANIUM_EFI_CALL_GATE_BASE);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, last_service_gate);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, region7_pal_alias);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, region7_service_alias);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(
                        &bundle, VIBTANIUM_EFI_PAL_PROC),
                    ==, IA64_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE);
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(
        VIBTANIUM_EFI_CALL_GATE_BASE - IA64_BUNDLE_SIZE));
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(
        VIBTANIUM_EFI_CALL_GATE_BASE + 1));
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(after_last_service_gate));
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(region4_pal_alias));
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(region4_service_alias));
    assert_boundary(IA64_TCG_TB_BOUNDARY_NONE, &bundle, region4_pal_alias);
    assert_boundary(IA64_TCG_TB_BOUNDARY_NONE, &bundle, region4_service_alias);
}

static void test_break_and_branch_end_tb(void)
{
    const uint64_t break_i_syscall_raw = 0x01000000000ULL;
    const uint64_t break_m_raw = 0;
    const uint64_t br_cond_raw = 0x0800001a006ULL;
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    IA64DecodedBundle bundle;

    bundle = make_bundle(0x00, 0, break_i_syscall_raw, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_BREAK, &bundle, 0x1000);

    bundle = make_bundle(0x10, break_m_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_BREAK, &bundle, 0x1000);

    bundle = make_bundle(0x16, br_cond_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_BRANCH, &bundle, 0x1000);

    bundle = make_bundle(0x16, br_ret_b0_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_BRANCH, &bundle, 0x1000);
}

static void test_state_changing_slots_end_tb(void)
{
    const uint64_t chk_s_m_r22_raw = 0x0220002c140ULL;
    const uint64_t kernel_rsm_0x6000_raw = 0x00038180000ULL;
    const uint64_t mov_rr_r41_r40_raw =
        (1ULL << 37) | (40ULL << 13) | (41ULL << 20);
    const uint64_t kernel_itr_i_r16_r18_raw = 0x02079024000ULL;
    const uint64_t kernel_tpa_r3_r2_raw =
        (1ULL << 37) | (0x1aULL << 27) | (2ULL << 20) | (3ULL << 6);
    const uint64_t kernel_invala_raw = 0x00080000000ULL;
    const uint64_t kernel_loadrs_raw = 0x00050000000ULL;
    IA64DecodedBundle bundle;

    bundle = make_bundle(0x00, chk_s_m_r22_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK, &bundle, 0x1000);

    bundle = make_bundle(0x00, kernel_rsm_0x6000_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_CPU_STATE, &bundle, 0x1000);

    bundle = make_bundle(0x00, mov_rr_r41_r40_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE, &bundle, 0x1000);

    bundle = make_bundle(0x00, kernel_itr_i_r16_r18_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE, &bundle, 0x1000);

    bundle = make_bundle(0x00, kernel_tpa_r3_r2_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION, &bundle, 0x1000);

    bundle = make_bundle(0x00, kernel_invala_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE, &bundle, 0x1000);

    bundle = make_bundle(0x00, kernel_loadrs_raw, 0, 0);
    assert_boundary(IA64_TCG_TB_BOUNDARY_RSE_STATE, &bundle, 0x1000);
}

static void test_fast_bundle_accepts_hot_integer_subset(void)
{
    const uint64_t addl_r8_0_r0_raw = 0x12000000200ULL;
    const uint64_t add_r1_r2_r3_raw =
        (8ULL << 37) | (3ULL << 20) | (2ULL << 13) | (1ULL << 6);
    const uint64_t and_r4_r4_r5_raw =
        (8ULL << 37) | (3ULL << 29) | (5ULL << 20) |
        (4ULL << 13) | (4ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, addl_r8_0_r0_raw,
                    add_r1_r2_r3_raw, and_r4_r4_r5_raw);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpuint(fast.slot_count, ==, IA64_SLOT_COUNT);
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_ADDL);
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_ALU_ADD);
    g_assert_cmpint(fast.slot[2].op, ==, IA64_TCG_FAST_OP_ALU_LOGIC);
    g_assert_cmphex(fast.source_nat_mask, ==,
                    (1ULL << 2) | (1ULL << 3) |
                    (1ULL << 4) | (1ULL << 5));
    g_assert_cmphex(fast.dest_mask, ==,
                    (1ULL << 1) | (1ULL << 4) | (1ULL << 8));
    g_assert_cmpuint(ia64_perf_fast_count(fast.op_counts,
                                          IA64_PERF_FAST_COUNT_ALU_ADD_SHIFT),
                     ==, 1);
    g_assert_cmpuint(ia64_perf_fast_count(fast.op_counts,
                                          IA64_PERF_FAST_COUNT_ALU_LOGIC_SHIFT),
                     ==, 1);
    g_assert_cmpuint(ia64_perf_fast_count(fast.op_counts,
                                          IA64_PERF_FAST_COUNT_ADDL_SHIFT),
                     ==, 1);
}

static void test_fast_bundle_accepts_nop_and_add_immediate(void)
{
    const uint64_t adds_r6_minus1_r7_raw =
        (8ULL << 37) | (1ULL << 36) | (2ULL << 34) |
        (0x3fULL << 27) | (7ULL << 20) | (0x7fULL << 13) |
        (6ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                    adds_r6_minus1_r7_raw, IA64_SMOKE_NOP_RAW);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_NOP);
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_ALU_ADD);
    g_assert_true(fast.slot[1].source2_immediate);
    g_assert_cmpint(fast.slot[1].immediate, ==, -1);
    g_assert_cmpint(fast.slot[2].op, ==, IA64_TCG_FAST_OP_NOP);
    g_assert_cmphex(fast.source_nat_mask, ==, 1ULL << 7);
    g_assert_cmphex(fast.dest_mask, ==, 1ULL << 6);
    g_assert_cmpuint(ia64_perf_fast_count(fast.op_counts,
                                          IA64_PERF_FAST_COUNT_NOP_SHIFT),
                     ==, 2);
}

static void test_fast_bundle_accepts_banked_static_gr(void)
{
    const uint64_t add_r17_r18_r19_raw =
        (8ULL << 37) | (19ULL << 20) | (18ULL << 13) | (17ULL << 6);
    const uint64_t and_r20_r20_r21_raw =
        (8ULL << 37) | (3ULL << 29) | (21ULL << 20) |
        (20ULL << 13) | (20ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, add_r17_r18_r19_raw,
                    and_r20_r20_r21_raw, IA64_SMOKE_NOP_RAW);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_ALU_ADD);
    g_assert_cmpuint(fast.slot[0].target, ==, 17);
    g_assert_cmpuint(fast.slot[0].source2, ==, 18);
    g_assert_cmpuint(fast.slot[0].source3, ==, 19);
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_ALU_LOGIC);
    g_assert_cmpuint(fast.slot[1].target, ==, 20);
    g_assert_cmpuint(fast.slot[1].source2, ==, 20);
    g_assert_cmpuint(fast.slot[1].source3, ==, 21);
    g_assert_cmphex(fast.source_nat_mask, ==,
                    (1ULL << 18) | (1ULL << 19) |
                    (1ULL << 20) | (1ULL << 21));
    g_assert_cmphex(fast.dest_mask, ==, (1ULL << 17) | (1ULL << 20));
}

static uint64_t make_cmp_eq_parallel_p6_p7_r20_r21(uint8_t major)
{
    return ((uint64_t)major << 37) | (1ULL << 33) | (7ULL << 27) |
           (21ULL << 20) | (20ULL << 13) | (6ULL << 6);
}

static void test_fast_bundle_accepts_compare_predicate_writes(void)
{
    const uint64_t cmp_eq_p6_p0_0_r16_raw = 0x1c801000180ULL;
    IA64DecodedBundle bundle =
        make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                    cmp_eq_p6_p0_0_r16_raw, IA64_SMOKE_NOP_RAW);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_COMPARE);
    g_assert_cmpuint(fast.slot[1].predicate1, ==, 6);
    g_assert_cmpuint(fast.slot[1].predicate2, ==, 0);
    g_assert_cmpint(fast.slot[1].compare_relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(fast.slot[1].predicate_write_kind, ==,
                    IA64_PRED_WRITE_NORMAL);
    g_assert_true(fast.slot[1].source2_immediate);
    g_assert_cmpint(fast.slot[1].immediate, ==, 0);
    g_assert_cmpuint(fast.slot[1].source3, ==, 16);
    g_assert_cmphex(fast.source_nat_mask, ==, 1ULL << 16);
    g_assert_cmpuint(ia64_perf_fast_count(fast.op_counts,
                                          IA64_PERF_FAST_COUNT_COMPARE_SHIFT),
                     ==, 1);

    bundle = make_bundle(0x00, make_cmp_eq_parallel_p6_p7_r20_r21(0xd),
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_COMPARE);
    g_assert_cmpuint(fast.slot[0].predicate1, ==, 6);
    g_assert_cmpuint(fast.slot[0].predicate2, ==, 7);
    g_assert_cmpint(fast.slot[0].predicate_write_kind, ==, IA64_PRED_WRITE_OR);
    g_assert_false(fast.slot[0].source2_immediate);
    g_assert_cmpuint(fast.slot[0].source2, ==, 20);
    g_assert_cmpuint(fast.slot[0].source3, ==, 21);
    g_assert_cmphex(fast.source_nat_mask, ==, (1ULL << 20) | (1ULL << 21));
}

static uint64_t make_extract_raw(bool sign_extend, uint8_t target,
                                 uint8_t source3, uint8_t position,
                                 uint8_t length)
{
    return (5ULL << 37) | (1ULL << 34) |
           ((uint64_t)(length - 1) << 27) |
           ((uint64_t)source3 << 20) |
           ((uint64_t)position << 14) |
           ((uint64_t)sign_extend << 13) |
           ((uint64_t)target << 6);
}

static void test_fast_bundle_accepts_integer_misc(void)
{
    const uint64_t addp4_r16_r17_r18_raw =
        (8ULL << 37) | (2ULL << 29) | (18ULL << 20) |
        (17ULL << 13) | (16ULL << 6);
    const uint64_t sub_r19_r19_r20_raw = 0x100294264c0ULL;
    const uint64_t zxt1_r8_r8_raw = 0x00080800200ULL;
    IA64DecodedBundle bundle =
        make_bundle(0x00, addp4_r16_r17_r18_raw,
                    sub_r19_r19_r20_raw, zxt1_r8_r8_raw);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_ALU_ADDP4);
    g_assert_cmpuint(fast.slot[0].target, ==, 16);
    g_assert_cmpuint(fast.slot[0].source2, ==, 17);
    g_assert_cmpuint(fast.slot[0].source3, ==, 18);
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_ALU_SUB);
    g_assert_cmpuint(fast.slot[1].target, ==, 19);
    g_assert_cmpuint(fast.slot[1].source2, ==, 19);
    g_assert_cmpuint(fast.slot[1].source3, ==, 20);
    g_assert_cmpint(fast.slot[2].op, ==, IA64_TCG_FAST_OP_INTEGER_EXTEND);
    g_assert_cmpint(fast.slot[2].integer_extend_kind, ==, IA64_EXT_ZXT);
    g_assert_cmpuint(fast.slot[2].width, ==, 1);
    g_assert_cmphex(fast.source_nat_mask, ==,
                    (1ULL << 8) | (1ULL << 17) |
                    (1ULL << 18) | (1ULL << 19) |
                    (1ULL << 20));
    g_assert_cmphex(fast.dest_mask, ==,
                    (1ULL << 8) | (1ULL << 16) | (1ULL << 19));
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT), ==, 3);
}

static void test_fast_bundle_accepts_shift_misc(void)
{
    const uint64_t linux_popcnt_r8_r8_raw = 0x0e690800200ULL;
    const uint64_t shr_u_r10_r12_r11_raw =
        (7ULL << 37) | (1ULL << 36) | (1ULL << 33) |
        (12ULL << 20) | (11ULL << 13) | (10ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                    linux_popcnt_r8_r8_raw, shr_u_r10_r12_r11_raw);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_BIT_COUNT);
    g_assert_cmpuint(fast.slot[1].target, ==, 8);
    g_assert_cmpuint(fast.slot[1].source3, ==, 8);
    g_assert_cmpuint(fast.slot[1].shift_kind, ==, 2);
    g_assert_cmpint(fast.slot[2].op, ==, IA64_TCG_FAST_OP_VARIABLE_SHIFT);
    g_assert_cmpuint(fast.slot[2].target, ==, 10);
    g_assert_cmpuint(fast.slot[2].source2, ==, 11);
    g_assert_cmpuint(fast.slot[2].source3, ==, 12);
    g_assert_cmpuint(fast.slot[2].shift_kind, ==,
                     IA64_TCG_FAST_SHIFT_RIGHT_UNSIGNED);
    g_assert_cmphex(fast.source_nat_mask, ==,
                    (1ULL << 8) | (1ULL << 11) | (1ULL << 12));
    g_assert_cmphex(fast.dest_mask, ==, (1ULL << 8) | (1ULL << 10));
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT), ==, 2);
}

static void test_fast_bundle_accepts_bitfield_misc(void)
{
    const uint64_t extract_r9_r2_25_39_raw =
        make_extract_raw(false, 9, 2, 25, 39);
    const uint64_t dep_z_r15_r15_8_56_raw = 0x0a7bb71e3c0ULL;
    IA64DecodedBundle bundle =
        make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                    extract_r9_r2_25_39_raw, dep_z_r15_r15_8_56_raw);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_EXTRACT);
    g_assert_cmpuint(fast.slot[1].target, ==, 9);
    g_assert_cmpuint(fast.slot[1].source3, ==, 2);
    g_assert_cmpuint(fast.slot[1].position, ==, 25);
    g_assert_cmpuint(fast.slot[1].length, ==, 39);
    g_assert_false(fast.slot[1].sign_extend);
    g_assert_cmpint(fast.slot[2].op, ==, IA64_TCG_FAST_OP_DEPOSIT);
    g_assert_cmpuint(fast.slot[2].target, ==, 15);
    g_assert_cmpuint(fast.slot[2].source2, ==, 15);
    g_assert_cmpuint(fast.slot[2].position, ==, 8);
    g_assert_cmpuint(fast.slot[2].length, ==, 56);
    g_assert_true(fast.slot[2].deposit_zero);
    g_assert_cmphex(fast.source_nat_mask, ==, (1ULL << 2) | (1ULL << 15));
    g_assert_cmphex(fast.dest_mask, ==, (1ULL << 9) | (1ULL << 15));
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT), ==, 2);
}

static void test_fast_bundle_accepts_predicate_test(void)
{
    const uint64_t tbit_nz_or_p10_p11_r20_2_raw =
        (0x5ULL << 37) | (1ULL << 33) | (11ULL << 27) |
        (20ULL << 20) | (2ULL << 14) | (1ULL << 12) |
        (10ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                    tbit_nz_or_p10_p11_r20_2_raw, IA64_SMOKE_NOP_RAW);
    IA64TcgFastBundle fast;

    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_PREDICATE_TEST);
    g_assert_cmpuint(fast.slot[1].predicate1, ==, 10);
    g_assert_cmpuint(fast.slot[1].predicate2, ==, 11);
    g_assert_cmpint(fast.slot[1].predicate_write_kind, ==,
                    IA64_PRED_WRITE_OR);
    g_assert_cmpint(fast.slot[1].predicate_test_kind, ==,
                    IA64_PRED_TEST_BIT);
    g_assert_cmpint(fast.slot[1].predicate_test_relation, ==,
                    IA64_PRED_TEST_NONZERO);
    g_assert_cmpuint(fast.slot[1].source3, ==, 20);
    g_assert_cmpint(fast.slot[1].immediate, ==, 2);
    g_assert_cmphex(fast.source_nat_mask, ==, 1ULL << 20);
}

static void test_fast_bundle_rejects_predicated_or_stacked_gr(void)
{
    const uint64_t add_r36_r36_r1_raw = 0x10000148900ULL;
    const uint64_t add_r1_r2_r3_raw =
        (8ULL << 37) | (3ULL << 20) | (2ULL << 13) | (1ULL << 6);
    IA64DecodedBundle bundle;
    IA64TcgFastBundle fast;

    bundle = make_bundle(0x00, add_r1_r2_r3_raw | 1,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));

    bundle = make_bundle(0x00, add_r36_r36_r1_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));
}

static uint64_t make_ldst_load_raw(uint8_t width_code,
                                   uint8_t target,
                                   uint8_t base)
{
    return (4ULL << 37) | ((uint64_t)width_code << 30) |
           ((uint64_t)base << 20) | ((uint64_t)target << 6);
}

static uint64_t make_ldst_load_update_raw(uint8_t width_code,
                                          uint8_t target,
                                          uint8_t base,
                                          uint8_t immediate)
{
    return (5ULL << 37) | ((uint64_t)width_code << 30) |
           ((uint64_t)base << 20) |
           (((uint64_t)immediate & 0x7f) << 13) |
           ((uint64_t)target << 6);
}

static uint64_t make_ldst_store_class_raw(uint8_t memory_class,
                                          uint8_t width_code,
                                          uint8_t source,
                                          uint8_t base)
{
    uint8_t x6 = (memory_class << 2) | width_code;

    return (4ULL << 37) | ((uint64_t)x6 << 30) |
           ((uint64_t)base << 20) | ((uint64_t)source << 13);
}

static uint64_t make_ldst_store_raw(uint8_t width_code,
                                    uint8_t source,
                                    uint8_t base)
{
    return make_ldst_store_class_raw(0x0c, width_code, source, base);
}

static uint64_t make_ldst_prefetch_raw(uint8_t width_code, uint8_t base)
{
    uint8_t x6 = (0x0b << 2) | width_code;

    return (4ULL << 37) | ((uint64_t)x6 << 30) |
           ((uint64_t)base << 20);
}

static void test_fast_bundle_accepts_ldst_slot0(void)
{
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t ld8_r2_r3_8_raw = make_ldst_load_update_raw(3, 2, 3, 8);
    const uint64_t ld8_r16_r17_raw = make_ldst_load_raw(3, 16, 17);
    const uint64_t st8_r4_r5_raw = make_ldst_store_raw(3, 4, 5);
    const uint64_t st8_rel_r6_r7_raw =
        make_ldst_store_class_raw(0x0d, 3, 6, 7);
    const uint64_t st8_spill_r8_r9_raw =
        make_ldst_store_class_raw(0x0e, 3, 8, 9);
    const uint64_t prefetch_r10_raw = make_ldst_prefetch_raw(3, 10);
    IA64DecodedBundle bundle;
    IA64TcgFastBundle fast;

    bundle = make_bundle(0x00, ld8_r2_r3_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_LDST_LOAD);
    g_assert_cmpuint(fast.slot[0].target, ==, 2);
    g_assert_cmpuint(fast.slot[0].base, ==, 3);
    g_assert_cmpuint(fast.slot[0].width, ==, 8);
    g_assert_cmpuint(fast.slot[0].slot_index, ==, 0);
    g_assert_false(fast.slot[0].base_update);
    g_assert_cmphex(fast.dest_mask, ==, 1ULL << 2);
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT), ==, 1);

    bundle = make_bundle(0x00, ld8_r2_r3_8_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_LDST_LOAD);
    g_assert_true(fast.slot[0].base_update);
    g_assert_cmpint(fast.slot[0].immediate, ==, 8);
    g_assert_cmphex(fast.dest_mask, ==, (1ULL << 2) | (1ULL << 3));

    bundle = make_bundle(0x00, ld8_r16_r17_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_LDST_LOAD);
    g_assert_cmpuint(fast.slot[0].target, ==, 16);
    g_assert_cmpuint(fast.slot[0].base, ==, 17);
    g_assert_cmphex(fast.dest_mask, ==, 1ULL << 16);

    bundle = make_bundle(0x00, st8_r4_r5_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[0].op, ==, IA64_TCG_FAST_OP_LDST_STORE);
    g_assert_cmpuint(fast.slot[0].source2, ==, 4);
    g_assert_cmpuint(fast.slot[0].base, ==, 5);
    g_assert_cmpuint(fast.slot[0].width, ==, 8);
    g_assert_cmphex(fast.dest_mask, ==, 0);
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT), ==, 1);

    bundle = make_bundle(0x08, IA64_SMOKE_NOP_RAW,
                         ld8_r2_r3_raw, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_LDST_LOAD);
    g_assert_cmpuint(fast.slot[1].target, ==, 2);
    g_assert_cmpuint(fast.slot[1].base, ==, 3);
    g_assert_cmpuint(fast.slot[1].slot_index, ==, 1);
    g_assert_cmphex(fast.dest_mask, ==, 1ULL << 2);

    bundle = make_bundle(0x08, IA64_SMOKE_NOP_RAW,
                         st8_rel_r6_r7_raw, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_LDST_STORE);
    g_assert_cmpuint(fast.slot[1].source2, ==, 6);
    g_assert_cmpuint(fast.slot[1].base, ==, 7);
    g_assert_cmpuint(fast.slot[1].slot_index, ==, 1);

    bundle = make_bundle(0x08, IA64_SMOKE_NOP_RAW,
                         st8_spill_r8_r9_raw, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_LDST_STORE);
    g_assert_cmpuint(fast.slot[1].source2, ==, 8);
    g_assert_cmpuint(fast.slot[1].base, ==, 9);

    bundle = make_bundle(0x08, IA64_SMOKE_NOP_RAW,
                         prefetch_r10_raw, IA64_SMOKE_NOP_RAW);
    g_assert_true(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_cmpint(fast.slot[1].op, ==, IA64_TCG_FAST_OP_NOP);
    g_assert_cmpuint(fast.slot[1].base, ==, 10);
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT), ==, 0);
    g_assert_cmpuint(ia64_perf_fast_count(
                         fast.op_counts,
                         IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT), ==, 0);
}

static void test_fast_bundle_rejects_unsafe_ldst(void)
{
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t ld8_r32_r3_raw = make_ldst_load_raw(3, 32, 3);
    const uint64_t add_r3_r3_r4_raw =
        (8ULL << 37) | (4ULL << 20) | (3ULL << 13) | (3ULL << 6);
    const uint64_t ld8_advanced_r2_r3_raw =
        (4ULL << 37) | ((uint64_t)((2 << 2) | 3) << 30) |
        (3ULL << 20) | (2ULL << 6);
    IA64DecodedBundle bundle;
    IA64TcgFastBundle fast;

    bundle = make_bundle(0x00, ld8_r2_r3_raw | 1,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));

    bundle = make_bundle(0x00, ld8_r32_r3_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));

    bundle = make_bundle(0x08, add_r3_r3_r4_raw,
                         ld8_r2_r3_raw, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_true(ia64_tcg_bundle_has_ldst_immediate(&bundle));
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_FAST_LDST_DEPENDENCY);

    bundle = make_bundle(0x00, ld8_advanced_r2_r3_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_true(ia64_tcg_bundle_has_ldst_immediate(&bundle));
}

static void test_fallback_plan_classifies_hot_helper_slots(void)
{
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t add_r1_r2_r3_raw =
        (8ULL << 37) | (3ULL << 20) | (2ULL << 13) | (1ULL << 6);
    const uint64_t br_cond_raw = 0x0800001a006ULL;
    IA64DecodedBundle bundle;
    uint32_t plan;

    bundle = make_bundle(0x00, ld8_r2_r3_raw,
                         add_r1_r2_r3_raw, IA64_SMOKE_NOP_RAW);
    plan = ia64_tcg_fallback_plan_for_bundle(&bundle);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 0), ==,
                    IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 1), ==,
                    IA64_TCG_FALLBACK_PLAN_ALU_ADD);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 2), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);

    bundle = make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, br_cond_raw);
    plan = ia64_tcg_fallback_plan_for_bundle(&bundle);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 0), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 1), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 2), ==,
                    IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE);
}

static void test_fallback_plan_keeps_long_immediate_tail_generic(void)
{
    IA64DecodedBundle bundle =
        make_bundle(0x04, IA64_SMOKE_NOP_RAW, 0, 0);
    uint32_t plan = ia64_tcg_fallback_plan_for_bundle(&bundle);

    g_assert_true(bundle.info->long_immediate);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 0), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 1), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);
    g_assert_cmpint(ia64_tcg_fallback_plan_slot(plan, 2), ==,
                    IA64_TCG_FALLBACK_PLAN_GENERIC);
}

static void test_direct_branch_accepts_p0_same_page(void)
{
    const uint64_t br_cond_raw = 0x0800001a006ULL & ~0x3fULL;
    IA64DecodedBundle bundle =
        make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                    IA64_SMOKE_NOP_RAW, br_cond_raw);
    IA64TcgDirectBranch branch;

    g_assert_true(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));
    g_assert_cmphex(branch.target_ip, ==, 0x20d0);
    g_assert_cmphex(branch.fallthrough_ip, ==, 0x2010);
    g_assert_cmpuint(branch.slot, ==, 2);
    g_assert_cmpuint(branch.predicate, ==, 0);
    g_assert_cmpuint(branch.nop_count, ==, 2);
    g_assert_cmpuint(branch.prefix.slot_count, ==, 2);
    g_assert_cmpuint(ia64_perf_fast_count(
                         branch.prefix.op_counts,
                         IA64_PERF_FAST_COUNT_NOP_SHIFT), ==, 2);
    g_assert_false(branch.conditional);
}

static void test_direct_branch_accepts_fast_prefix(void)
{
    const uint64_t br_cond_raw = 0x0800001a006ULL & ~0x3fULL;
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t add_r4_r5_r6_raw =
        (8ULL << 37) | (6ULL << 20) | (5ULL << 13) | (4ULL << 6);
    IA64DecodedBundle bundle =
        make_bundle(0x10, ld8_r2_r3_raw, add_r4_r5_r6_raw, br_cond_raw);
    IA64TcgDirectBranch branch;

    g_assert_true(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));
    g_assert_cmphex(branch.target_ip, ==, 0x20d0);
    g_assert_cmphex(branch.fallthrough_ip, ==, 0x2010);
    g_assert_cmpuint(branch.nop_count, ==, 0);
    g_assert_cmpuint(branch.prefix.slot_count, ==, 2);
    g_assert_cmpint(branch.prefix.slot[0].op, ==,
                    IA64_TCG_FAST_OP_LDST_LOAD);
    g_assert_cmpint(branch.prefix.slot[1].op, ==,
                    IA64_TCG_FAST_OP_ALU_ADD);
    g_assert_cmphex(branch.prefix.dest_mask, ==,
                    (1ULL << 2) | (1ULL << 4));
    g_assert_cmpuint(ia64_perf_fast_count(
                         branch.prefix.op_counts,
                         IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT), ==, 1);
    g_assert_cmpuint(ia64_perf_fast_count(
                         branch.prefix.op_counts,
                         IA64_PERF_FAST_COUNT_ALU_ADD_SHIFT), ==, 1);
}

static void test_direct_branch_accepts_predicate_to_next_bundle(void)
{
    const uint64_t br_cond_to_fallthrough_raw = 0x08600002006ULL;
    IA64DecodedBundle bundle =
        make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                    IA64_SMOKE_NOP_RAW, br_cond_to_fallthrough_raw);
    IA64TcgDirectBranch branch;

    g_assert_true(ia64_tcg_build_direct_branch(&bundle,
                                               0xa0000001003e9700ULL,
                                               &branch));
    g_assert_cmphex(branch.target_ip, ==, 0xa0000001003e9710ULL);
    g_assert_cmphex(branch.fallthrough_ip, ==, 0xa0000001003e9710ULL);
    g_assert_cmpuint(branch.predicate, ==, 6);
    g_assert_true(branch.conditional);
}

static void test_direct_branch_rejects_unsafe_forms(void)
{
    const uint64_t br_cond_raw = 0x0800001a006ULL & ~0x3fULL;
    const uint64_t br_cloop_raw = 0x091ffffc140ULL;
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    const uint64_t cmp_eq_p6_p7_r20_r21_raw =
        make_cmp_eq_parallel_p6_p7_r20_r21(0xd);
    const uint64_t add_r3_r3_r4_raw =
        (8ULL << 37) | (4ULL << 20) | (3ULL << 13) | (3ULL << 6);
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    IA64DecodedBundle bundle;
    IA64TcgDirectBranch branch;

    bundle = make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, br_cloop_raw);
    g_assert_false(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));

    bundle = make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, br_cond_raw | 16);
    g_assert_false(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));

    bundle = make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, br_ret_b0_raw);
    g_assert_false(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));
    g_assert_true(ia64_tcg_bundle_has_indirect_branch(&bundle));

    bundle = make_bundle(0x10, cmp_eq_p6_p7_r20_r21_raw,
                         IA64_SMOKE_NOP_RAW, 0x08600002006ULL);
    g_assert_false(ia64_tcg_build_direct_branch(
                       &bundle, 0xa0000001003e9700ULL, &branch));

    bundle = make_bundle(0x18, add_r3_r3_r4_raw,
                         ld8_r2_r3_raw, br_cond_raw);
    g_assert_false(ia64_tcg_build_direct_branch(&bundle, 0x2000, &branch));
}

static void test_direct_branch_rejects_page_crossing(void)
{
    const uint64_t br_cond_to_fallthrough_raw =
        0x08600002006ULL & ~0x3fULL;
    uint64_t pc = 0x1000 - IA64_BUNDLE_SIZE;
    IA64DecodedBundle bundle =
        make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                    IA64_SMOKE_NOP_RAW, br_cond_to_fallthrough_raw);
    IA64TcgDirectBranch branch;

    g_assert_false(ia64_tcg_build_direct_branch(&bundle, pc, &branch));
    g_assert_true(ia64_tcg_bundle_has_direct_branch(&bundle));
}

static void test_fallback_reason_classifies_helper_sources(void)
{
    const uint64_t add_r1_r2_r3_raw =
        (8ULL << 37) | (3ULL << 20) | (2ULL << 13) | (1ULL << 6);
    const uint64_t add_r36_r36_r1_raw = 0x10000148900ULL;
    const uint64_t add_r3_r3_r4_raw =
        (8ULL << 37) | (4ULL << 20) | (3ULL << 13) | (3ULL << 6);
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    IA64DecodedBundle bundle;

    bundle = make_bundle(0x00, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_RUNTIME_GUARD);

    bundle = make_bundle(0x00, add_r1_r2_r3_raw | 1,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT);

    bundle = make_bundle(0x00, add_r36_r36_r1_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_FAST_STATIC_GR);

    bundle = make_bundle(0x08, add_r3_r3_r4_raw,
                         ld8_r2_r3_raw, IA64_SMOKE_NOP_RAW);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_FAST_LDST_DEPENDENCY);

    bundle = make_bundle(0x10, IA64_SMOKE_NOP_RAW,
                         IA64_SMOKE_NOP_RAW, br_ret_b0_raw);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_BOUNDARY_BRANCH);

    bundle = make_bundle(0x06, 1, 2, 3);
    g_assert_cmpint(ia64_tcg_fallback_reason_for_bundle(&bundle, 0x1000),
                    ==, IA64_TCG_FALLBACK_INVALID_TEMPLATE);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-tcg-skeleton/helper-flags-conservative",
                    test_helper_flags_are_conservative);
    g_test_add_func("/ia64-tcg-skeleton/fallthrough",
                    test_fallthrough_bundle_does_not_end_tb);
    g_test_add_func("/ia64-tcg-skeleton/invalid-template",
                    test_invalid_template_ends_tb);
    g_test_add_func("/ia64-tcg-skeleton/efi-call-gate",
                    test_efi_call_gate_ends_tb);
    g_test_add_func("/ia64-tcg-skeleton/break-and-branch",
                    test_break_and_branch_end_tb);
    g_test_add_func("/ia64-tcg-skeleton/state-changing-slots",
                    test_state_changing_slots_end_tb);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-hot-integer-subset",
                    test_fast_bundle_accepts_hot_integer_subset);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-nop-add-immediate",
                    test_fast_bundle_accepts_nop_and_add_immediate);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-banked-static-gr",
                    test_fast_bundle_accepts_banked_static_gr);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-compare",
                    test_fast_bundle_accepts_compare_predicate_writes);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-integer-misc",
                    test_fast_bundle_accepts_integer_misc);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-shift-misc",
                    test_fast_bundle_accepts_shift_misc);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-bitfield-misc",
                    test_fast_bundle_accepts_bitfield_misc);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-predicate-test",
                    test_fast_bundle_accepts_predicate_test);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-rejects-unsafe",
                    test_fast_bundle_rejects_predicated_or_stacked_gr);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-ldst-slot0",
                    test_fast_bundle_accepts_ldst_slot0);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-ldst-rejects-unsafe",
                    test_fast_bundle_rejects_unsafe_ldst);
    g_test_add_func("/ia64-tcg-skeleton/fallback-plan-hot-helper-slots",
                    test_fallback_plan_classifies_hot_helper_slots);
    g_test_add_func("/ia64-tcg-skeleton/fallback-plan-long-immediate",
                    test_fallback_plan_keeps_long_immediate_tail_generic);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-p0-same-page",
                    test_direct_branch_accepts_p0_same_page);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-fast-prefix",
                    test_direct_branch_accepts_fast_prefix);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-predicate-next",
                    test_direct_branch_accepts_predicate_to_next_bundle);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-rejects-unsafe",
                    test_direct_branch_rejects_unsafe_forms);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-rejects-page-crossing",
                    test_direct_branch_rejects_page_crossing);
    g_test_add_func("/ia64-tcg-skeleton/fallback-reason-classifies-helper-sources",
                    test_fallback_reason_classifies_helper_sources);

    return g_test_run();
}
