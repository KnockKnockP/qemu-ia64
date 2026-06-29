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

    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, VIBTANIUM_EFI_PAL_PROC);
    assert_boundary(IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
                    &bundle, VIBTANIUM_EFI_CALL_GATE_BASE);
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(
        VIBTANIUM_EFI_CALL_GATE_BASE - IA64_BUNDLE_SIZE));
    g_assert_false(ia64_tcg_pc_is_efi_call_gate(
        VIBTANIUM_EFI_CALL_GATE_BASE + 1));
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

static uint64_t make_ldst_store_raw(uint8_t width_code,
                                    uint8_t source,
                                    uint8_t base)
{
    uint8_t x6 = (0x0c << 2) | width_code;

    return (4ULL << 37) | ((uint64_t)x6 << 30) |
           ((uint64_t)base << 20) | ((uint64_t)source << 13);
}

static void test_fast_bundle_accepts_ldst_slot0(void)
{
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t ld8_r2_r3_8_raw = make_ldst_load_update_raw(3, 2, 3, 8);
    const uint64_t st8_r4_r5_raw = make_ldst_store_raw(3, 4, 5);
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
}

static void test_fast_bundle_rejects_unsafe_ldst(void)
{
    const uint64_t ld8_r2_r3_raw = make_ldst_load_raw(3, 2, 3);
    const uint64_t ld8_r16_r3_raw = make_ldst_load_raw(3, 16, 3);
    const uint64_t ld8_advanced_r2_r3_raw =
        (4ULL << 37) | ((uint64_t)((2 << 2) | 3) << 30) |
        (3ULL << 20) | (2ULL << 6);
    IA64DecodedBundle bundle;
    IA64TcgFastBundle fast;

    bundle = make_bundle(0x00, ld8_r2_r3_raw | 1,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));

    bundle = make_bundle(0x00, ld8_r16_r3_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));

    bundle = make_bundle(0x08, IA64_SMOKE_NOP_RAW,
                         ld8_r2_r3_raw, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_true(ia64_tcg_bundle_has_ldst_immediate(&bundle));

    bundle = make_bundle(0x00, ld8_advanced_r2_r3_raw,
                         IA64_SMOKE_NOP_RAW, IA64_SMOKE_NOP_RAW);
    g_assert_false(ia64_tcg_build_fast_bundle(&bundle, &fast));
    g_assert_true(ia64_tcg_bundle_has_ldst_immediate(&bundle));
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
    g_assert_false(branch.conditional);
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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

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
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-rejects-unsafe",
                    test_fast_bundle_rejects_predicated_or_stacked_gr);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-ldst-slot0",
                    test_fast_bundle_accepts_ldst_slot0);
    g_test_add_func("/ia64-tcg-skeleton/fast-bundle-ldst-rejects-unsafe",
                    test_fast_bundle_rejects_unsafe_ldst);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-p0-same-page",
                    test_direct_branch_accepts_p0_same_page);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-predicate-next",
                    test_direct_branch_accepts_predicate_to_next_bundle);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-rejects-unsafe",
                    test_direct_branch_rejects_unsafe_forms);
    g_test_add_func("/ia64-tcg-skeleton/direct-branch-rejects-page-crossing",
                    test_direct_branch_rejects_page_crossing);

    return g_test_run();
}
