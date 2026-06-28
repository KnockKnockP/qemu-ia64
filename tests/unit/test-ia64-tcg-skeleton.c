/*
 * IA-64 TCG skeleton boundary-policy tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "target/ia64/exec-smoke.h"
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

    return g_test_run();
}
