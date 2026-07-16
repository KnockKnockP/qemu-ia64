/*
 * IA-64 production architectural-state tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Raw slot decoding and legacy instruction execution are intentionally not
 * tested here: the production runtime has exactly one decoder (`decode.c`)
 * and one typed TCG execution engine.
 */

#include "qemu/osdep.h"
#include "target/ia64/insn.h"

static void test_reset_state(void)
{
    CPUIA64State env;

    memset(&env, 0xff, sizeof(env));
    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_cmphex(env.gr[0], ==, 0);
    g_assert_cmphex(env.ip, ==, 0);
    g_assert_cmphex(env.psr, ==, 0);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmphex(env.pr, ==, 1);
    g_assert_cmpint(env.rse.invalid, ==, IA64_RSE_PHYS_STACKED_REGS);
    g_assert_cmphex(env.fr[0].raw[0], ==, 0);
    g_assert_cmphex(env.fr[0].raw[1], ==, 0);
    g_assert_cmphex(env.fr[1].raw[0], ==,
                    UINT64_C(0x8000000000000000));
    g_assert_cmphex(env.fr[1].raw[1], ==, UINT64_C(0xffff));
    g_assert_cmphex(env.cr[IA64_CR_IVR], ==, UINT64_C(0x0f));
    g_assert_cmphex(env.cr[IA64_CR_ITV], ==, UINT64_C(1) << 16);
    g_assert_cmphex(env.cpuid[0], ==, UINT64_C(0x49656e69756e6547));
    g_assert_cmphex(env.cpuid[1], ==, UINT64_C(0x000000006c65746e));
}

static void test_cfm_updates_decoded_frame(void)
{
    CPUIA64State env;
    uint64_t cfm = ia64_make_cfm(16, 8, 2) |
                   (UINT64_C(3) << 18) |
                   (UINT64_C(4) << 25) |
                   (UINT64_C(5) << 32);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, cfm);

    g_assert_cmphex(env.cfm, ==, cfm);
    g_assert_cmpuint(env.rse.sof, ==, 16);
    g_assert_cmpuint(env.rse.sol, ==, 8);
    g_assert_cmpuint(env.rse.sor, ==, 2);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 3);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 4);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 5);
    g_assert_cmpint(env.rse.invalid, ==,
                    IA64_RSE_PHYS_STACKED_REGS - 16);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_gr_write_clears_nat(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr_nat(&env, 20, true);
    g_assert_true(ia64_read_gr_nat(&env, 20));

    ia64_write_gr(&env, 20, UINT64_C(0x0123456789abcdef));
    g_assert_cmphex(ia64_read_gr(&env, 20), ==,
                    UINT64_C(0x0123456789abcdef));
    g_assert_false(ia64_read_gr_nat(&env, 20));

    ia64_write_gr(&env, 0, UINT64_MAX);
    ia64_write_gr_nat(&env, 0, true);
    g_assert_cmphex(ia64_read_gr(&env, 0), ==, 0);
    g_assert_false(ia64_read_gr_nat(&env, 0));
}

static void test_alat_architectural_names(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_alat_record_gr(&env, 12, UINT64_C(0x2000), 8, true);
    ia64_alat_record_fr(&env, 12, UINT64_C(0x3000), 10, false);

    g_assert_true(ia64_alat_check_gr(
        &env, 12, UINT64_C(0x2000), 8, true, false));
    g_assert_true(ia64_alat_check_fr(
        &env, 12, UINT64_C(0x3000), 10, false, false));
    g_assert_false(ia64_alat_check_fr(
        &env, 12, UINT64_C(0x2000), 8, true, false));

    ia64_alat_invalidate_gr(&env, 12);
    g_assert_false(ia64_alat_test_gr(&env, 12, false));
    g_assert_true(ia64_alat_test_fr(&env, 12, false));

    ia64_alat_invalidate_all(&env);
    g_assert_cmpuint(env.alat.valid_mask, ==, 0);
    g_assert_cmpuint(env.alat.next, ==, 0);
}

static void test_float_register_memory_formats(void)
{
    CPUIA64State env;
    IA64FloatReg spill;
    uint64_t sign_exponent;
    uint64_t mantissa;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_fr_from_double_bits(&env, 8,
                                   UINT64_C(0x4014000000000000));
    g_assert_cmphex(ia64_read_fr_as_double_bits(&env.fr[8]), ==,
                    UINT64_C(0x4014000000000000));
    ia64_write_fr_from_single_bits(&env, 9, UINT32_C(0x40a00000));
    g_assert_cmphex(ia64_read_fr_as_single_bits(&env.fr[9]), ==,
                    UINT32_C(0x40a00000));

    ia64_float_reg_to_spill(&env.fr[8], &sign_exponent, &mantissa);
    ia64_float_reg_from_spill(sign_exponent, mantissa, &spill);
    g_assert_cmpmem(&spill, sizeof(spill), &env.fr[8], sizeof(env.fr[8]));
}

static void test_issue_group_ar_entry_image(void)
{
    const uint64_t entry = UINT64_C(0x0102030405060708);
    const uint64_t retired = UINT64_C(0x1112131415161718);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.issue_group.typed_active = true;
    env.ar[IA64_AR_CSD] = entry;

    g_assert_true(ia64_issue_group_preserve_ar_source(
        &env, IA64_AR_CSD, env.ar[IA64_AR_CSD]));
    env.ar[IA64_AR_CSD] = retired;
    g_assert_cmphex(ia64_issue_group_select_ar_source(
                        &env, IA64_AR_CSD, env.ar[IA64_AR_CSD]),
                    ==, entry);

    /* WAW keeps the visibility-epoch entry image. */
    g_assert_true(ia64_issue_group_preserve_ar_source(
        &env, IA64_AR_CSD, retired));
    g_assert_cmpuint(env.issue_group.saved_ar_count, ==, 1);

    ia64_env_begin_source_visibility_epoch(&env);
    g_assert_cmpuint(env.issue_group.saved_ar_count, ==, 0);
    g_assert_false(env.issue_group.typed_active);
    g_assert_cmphex(env.ar[IA64_AR_CSD], ==, retired);
}

static void test_rse_backing_store_geometry(void)
{
    g_assert_true(ia64_rse_address_is_rnat_slot(UINT64_C(0x1f8)));
    g_assert_false(ia64_rse_address_is_rnat_slot(UINT64_C(0x1f0)));
    g_assert_cmphex(ia64_rse_skip_regs(UINT64_C(0), 63), ==,
                    UINT64_C(0x200));
    g_assert_cmphex(ia64_rse_skip_regs(UINT64_C(0x200), -63), ==,
                    UINT64_C(0));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-arch-state/reset", test_reset_state);
    g_test_add_func("/ia64-arch-state/cfm", test_cfm_updates_decoded_frame);
    g_test_add_func("/ia64-arch-state/gr-nat", test_gr_write_clears_nat);
    g_test_add_func("/ia64-arch-state/alat", test_alat_architectural_names);
    g_test_add_func("/ia64-arch-state/float-memory-format",
                    test_float_register_memory_formats);
    g_test_add_func("/ia64-arch-state/issue-group-ar",
                    test_issue_group_ar_entry_image);
    g_test_add_func("/ia64-arch-state/rse-backing-store",
                    test_rse_backing_store_geometry);

    return g_test_run();
}
