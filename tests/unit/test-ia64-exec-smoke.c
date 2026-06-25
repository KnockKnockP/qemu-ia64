/*
 * IA-64 minimal execution smoke tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/exec-smoke.h"

static void store_le64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        p[i] = value >> (i * 8);
    }
}

static void make_bundle(uint8_t *bundle, uint8_t tmpl,
                        uint64_t slot0, uint64_t slot1, uint64_t slot2)
{
    uint64_t lo;
    uint64_t hi;

    slot0 &= IA64_SLOT_MASK;
    slot1 &= IA64_SLOT_MASK;
    slot2 &= IA64_SLOT_MASK;

    lo = tmpl | (slot0 << 5) | ((slot1 & ((1ULL << 18) - 1)) << 46);
    hi = (slot1 >> 18) | (slot2 << 23);

    store_le64(bundle, lo);
    store_le64(bundle + 8, hi);
}

static void make_nop_mii_bundle(uint8_t *bundle)
{
    make_bundle(bundle, 0x00,
                IA64_SMOKE_NOP_RAW,
                IA64_SMOKE_NOP_RAW,
                IA64_SMOKE_NOP_RAW);
}

static void test_reset(void)
{
    CPUIA64State env;

    memset(&env, 0xff, sizeof(env));
    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_cmphex(env.gr[0], ==, 0);
    g_assert_cmphex(env.ip, ==, 0);
    g_assert_cmphex(env.psr, ==, 0);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmphex(env.pr, ==, 1);
    g_assert_cmphex(env.ar[IA64_AR_RSC], ==, env.rse.rsc);
    g_assert_cmphex(env.ar[IA64_AR_UNAT], ==, env.nat.unat);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, env.ip);
}

static void test_bundle_fetch_decode(void)
{
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64DecodedBundle decoded;

    make_nop_mii_bundle(bundle);

    g_assert_true(ia64_decode_bundle(bundle, &decoded));
    g_assert_cmphex(decoded.tmpl, ==, 0x00);
    g_assert_cmpstr(decoded.info->name, ==, "MII");
    g_assert_cmphex(decoded.slot[0], ==, IA64_SMOKE_NOP_RAW);
    g_assert_cmphex(decoded.slot[1], ==, IA64_SMOKE_NOP_RAW);
    g_assert_cmphex(decoded.slot[2], ==, IA64_SMOKE_NOP_RAW);
}

static void test_ip_advances_for_nop_bundle(void)
{
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64ExecSmokeReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x1000;
    make_nop_mii_bundle(bundle);

    g_assert_cmpint(ia64_exec_smoke_bundle(&env, bundle, &report), ==,
                    IA64_EXEC_SMOKE_OK);
    g_assert_cmphex(env.ip, ==, 0x1010);
    g_assert_cmphex(report.ip_before, ==, 0x1000);
    g_assert_cmphex(report.ip_after, ==, 0x1010);
    g_assert_cmpint(report.failed_slot, ==, -1);
    g_assert_nonnull(strstr(report.message, "executed IA-64 smoke NOP"));
}

static void test_unsupported_instruction_message(void)
{
    const uint64_t mov_r3_ip_raw = 0x1800000c0ULL;
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64ExecSmokeReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x2000;
    make_bundle(bundle, 0x00,
                IA64_SMOKE_NOP_RAW, mov_r3_ip_raw, IA64_SMOKE_NOP_RAW);

    g_assert_cmpint(ia64_exec_smoke_bundle(&env, bundle, &report), ==,
                    IA64_EXEC_SMOKE_UNSUPPORTED_SLOT);
    g_assert_cmphex(env.ip, ==, 0x2000);
    g_assert_cmpint(report.failed_slot, ==, 1);
    g_assert_nonnull(strstr(report.message,
                           "unsupported IA-64 smoke instruction"));
    g_assert_nonnull(strstr(report.message, "slot=1"));
    g_assert_nonnull(strstr(report.message, "type=I"));
    g_assert_nonnull(strstr(report.message, "raw=0x001800000c0"));
}

static void test_m34_alloc_updates_frame_state(void)
{
    const uint64_t elilo_alloc_raw = 0x02c0040c880ULL;
    CPUIA64State env;
    uint64_t old_cfm;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cfm = ia64_make_cfm(2, 1, 0);
    env.ar[IA64_AR_PFS] = 0x12345678;
    old_cfm = env.cfm;

    g_assert_true(ia64_slot_is_m34_alloc(IA64_SLOT_TYPE_M, elilo_alloc_raw));
    g_assert_true(ia64_exec_m34_alloc(&env, elilo_alloc_raw));

    g_assert_cmphex(env.gr[34], ==, 0x12345678);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, old_cfm);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.sof, ==, 6);
    g_assert_cmpuint(env.rse.sol, ==, 4);
    g_assert_cmpuint(env.rse.sor, ==, 0);
}

static void test_i_unit_mov_ip_and_nop(void)
{
    const uint64_t mov_ip_r35_raw = 0x001800008c0ULL;
    const uint64_t mov_b_r35_b0_raw = 0x001880008c0ULL;
    const uint64_t nop_i_raw = 0x00008000000ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.br[0] = 0xfeedface;

    g_assert_true(ia64_slot_is_i_mov_ip(IA64_SLOT_TYPE_I, mov_ip_r35_raw));
    g_assert_true(ia64_exec_i_mov_ip(&env, mov_ip_r35_raw, 0x1001000));
    g_assert_cmphex(env.gr[35], ==, 0x1001000);

    g_assert_true(ia64_slot_is_i_mov_from_branch(IA64_SLOT_TYPE_I,
                                                 mov_b_r35_b0_raw));
    g_assert_true(ia64_exec_i_mov_from_branch(&env, mov_b_r35_b0_raw));
    g_assert_cmphex(env.gr[35], ==, 0xfeedface);

    g_assert_true(ia64_slot_is_i_nop(IA64_SLOT_TYPE_I, nop_i_raw));
}

static void test_i_unit_mov_from_predicate(void)
{
    const uint64_t mov_pr_r62_raw = 0x00198000f80ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr = 0x41;

    g_assert_true(ia64_slot_is_i_mov_from_predicate(IA64_SLOT_TYPE_I,
                                                    mov_pr_r62_raw));
    g_assert_true(ia64_exec_i_mov_from_predicate(&env, mov_pr_r62_raw));
    g_assert_cmphex(env.gr[62], ==, 0x41);
}

static void test_i_unit_mov_to_branch(void)
{
    const uint64_t mov_b6_r14_raw = 0x00e0011c180ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.gr[14] = 0x10203040;

    g_assert_true(ia64_slot_is_i_mov_to_branch(IA64_SLOT_TYPE_I,
                                               mov_b6_r14_raw));
    g_assert_true(ia64_exec_i_mov_to_branch(&env, mov_b6_r14_raw));
    g_assert_cmphex(env.br[6], ==, 0x10203040);
}

static void test_lx_movl_reconstructs_immediate(void)
{
    const uint64_t l_raw = 0x1ffffffffffULL;
    const uint64_t x_raw = 0x0d807000900ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_slot_pair_is_lx_movl(l_raw, x_raw));
    g_assert_cmphex(ia64_lx_movl_imm64(l_raw, x_raw), ==,
                    0xffffffffffdc8000ULL);
    g_assert_true(ia64_exec_lx_movl(&env, l_raw, x_raw));
    g_assert_cmphex(env.gr[36], ==, 0xffffffffffdc8000ULL);
}

static void test_alu_add_register_form(void)
{
    const uint64_t add_r36_r36_r1_raw = 0x10000148900ULL;
    const uint64_t adds_r36_0_r32_raw = 0x10802000900ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.gr[1] = 0x1238000;
    env.gr[36] = 0xffffffffffdc8000ULL;

    g_assert_true(ia64_slot_is_alu_add(IA64_SLOT_TYPE_M,
                                       add_r36_r36_r1_raw));
    g_assert_true(ia64_exec_alu_add(&env, add_r36_r36_r1_raw));
    g_assert_cmphex(env.gr[36], ==, 0x1000000);

    env.gr[32] = 0xfeedface;
    g_assert_true(ia64_slot_is_alu_add(IA64_SLOT_TYPE_M,
                                       adds_r36_0_r32_raw));
    g_assert_true(ia64_exec_alu_add(&env, adds_r36_0_r32_raw));
    g_assert_cmphex(env.gr[36], ==, 0xfeedface);
}

static void test_addl_immediate_form(void)
{
    const uint64_t addl_r8_0_r0_raw = 0x12000000200ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.gr[8] = 0xdeadbeef;

    g_assert_true(ia64_slot_is_addl(IA64_SLOT_TYPE_M, addl_r8_0_r0_raw));
    g_assert_cmpint(ia64_addl_immediate(addl_r8_0_r0_raw), ==, 0);
    g_assert_true(ia64_exec_addl(&env, addl_r8_0_r0_raw));
    g_assert_cmphex(env.gr[8], ==, 0);
}

static void test_ldst_immediate_decode(void)
{
    const uint64_t elilo_ld8_r16_r33_8_raw = 0x0a0c2110400ULL;
    const uint64_t elilo_ld8_r17_r33_8_raw = 0x0a0c2110440ULL;
    IA64LdstImmediate decoded;

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             elilo_ld8_r16_r33_8_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 16);
    g_assert_cmpuint(decoded.base, ==, 33);
    g_assert_cmpint(decoded.immediate, ==, 8);
    g_assert_true(decoded.base_update);
    g_assert_false(decoded.update_from_register);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             elilo_ld8_r17_r33_8_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 17);
    g_assert_cmpuint(decoded.base, ==, 33);
    g_assert_cmpint(decoded.immediate, ==, 8);
}

static void test_compare_immediate_updates_predicates(void)
{
    const uint64_t cmp_eq_p6_p0_0_r16_raw = 0x1c801000180ULL;
    IA64CompareInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_compare(IA64_SLOT_TYPE_I,
                                      cmp_eq_p6_p0_0_r16_raw,
                                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_NORMAL);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.p1, ==, 6);
    g_assert_cmpuint(decoded.p2, ==, 0);
    g_assert_true(decoded.source_immediate);
    g_assert_cmpint(decoded.immediate, ==, 0);
    g_assert_cmpuint(decoded.source3, ==, 16);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.gr[16] = 0;
    g_assert_true(ia64_exec_compare(&env, &decoded));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 1ULL << 6);
    g_assert_cmphex(env.pr & 1, ==, 1);

    env.gr[16] = 1;
    g_assert_true(ia64_exec_compare(&env, &decoded));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 0);
    g_assert_cmphex(env.pr & 1, ==, 1);
}

static void test_b_unit_relative_call_updates_link_and_frame(void)
{
    const uint64_t br_call_raw = 0x0a006ba6000ULL;
    CPUIA64State env;
    uint64_t target = 0;
    uint64_t old_cfm;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cfm = ia64_make_cfm(6, 4, 0);
    old_cfm = env.cfm;

    g_assert_true(ia64_slot_is_b_call_relative(IA64_SLOT_TYPE_B,
                                               br_call_raw));
    g_assert_cmpint(ia64_branch_displacement(br_call_raw), ==, 220464);
    g_assert_true(ia64_exec_b_call_relative(&env, br_call_raw, 0x1001030,
                                            &target));

    g_assert_cmphex(target, ==, 0x1036d60);
    g_assert_cmphex(env.br[0], ==, 0x1001040);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, old_cfm);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(2, 0, 0));
}

static void test_b_unit_relative_branch(void)
{
    const uint64_t br_cond_raw = 0x0800001a006ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B,
                                                 br_cond_raw));
    g_assert_cmpint(ia64_branch_displacement(br_cond_raw), ==, 208);
    g_assert_true(ia64_exec_b_branch_relative(&env, br_cond_raw, 0x1036da0,
                                              &target));

    g_assert_cmphex(target, ==, 0x1036e70);
}

static void test_b_unit_indirect_return(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cfm = ia64_make_cfm(2, 0, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B,
                                                 br_ret_b0_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.sof, ==, 6);
    g_assert_cmpuint(env.rse.sol, ==, 4);
}

static void test_b_unit_predict_or_nop(void)
{
    const uint64_t brp_raw = 0x04000000000ULL;

    g_assert_true(ia64_slot_is_b_predict_or_nop(IA64_SLOT_TYPE_B, brp_raw));
    g_assert_false(ia64_slot_is_b_predict_or_nop(IA64_SLOT_TYPE_I, brp_raw));
}

static void test_reserved_template_message(void)
{
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64ExecSmokeReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x3000;
    make_bundle(bundle, 0x06,
                IA64_SMOKE_NOP_RAW,
                IA64_SMOKE_NOP_RAW,
                IA64_SMOKE_NOP_RAW);

    g_assert_cmpint(ia64_exec_smoke_bundle(&env, bundle, &report), ==,
                    IA64_EXEC_SMOKE_RESERVED_TEMPLATE);
    g_assert_cmphex(env.ip, ==, 0x3000);
    g_assert_cmpint(report.failed_slot, ==, -1);
    g_assert_nonnull(strstr(report.message,
                           "reserved IA-64 template 0x06"));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-exec-smoke/reset", test_reset);
    g_test_add_func("/ia64-exec-smoke/bundle-fetch-decode",
                    test_bundle_fetch_decode);
    g_test_add_func("/ia64-exec-smoke/ip-advances-for-nop-bundle",
                    test_ip_advances_for_nop_bundle);
    g_test_add_func("/ia64-exec-smoke/unsupported-instruction-message",
                    test_unsupported_instruction_message);
    g_test_add_func("/ia64-exec-smoke/m34-alloc-updates-frame-state",
                    test_m34_alloc_updates_frame_state);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-ip-and-nop",
                    test_i_unit_mov_ip_and_nop);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-from-predicate",
                    test_i_unit_mov_from_predicate);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-to-branch",
                    test_i_unit_mov_to_branch);
    g_test_add_func("/ia64-exec-smoke/lx-movl-reconstructs-immediate",
                    test_lx_movl_reconstructs_immediate);
    g_test_add_func("/ia64-exec-smoke/alu-add-register-form",
                    test_alu_add_register_form);
    g_test_add_func("/ia64-exec-smoke/addl-immediate-form",
                    test_addl_immediate_form);
    g_test_add_func("/ia64-exec-smoke/ldst-immediate-decode",
                    test_ldst_immediate_decode);
    g_test_add_func("/ia64-exec-smoke/compare-immediate-predicate-write",
                    test_compare_immediate_updates_predicates);
    g_test_add_func("/ia64-exec-smoke/b-unit-relative-call",
                    test_b_unit_relative_call_updates_link_and_frame);
    g_test_add_func("/ia64-exec-smoke/b-unit-relative-branch",
                    test_b_unit_relative_branch);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-return",
                    test_b_unit_indirect_return);
    g_test_add_func("/ia64-exec-smoke/b-unit-predict-or-nop",
                    test_b_unit_predict_or_nop);
    g_test_add_func("/ia64-exec-smoke/reserved-template-message",
                    test_reserved_template_message);

    return g_test_run();
}
