/*
 * IA-64 instruction execution tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/exception.h"
#include "target/ia64/insn.h"
#include "target/ia64/mem.h"
#include "exec/page-protection.h"

#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_DCR_PP_BIT  UINT64_C(0x0000000000000001)
#define IA64_DCR_BE_BIT  UINT64_C(0x0000000000000002)
#define IA64_PSR_BE_BIT  UINT64_C(0x0000000000000002)
#define IA64_PSR_UP_BIT  UINT64_C(0x0000000000000004)
#define IA64_PSR_AC_BIT  UINT64_C(0x0000000000000008)
#define IA64_PSR_MFL_BIT UINT64_C(0x0000000000000010)
#define IA64_PSR_MFH_BIT UINT64_C(0x0000000000000020)
#define IA64_PSR_IC_BIT  UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT   UINT64_C(0x0000000000004000)
#define IA64_PSR_PK_BIT  UINT64_C(0x0000000000008000)
#define IA64_PSR_DT_BIT  UINT64_C(0x0000000000020000)
#define IA64_PSR_DFL_BIT UINT64_C(0x0000000000040000)
#define IA64_PSR_DFH_BIT UINT64_C(0x0000000000080000)
#define IA64_PSR_SP_BIT  UINT64_C(0x0000000000100000)
#define IA64_PSR_PP_BIT  UINT64_C(0x0000000000200000)
#define IA64_PSR_DI_BIT  UINT64_C(0x0000000000400000)
#define IA64_PSR_SI_BIT  UINT64_C(0x0000000000800000)
#define IA64_PSR_DB_BIT  UINT64_C(0x0000000001000000)
#define IA64_PSR_LP_BIT  UINT64_C(0x0000000002000000)
#define IA64_PSR_TB_BIT  UINT64_C(0x0000000004000000)
#define IA64_PSR_RT_BIT  UINT64_C(0x0000000008000000)
#define IA64_PSR_MC_BIT  UINT64_C(0x0000000800000000)
#define IA64_PSR_IT_BIT  UINT64_C(0x0000001000000000)
#define IA64_PSR_ID_BIT  UINT64_C(0x0000002000000000)
#define IA64_PSR_DA_BIT  UINT64_C(0x0000004000000000)
#define IA64_PSR_DD_BIT  UINT64_C(0x0000008000000000)
#define IA64_PSR_SS_BIT  UINT64_C(0x0000010000000000)
#define IA64_PSR_ED_BIT  UINT64_C(0x0000080000000000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PFS_CFM_MASK UINT64_C(0x0000003fffffffff)
#define IA64_PFS_PEC_SHIFT 52
#define IA64_PFS_PPL_SHIFT 62
#define IA64_TPR_MIC(class) ((uint64_t)(class) << 4)
#define IA64_TPR_MMI_BIT UINT64_C(0x0000000000010000)
#define IA64_PTE_P_BIT UINT64_C(0x0000000000000001)
#define IA64_PTE_A_BIT UINT64_C(0x0000000000000020)
#define IA64_PTE_D_BIT UINT64_C(0x0000000000000040)
#define IA64_TEST_FR_SPECIAL_EXPONENT 0x1ffff
#define IA64_TEST_FR_NATVAL_EXPONENT 0x1fffe
#define IA64_TEST_FR_INTEGER_BIT UINT64_C(0x8000000000000000)
#define IA64_TEST_FR_QUIET_NAN_BIT UINT64_C(0x4000000000000000)

static uint64_t ia64_make_pfs(uint64_t cfm, uint64_t ec, uint64_t cpl)
{
    return (cfm & IA64_PFS_CFM_MASK) |
           ((ec & 0x3f) << IA64_PFS_PEC_SHIFT) |
           ((cpl & 0x3) << IA64_PFS_PPL_SHIFT);
}

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
                IA64_INSN_NOP_RAW,
                IA64_INSN_NOP_RAW,
                IA64_INSN_NOP_RAW);
}

static uint64_t make_i2_packed_raw(uint8_t za, uint8_t zb,
                                   uint8_t x2b, uint8_t x2c,
                                   uint8_t r1, uint8_t r2, uint8_t r3)
{
    return (7ULL << 37) | ((uint64_t)za << 36) | (2ULL << 34) |
           ((uint64_t)zb << 33) | ((uint64_t)x2c << 30) |
           ((uint64_t)x2b << 28) | ((uint64_t)r3 << 20) |
           ((uint64_t)r2 << 13) | ((uint64_t)r1 << 6);
}

static uint64_t make_i_multiply_shift_raw(uint8_t za, uint8_t zb,
                                          uint8_t x2b, uint8_t x2c,
                                          uint8_t r1, uint8_t r2, uint8_t r3)
{
    return (7ULL << 37) | ((uint64_t)za << 36) |
           ((uint64_t)zb << 33) | ((uint64_t)x2c << 30) |
           ((uint64_t)x2b << 28) | ((uint64_t)r3 << 20) |
           ((uint64_t)r2 << 13) | ((uint64_t)r1 << 6);
}

static uint64_t make_packed_alu_raw(uint8_t za, uint8_t zb, uint8_t x4,
                                    uint8_t x2b, uint8_t r1, uint8_t r2,
                                    uint8_t r3)
{
    return (8ULL << 37) | ((uint64_t)za << 36) | (1ULL << 34) |
           ((uint64_t)zb << 33) | ((uint64_t)x4 << 29) |
           ((uint64_t)x2b << 27) | ((uint64_t)r3 << 20) |
           ((uint64_t)r2 << 13) | ((uint64_t)r1 << 6);
}

static uint64_t make_extract_raw(bool sign_extend, uint8_t r1, uint8_t r3,
                                 uint8_t position, uint8_t length)
{
    g_assert_cmpuint(length, >=, 1);
    g_assert_cmpuint(length, <=, 64);

    return (5ULL << 37) | (1ULL << 34) |
           ((uint64_t)(length - 1) << 27) |
           ((uint64_t)r3 << 20) | ((uint64_t)position << 14) |
           ((uint64_t)sign_extend << 13) | ((uint64_t)r1 << 6);
}

static uint64_t make_m_getf_raw(uint8_t x6, uint8_t r1, uint8_t f2)
{
    return (4ULL << 37) | (1ULL << 27) | ((uint64_t)x6 << 30) |
           ((uint64_t)f2 << 13) | ((uint64_t)r1 << 6);
}

static void test_reset(void)
{
    CPUIA64State env;

    memset(&env, 0xff, sizeof(env));
    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_cmphex(env.gr[0], ==, 0);
    g_assert_cmphex(env.ip, ==, 0);
    g_assert_cmphex(env.last_successful_bundle, ==, 0);
    g_assert_cmphex(env.psr, ==, 0);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmphex(env.pr, ==, 1);
    g_assert_cmphex(env.ar[IA64_AR_RSC], ==, env.rse.rsc);
    g_assert_cmphex(env.ar[IA64_AR_UNAT], ==, env.nat.unat);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, env.ip);
    g_assert_cmphex(env.fr[0].raw[0], ==, 0);
    g_assert_cmphex(env.fr[0].raw[1], ==, 0x1ffff);
    g_assert_cmphex(env.fr[1].raw[0], ==, 0x8000000000000000ULL);
    g_assert_cmphex(env.fr[1].raw[1], ==, 0xffff);
    g_assert_cmphex(env.cpuid[0], ==, 0x49656e69756e6547ULL);
    g_assert_cmphex(env.cpuid[1], ==, 0x000000006c65746eULL);
    g_assert_cmphex(env.cpuid[3], ==, 0x0000000200000004ULL);
    g_assert_cmphex(env.cpuid[4], ==, 0x0000000300000000ULL);
}

static void test_last_successful_bundle_uses_pre_instruction_ic(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.last_successful_bundle = 0x1110;

    ia64_note_successful_instruction(&env, 0x222f, 0);
    g_assert_cmphex(env.last_successful_bundle, ==, 0x1110);

    ia64_note_successful_instruction(&env, 0x333f, IA64_PSR_IC_BIT);
    g_assert_cmphex(env.last_successful_bundle, ==, 0x3330);

    /* An instruction that clears IC still retires because its pre-state was 1. */
    ia64_note_successful_instruction(&env, 0x4440, IA64_PSR_IC_BIT);
    g_assert_cmphex(env.last_successful_bundle, ==, 0x4440);

    /* An instruction that sets IC does not retire into IIPA from pre-state 0. */
    ia64_note_successful_instruction(&env, 0x5550, 0);
    g_assert_cmphex(env.last_successful_bundle, ==, 0x4440);
}

static void test_banked_static_general_registers(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_gr(&env, 16, 0x1111);
    ia64_write_gr(&env, 31, 0x3131);
    env.psr |= IA64_PSR_BN_BIT;
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0);
    g_assert_cmphex(ia64_read_gr(&env, 31), ==, 0);

    ia64_write_gr(&env, 16, 0x2222);
    ia64_write_gr(&env, 31, 0x3232);
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x2222);
    g_assert_cmphex(ia64_read_gr(&env, 31), ==, 0x3232);

    env.psr &= ~IA64_PSR_BN_BIT;
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x1111);
    g_assert_cmphex(ia64_read_gr(&env, 31), ==, 0x3131);

    env.psr |= IA64_PSR_BN_BIT;
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x2222);
    g_assert_cmphex(ia64_read_gr(&env, 31), ==, 0x3232);
}

static void test_pal_calling_convention_table(void)
{
    g_assert_false(ia64_pal_uses_stacked_calling_convention(1));
    g_assert_false(ia64_pal_uses_stacked_calling_convention(20));
    g_assert_false(ia64_pal_uses_stacked_calling_convention(256));
    g_assert_false(ia64_pal_uses_stacked_calling_convention(258));
    g_assert_false(ia64_pal_uses_stacked_calling_convention(
        UINT64_C(0x6000000000017050)));

    g_assert_true(ia64_pal_uses_stacked_calling_convention(257));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(259));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(260));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(261));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(262));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(263));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(274));
    g_assert_true(ia64_pal_uses_stacked_calling_convention(276));
}

static void test_banked_register_switch_via_bsw(void)
{
    const uint64_t bsw_0_raw = 0x0cULL << 27;
    const uint64_t bsw_1_raw = 0x0dULL << 27;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_gr(&env, 16, 0x1111);
    ia64_write_gr_nat(&env, 16, true);
    g_assert_true(ia64_read_gr_nat(&env, 16));

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x0ff0,
                                              &target));
    g_assert_false(ia64_read_gr_nat(&env, 16));
    ia64_write_gr(&env, 16, 0x2222);
    ia64_write_gr_nat(&env, 17, true);

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_0_raw, 0x1000,
                                              &target));
    g_assert_true(ia64_read_gr_nat(&env, 16));
    g_assert_false(ia64_read_gr_nat(&env, 17));

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x1010,
                                              &target));
    g_assert_cmphex(target, ==, 0x1020);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, IA64_PSR_BN_BIT);
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x2222);
    g_assert_false(ia64_read_gr_nat(&env, 16));
    g_assert_true(ia64_read_gr_nat(&env, 17));
    ia64_write_gr(&env, 16, 0x3333);

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_0_raw, 0x1020,
                                              &target));
    g_assert_cmphex(target, ==, 0x1030);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, 0);
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x1111);
    g_assert_true(ia64_read_gr_nat(&env, 16));
    g_assert_false(ia64_read_gr_nat(&env, 17));

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x1030,
                                              &target));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x3333);
    g_assert_false(ia64_read_gr_nat(&env, 16));
    g_assert_true(ia64_read_gr_nat(&env, 17));
}

static void test_syscall_break_user_to_kernel_transition(void)
{
    const uint64_t linux_break_syscall = 0x100000;
    CPUIA64State env;
    uint64_t next_ip = 0;
    uint64_t user_psr;
    vaddr user_ip = 0x2000000000012347ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    user_psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                                IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK, 1);
    env.ip = user_ip;
    env.psr = user_psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    next_ip = user_ip + IA64_BUNDLE_SIZE;

    ia64_deliver_break_interruption(&env, linux_break_syscall, &next_ip,
                                    "break.i iim=0x100000");

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_BREAK);
    g_assert_cmphex(env.exception.vector, ==, 0x2c00);
    g_assert_cmphex(env.cr[IA64_CR_IIM], ==, linux_break_syscall);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, user_psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, user_ip & ~0xfULL);
    g_assert_cmphex(env.ip, ==, 0x102c00);
    g_assert_cmphex(next_ip, ==, env.ip);
    g_assert_cmphex(env.psr & (IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                               IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK), ==, 0);
    g_assert_cmpuint(ia64_psr_ri(env.psr), ==, 0);
}

static void test_syscall_return_rfi_kernel_to_user_transition(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    CPUIA64State env;
    uint64_t target = 0;
    uint64_t user_psr;
    vaddr user_ip = 0x2000000000045677ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0xa000000100001000ULL;
    env.psr = IA64_PSR_IC_BIT;
    user_psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                                IA64_PSR_CPL_MASK, 2);
    env.cr[IA64_CR_IPSR] = user_psr;
    env.cr[IA64_CR_IIP] = user_ip;
    env.cr[IA64_CR_IFS] = 0;

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, env.ip,
                                              &target));

    g_assert_cmphex(target, ==, user_ip & ~0xfULL);
    g_assert_cmphex(env.psr, ==, user_psr);
    g_assert_cmphex(env.psr & IA64_PSR_CPL_MASK, ==, IA64_PSR_CPL_MASK);
    g_assert_cmpuint(ia64_psr_ri(env.psr), ==, 2);
}

static void test_epc_clears_user_cpl_for_kernel_entry(void)
{
    const uint64_t epc_raw = 0x10ULL << 27;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_CPL_MASK | IA64_PSR_BN_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, epc_raw, 0x3000,
                                              &target));

    g_assert_cmphex(target, ==, 0x3010);
    g_assert_cmphex(env.psr & IA64_PSR_CPL_MASK, ==, 0);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, IA64_PSR_BN_BIT);
}

static void test_epc_gate_return_restores_pfs_privilege(void)
{
    const uint64_t br_call_raw = 0x0a006ba6000ULL;
    const uint64_t br_ret_b6_raw = 0x0010800c100ULL;
    const uint64_t epc_raw = 0x10ULL << 27;
    const uint64_t caller_cfm = ia64_make_cfm(6, 4, 0);
    const uint64_t caller_ec = 0x2a;
    const uint64_t caller_cpl = 3;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_CPL_MASK | IA64_PSR_BN_BIT;
    env.ar[IA64_AR_EC] = caller_ec;
    ia64_set_cfm(&env, caller_cfm);
    env.br[6] = 0x400000000005b4e7ULL;

    g_assert_true(ia64_exec_b_call_relative(&env, br_call_raw, 0x1001030,
                                            &target));
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==,
                    ia64_make_pfs(caller_cfm, caller_ec, caller_cpl));

    g_assert_true(ia64_exec_b_indirect_branch(&env, epc_raw, target,
                                              &target));
    g_assert_cmphex(env.psr & IA64_PSR_CPL_MASK, ==, 0);
    env.ar[IA64_AR_EC] = 0;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b6_raw, target,
                                              &target));

    g_assert_cmphex(target, ==, 0x400000000005b4e0ULL);
    g_assert_cmphex(env.psr & IA64_PSR_CPL_MASK, ==,
                    caller_cpl << IA64_PSR_CPL_SHIFT);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, caller_ec);
    g_assert_cmphex(env.cfm, ==, caller_cfm);
}

static void test_bundle_fetch_decode(void)
{
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64DecodedBundle decoded;

    make_nop_mii_bundle(bundle);

    g_assert_true(ia64_decode_bundle(bundle, &decoded));
    g_assert_cmphex(decoded.tmpl, ==, 0x00);
    g_assert_cmpstr(decoded.info->name, ==, "MII");
    g_assert_cmphex(decoded.slot[0], ==, IA64_INSN_NOP_RAW);
    g_assert_cmphex(decoded.slot[1], ==, IA64_INSN_NOP_RAW);
    g_assert_cmphex(decoded.slot[2], ==, IA64_INSN_NOP_RAW);
}

static void test_ip_advances_for_nop_bundle(void)
{
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64InsnReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x1000;
    make_nop_mii_bundle(bundle);

    g_assert_cmpint(ia64_insn_exec_bundle(&env, bundle, &report), ==,
                    IA64_INSN_OK);
    g_assert_cmphex(env.ip, ==, 0x1010);
    g_assert_cmphex(report.ip_before, ==, 0x1000);
    g_assert_cmphex(report.ip_after, ==, 0x1010);
    g_assert_cmpint(report.failed_slot, ==, -1);
    g_assert_nonnull(strstr(report.message, "executed IA-64 NOP"));
}

static void test_unsupported_instruction_message(void)
{
    const uint64_t mov_r3_ip_raw = 0x1800000c0ULL;
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64InsnReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x2000;
    make_bundle(bundle, 0x00,
                IA64_INSN_NOP_RAW, mov_r3_ip_raw, IA64_INSN_NOP_RAW);

    g_assert_cmpint(ia64_insn_exec_bundle(&env, bundle, &report), ==,
                    IA64_INSN_UNSUPPORTED_SLOT);
    g_assert_cmphex(env.ip, ==, 0x2000);
    g_assert_cmpint(report.failed_slot, ==, 1);
    g_assert_nonnull(strstr(report.message,
                           "unsupported IA-64 instruction"));
    g_assert_nonnull(strstr(report.message, "slot=1"));
    g_assert_nonnull(strstr(report.message, "type=I"));
    g_assert_nonnull(strstr(report.message, "raw=0x001800000c0"));
}

static void test_m34_alloc_updates_frame_state(void)
{
    const uint64_t elilo_alloc_raw = 0x02c0040c880ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(2, 1, 0));
    env.ar[IA64_AR_PFS] = 0x12345678;

    g_assert_true(ia64_slot_is_m34_alloc(IA64_SLOT_TYPE_M, elilo_alloc_raw));
    g_assert_true(ia64_exec_m34_alloc(&env, elilo_alloc_raw));

    g_assert_cmphex(ia64_read_gr(&env, 34), ==, 0x12345678);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, 0x12345678);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.sof, ==, 6);
    g_assert_cmpuint(env.rse.sol, ==, 4);
    g_assert_cmpuint(env.rse.sor, ==, 0);
}

static void test_frame_state_updates_preserve_interruption_frame_state(void)
{
    const uint64_t elilo_alloc_raw = 0x02c0040c880ULL;
    const uint64_t br_ctop_raw = 0x080000001c0ULL;
    const uint64_t clrrrb_raw = 0x04ULL << 27;
    const uint64_t cfm_with_rrb = ia64_make_cfm(8, 3, 1) |
        (5ULL << 18) | (6ULL << 25) | (7ULL << 32);
    const uint64_t saved_ifs = 0x8000000000003333ULL;
    CPUIA64State env;
    uint64_t target = 0;
    bool taken = false;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_IFS] = saved_ifs;
    ia64_set_cfm(&env, ia64_make_cfm(2, 1, 0));
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);

    g_assert_true(ia64_exec_m34_alloc(&env, elilo_alloc_raw));
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);

    ia64_set_cfm(&env, ia64_make_cfm(8, 3, 1));
    env.ar[IA64_AR_LC] = 1;
    g_assert_true(ia64_exec_b_branch_relative(&env, br_ctop_raw, 0x2000,
                                              &target, &taken));
    g_assert_true(taken);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 7);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 95);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 47);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);

    ia64_set_cfm(&env, cfm_with_rrb);
    g_assert_true(ia64_exec_b_indirect_branch(&env, clrrrb_raw, 0x2010,
                                              &target));
    g_assert_cmpuint(env.rse.rrb_gr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);
}

static void test_rse_backing_store_address_helpers(void)
{
    const uint64_t br_call_raw = 0x0a006ba6000ULL;
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    uint64_t address;
    CPUIA64State env;
    uint64_t target = 0;

    g_assert_cmphex(ia64_rse_skip_regs(0x1000, 63), ==, 0x1200);
    g_assert_cmphex(ia64_rse_skip_regs(0x1010, -4), ==, 0x0fe8);
    g_assert_cmpuint(ia64_rse_num_regs(0x1000, 0x1200), ==, 63);
    g_assert_cmphex(ia64_rse_reg_address(0x11f8), ==, 0x1200);

    address = ia64_rse_skip_regs(0x1000, 62);
    g_assert_cmphex(address, ==, 0x11f0);
    address = ia64_rse_reg_address(address + 8);
    g_assert_cmphex(address, ==, ia64_rse_skip_regs(0x1000, 63));
    address = ia64_rse_reg_address(address + 8);
    g_assert_cmphex(address, ==, ia64_rse_skip_regs(0x1000, 64));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.bspstore = 0x1000;
    env.rse.bsp = 0x1000;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    ia64_set_cfm(&env, ia64_make_cfm(6, 4, 0));

    g_assert_true(ia64_exec_b_call_relative(&env, br_call_raw, 0x1001030,
                                            &target));
    g_assert_cmphex(env.rse.bsp, ==, 0x1020);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, 0x1020);

    env.br[0] = 0x1001047;
    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));
    g_assert_cmphex(env.rse.bsp, ==, 0x1000);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, 0x1000);
}

static void test_rse_stacked_write_marks_clean_register_dirty(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 100;
    env.rse.clean_count = 104;
    ia64_set_cfm(&env, ia64_make_cfm(4, 4, 0));

    ia64_write_gr(&env, 33, 0xa000000100825380ULL);

    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0xa000000100825380ULL);
    g_assert_cmphex(env.rse.stacked_gr[101], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, UINT64_C(1) << 1);
    g_assert_cmpuint(env.rse.clean_count, ==, 104);

    ia64_rse_sync_logical_out(&env);

    g_assert_cmphex(env.rse.stacked_gr[101], ==,
                    0xa000000100825380ULL);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
    g_assert_cmpuint(env.rse.clean_count, ==, 101);
}

static void test_rse_bspstore_write_preserves_dirty_boundary(void)
{
    const uint64_t mov_ar_bspstore_r33_raw =
        (0x2aULL << 27) | (18ULL << 20) | (33ULL << 13);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 104;
    env.rse.clean_count = 101;
    env.rse.bspstore = 0x2000;
    env.rse.bsp = 0x2000;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.rse.rnat = UINT64_C(1) << 12;
    ia64_rse_sync_rnat(&env);
    ia64_write_gr(&env, 33, 0x3018);

    g_assert_true(ia64_slot_is_mov_to_application(IA64_SLOT_TYPE_I,
                                                  mov_ar_bspstore_r33_raw));
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_ar_bspstore_r33_raw));
    g_assert_cmphex(env.rse.bspstore, ==, 0x3018);
    /* RNAT is undefined architecturally; the model preserves its bits. */
    g_assert_cmphex(env.rse.rnat, ==, UINT64_C(1) << 12);
    g_assert_cmphex(env.ar[IA64_AR_RNAT], ==, UINT64_C(1) << 12);
    g_assert_cmpuint(env.rse.clean_count, ==, 0);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_rse_rsc_privilege_clamp_matrix(void)
{
    const uint64_t mov_ar_rsc_r33_raw =
        (UINT64_C(0x2a) << 27) | (UINT64_C(16) << 20) |
        (UINT64_C(33) << 13);

    for (uint32_t cpl = 0; cpl < 4; cpl++) {
        for (uint32_t requested = 0; requested < 4; requested++) {
            CPUIA64State env;
            uint64_t value = UINT64_C(0x23400013) |
                             ((uint64_t)requested << IA64_RSC_PL_SHIFT);
            uint64_t expected_pl = MAX(cpl, requested);
            uint64_t expected = (value & ~IA64_RSC_PL_MASK) |
                                (expected_pl << IA64_RSC_PL_SHIFT);

            ia64_cpu_reset_synthetic_itanium2(&env);
            env.psr = (uint64_t)cpl << IA64_PSR_CPL_SHIFT;
            ia64_write_gr(&env, 33, value);
            g_assert_true(ia64_exec_mov_to_application(
                &env, IA64_SLOT_TYPE_I, mov_ar_rsc_r33_raw));
            g_assert_cmphex(env.rse.rsc, ==, expected);
            g_assert_cmphex(env.ar[IA64_AR_RSC], ==, expected);
            g_assert_cmphex(env.rse.loadrs, ==,
                            (expected >> IA64_RSC_LOADRS_SHIFT) &
                            IA64_RSC_LOADRS_MASK);
        }
    }
}

static bool test_platform_break_handler(CPUIA64State *env, uint64_t iim)
{
    ia64_write_gr(env, 8, iim);
    return iim == 0x80015;
}

static void test_platform_break_handler_survives_reset(void)
{
    CPUIA64State env = { 0 };

    env.platform_break_handler = test_platform_break_handler;
    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_try_platform_break(&env, 0x80015));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x80015);
    g_assert_false(ia64_try_platform_break(&env, 0x80014));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x80014);
}

static void test_rse_loadrs_dirty_partition_survives_bspstore_switch(void)
{
    const uint64_t mov_ar_bspstore_r33_raw =
        (0x2aULL << 27) | (18ULL << 20) | (33ULL << 13);
    CPUIA64State env;
    uint32_t dirty;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 32;
    env.rse.bspstore = 0x2000;
    env.rse.bsp = 0x2000;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;

    ia64_rse_mark_dirty_partition(&env, 10);
    dirty = ia64_rse_num_regs(env.rse.bspstore, env.rse.bsp);

    g_assert_cmpuint(dirty, ==, 10);
    g_assert_cmphex(env.rse.bsp, ==, ia64_rse_skip_regs(0x2000, 10));
    g_assert_cmpuint(env.rse.clean_count, ==, 0);

    ia64_write_gr(&env, 33, 0x6000);
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_ar_bspstore_r33_raw));

    g_assert_cmphex(env.rse.bspstore, ==, 0x6000);
    g_assert_cmphex(env.rse.bsp, ==, ia64_rse_skip_regs(0x6000, 10));
    g_assert_cmpuint(ia64_rse_num_regs(env.rse.bspstore, env.rse.bsp), ==, 10);
}

typedef struct TestRSEBackingStore {
    uint64_t first_address;
    uint64_t value[16];
    uint32_t read_count;
    bool forbid_reads;
} TestRSEBackingStore;

static uint64_t test_rse_read_backing_store_register(CPUIA64State *env,
                                                     uint64_t address,
                                                     void *opaque)
{
    TestRSEBackingStore *store = opaque;
    uint32_t index;

    g_assert_nonnull(env);
    g_assert_nonnull(store);
    g_assert_false(store->forbid_reads);
    g_assert_cmphex(address, >=, store->first_address);

    index = (address - store->first_address) / 8;
    g_assert_cmpuint(index, <, G_N_ELEMENTS(store->value));
    store->read_count++;
    return store->value[index];
}

static void test_rse_loadrs_preserves_dirty_frame_uncovered_by_rfi(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t interrupted_cfm = ia64_make_cfm(8, 3, 0);
    const uint64_t expected[8] = {
        0x1000000000000000ULL, 0x2111111111111111ULL,
        0x3222222222222222ULL, 0x4333333333333333ULL,
        0x5444444444444444ULL, 0x6555555555555555ULL,
        0x7666666666666666ULL, 0x8777777777777777ULL,
    };
    TestRSEBackingStore store = {
        .first_address = 0x6000,
        .value = {
            0xdead000000000000ULL, 0xdead111111111111ULL,
            0xdead222222222222ULL, 0xdead333333333333ULL,
            0xdead444444444444ULL, 0xdead555555555555ULL,
            0xdead666666666666ULL, 0xdead777777777777ULL,
        },
        .forbid_reads = true,
    };
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    /*
     * Model the covered eight-register interruption frame immediately below
     * the handler's empty frame.  In the 96-register physical file BOF is p8;
     * current_frame_base alone is not enough to describe that mapping.
     */
    env.rse.bol = G_N_ELEMENTS(expected);
    env.rse.current_frame_base = 19;
    ia64_set_cfm(&env, 0);
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xdead000000000000ULL | i;
    }
    for (uint32_t i = 0; i < G_N_ELEMENTS(expected); i++) {
        env.rse.stacked_gr[11 + i] = expected[i];
    }

    env.rse.bspstore = store.first_address;
    env.rse.bsp = ia64_rse_skip_regs(store.first_address,
                                     G_N_ELEMENTS(expected));
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;

    ia64_rse_load_dirty_partition(&env, store.first_address, env.rse.bsp,
                                  test_rse_read_backing_store_register,
                                  &store);
    ia64_rse_set_dirty_partition(&env, store.first_address, env.rse.bsp);

    g_assert_cmpuint(ia64_rse_dirty_partition_first_slot(
                         &env, G_N_ELEMENTS(expected)), ==, 11);
    g_assert_cmpuint(store.read_count, ==, 0);
    g_assert_cmphex(env.rse.stacked_gr[11], ==, expected[0]);
    g_assert_cmphex(env.rse.stacked_gr[18], ==, expected[7]);
    g_assert_cmphex(env.rse.stacked_gr[19], ==,
                    0xdead000000000000ULL | 19);

    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0x2000000000118397ULL;
    env.cr[IA64_CR_IFS] = interrupted_cfm | IA64_IFS_VALID_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0xa00000010000bfb0,
                                              &target));
    g_assert_cmphex(target, ==, 0x2000000000118390ULL);
    g_assert_cmphex(env.cfm, ==, interrupted_cfm);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 11);
    for (uint32_t i = 0; i < G_N_ELEMENTS(expected); i++) {
        g_assert_cmphex(ia64_read_gr(&env, 32 + i), ==, expected[i]);
    }
}

static void test_rse_loadrs_reads_clean_prefix_only(void)
{
    const uint64_t dirty[4] = {
        0xd100000000000000ULL, 0xd211111111111111ULL,
        0xd322222222222222ULL, 0xd433333333333333ULL,
    };
    TestRSEBackingStore store = {
        .first_address = 0x6000,
        .value = {
            0xc100000000000000ULL, 0xc211111111111111ULL,
            0xc322222222222222ULL, 0xc433333333333333ULL,
        },
    };
    CPUIA64State env;
    uint64_t start = store.first_address;
    uint64_t mid = ia64_rse_skip_regs(start, 4);
    uint64_t end = ia64_rse_skip_regs(start, 8);

    ia64_cpu_reset_synthetic_itanium2(&env);
    /* Four clean plus four dirty registers precede the empty frame. */
    env.rse.bol = 8;
    env.rse.current_frame_base = 12;
    ia64_set_cfm(&env, 0);
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xdead000000000000ULL | i;
    }
    for (uint32_t i = 0; i < G_N_ELEMENTS(dirty); i++) {
        env.rse.stacked_gr[8 + i] = dirty[i];
    }
    env.rse.bspstore = mid;
    env.rse.bsp = end;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;

    ia64_rse_load_dirty_partition(&env, start, end,
                                  test_rse_read_backing_store_register,
                                  &store);
    ia64_rse_set_dirty_partition(&env, start, end);

    g_assert_cmpuint(store.read_count, ==, 4);
    for (uint32_t i = 0; i < 4; i++) {
        g_assert_cmphex(env.rse.stacked_gr[4 + i], ==, store.value[i]);
        g_assert_cmphex(env.rse.stacked_gr[8 + i], ==, dirty[i]);
    }
    g_assert_cmphex(env.rse.bspstore, ==, start);
    g_assert_cmphex(env.rse.bsp, ==, end);
    g_assert_cmpuint(env.rse.clean_count, ==, 0);
}

static void test_rse_load_restores_nat_from_rnat_collection(void)
{
    const uint64_t start = 0x61e0;
    const uint64_t rnat = (UINT64_C(1) << 60) | (UINT64_C(1) << 62);
    TestRSEBackingStore store = {
        .first_address = start,
        .value = {
            0xa100000000000000ULL, 0xa211111111111111ULL,
            0xa322222222222222ULL, rnat,
            0xa433333333333333ULL, 0xa544444444444444ULL,
        },
    };
    CPUIA64State env;
    uint64_t end = ia64_rse_skip_regs(start, 5);

    ia64_cpu_reset_synthetic_itanium2(&env);
    /* The five loaded registers occupy the physical slots below BOF. */
    env.rse.bol = 5;
    env.rse.current_frame_base = 20;
    env.rse.rnat = UINT64_C(1);
    ia64_rse_sync_rnat(&env);
    ia64_rse_load_dirty_partition(&env, start, end,
                                  test_rse_read_backing_store_register,
                                  &store);
    ia64_rse_set_dirty_partition(&env, start, end);

    g_assert_cmpuint(store.read_count, ==, 6);
    g_assert_cmphex(env.rse.stacked_gr[15], ==, store.value[0]);
    g_assert_cmphex(env.rse.stacked_gr[16], ==, store.value[1]);
    g_assert_cmphex(env.rse.stacked_gr[17], ==, store.value[2]);
    g_assert_cmphex(env.rse.stacked_gr[18], ==, store.value[4]);
    g_assert_cmphex(env.rse.stacked_gr[19], ==, store.value[5]);
    g_assert_true(ia64_rse_read_physical_nat(&env, 15));
    g_assert_false(ia64_rse_read_physical_nat(&env, 16));
    g_assert_true(ia64_rse_read_physical_nat(&env, 17));
    g_assert_true(ia64_rse_read_physical_nat(&env, 18));
    g_assert_false(ia64_rse_read_physical_nat(&env, 19));
}

static void test_rse_restored_frame_uses_bsp_load(void)
{
    TestRSEBackingStore store = {
        .first_address = 0x6000,
        .value = {
            0xa100000000000000ULL, 0xa211111111111111ULL,
            0xa322222222222222ULL, 0xa433333333333333ULL,
        },
    };
    CPUIA64State env;
    uint32_t filled;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 12;
    env.rse.bsp = store.first_address;
    env.rse.bspstore = store.first_address;
    env.rse.bsp_load = ia64_rse_skip_regs(store.first_address, 4);
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xdead000000000000ULL | i;
    }

    filled = ia64_rse_load_restored_frame(
        &env, 4, test_rse_read_backing_store_register, &store);

    g_assert_cmpuint(filled, ==, 4);
    g_assert_cmpuint(store.read_count, ==, 4);
    for (uint32_t i = 0; i < 4; i++) {
        g_assert_cmphex(env.rse.stacked_gr[12 + i], ==, store.value[i]);
        g_assert_cmphex(ia64_read_gr(&env, 32 + i), ==, store.value[i]);
    }
    g_assert_cmphex(env.rse.bsp, ==, store.first_address);
    g_assert_cmphex(env.rse.bspstore, ==, store.first_address);
    g_assert_cmphex(env.rse.bsp_load, ==, store.first_address);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, store.first_address);
    g_assert_cmphex(env.ar[IA64_AR_BSPSTORE], ==, store.first_address);
}

static void test_rse_reconstructs_clean_partition_after_load(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 17;
    env.rse.clean_count = 0;
    env.rse.bspstore = 0x4000;
    env.rse.bsp = 0x4000;

    ia64_rse_reconstruct_transients(&env);

    g_assert_cmpuint(env.rse.clean_count, ==, 0);

    env.rse.clean_count = 17;
    env.rse.bsp = ia64_rse_skip_regs(env.rse.bspstore, 3);

    ia64_rse_reconstruct_transients(&env);

    g_assert_cmpuint(env.rse.clean_count, ==, 0);

    env.rse.clean_count = 17;
    env.rse.bsp = ia64_rse_skip_regs(env.rse.bspstore, 20);

    ia64_rse_reconstruct_transients(&env);

    g_assert_cmpuint(env.rse.clean_count, ==, 0);

    env.rse.clean_count = 17;
    env.rse.bspstore = 0;
    env.rse.bsp = 0;

    ia64_rse_reconstruct_transients(&env);

    g_assert_cmpuint(env.rse.clean_count, ==, 0);
}

typedef struct TestRSEWriteCapture {
    uint64_t address[32];
    uint64_t value[32];
    uint32_t count;
} TestRSEWriteCapture;

static void test_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque)
{
    TestRSEWriteCapture *capture = opaque;

    g_assert_nonnull(env);
    g_assert_nonnull(capture);
    g_assert_cmpuint(capture->count, <, G_N_ELEMENTS(capture->address));
    capture->address[capture->count] = address;
    capture->value[capture->count] = value;
    capture->count++;
}

static void test_rse_alloc_spill_keeps_physical_bound(void)
{
    TestRSEWriteCapture capture = { 0 };
    CPUIA64State env;
    uint64_t address;
    uint32_t spilled;

    ia64_cpu_reset_synthetic_itanium2(&env);
    /*
     * 90 dirty registers below the current frame, backing store positioned
     * so the spill crosses a NaT-collection slot (0x61f8 has slot number
     * 0x3f).  Growing the frame to sof=20 exceeds the 96-register physical
     * file by 14, so exactly the 14 oldest dirty registers must spill.
     */
    env.rse.bol = 90;
    env.rse.current_frame_base = 90;
    env.rse.bspstore = 0x61e0;
    env.rse.bsp = ia64_rse_skip_regs(env.rse.bspstore, 90);
    env.rse.bsp_load = env.rse.bspstore;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.rse.dirty = 90;
    env.rse.dirty_nat =
        (env.rse.bsp - env.rse.bspstore) / 8 - 90;
    env.rse.invalid = 6;
    env.rse.rnat = 0;
    ia64_rse_sync_rnat(&env);
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xb0d0000000000000ULL | i;
    }
    ia64_rse_write_physical_nat(&env, 1, true);
    ia64_rse_write_physical_nat(&env, 4, true);

    spilled = ia64_rse_spill_excess_dirty(
        &env, 20, test_rse_write_backing_store_register, &capture);

    g_assert_cmpuint(spilled, ==, 14);
    g_assert_cmpuint(capture.count, ==, 15);
    address = 0x61e0;
    for (uint32_t i = 0, reg = 0; i < capture.count; i++) {
        g_assert_cmphex(capture.address[i], ==, address);
        if (ia64_rse_address_is_rnat_slot(address)) {
            g_assert_cmphex(capture.value[i], ==,
                            UINT64_C(1) << 61);
        } else {
            g_assert_cmphex(capture.value[i], ==,
                            0xb0d0000000000000ULL | reg);
            reg++;
        }
        address += 8;
    }
    g_assert_cmphex(capture.address[3], ==, 0x61f8);
    g_assert_cmphex(capture.address[4], ==, 0x6200);
    g_assert_cmphex(env.rse.bspstore, ==,
                    ia64_rse_skip_regs(0x61e0, 14));
    g_assert_cmphex(env.rse.bsp_load, ==, env.rse.bspstore);
    g_assert_cmphex(env.rse.rnat, ==, UINT64_C(1) << 1);
    g_assert_cmphex(env.ar[IA64_AR_RNAT], ==, env.rse.rnat);
    g_assert_cmphex(env.ar[IA64_AR_BSPSTORE], ==, env.rse.bspstore);
    g_assert_cmpuint(ia64_rse_num_regs(env.rse.bspstore, env.rse.bsp) + 20,
                     ==, IA64_RSE_PHYS_STACKED_REGS);
    g_assert_cmpuint(env.rse.clean_count, ==, 14);
}

static void test_rse_alloc_spill_noop_paths(void)
{
    TestRSEWriteCapture capture = { 0 };
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.bol = 50;
    env.rse.current_frame_base = 50;
    env.rse.bspstore = 0x6000;
    env.rse.bsp = ia64_rse_skip_regs(env.rse.bspstore, 50);
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.rse.dirty = 50;
    env.rse.dirty_nat =
        (env.rse.bsp - env.rse.bspstore) / 8 - 50;
    env.rse.invalid = 46;

    /* dirty (50) + sof (40) fits in the physical file: no spill. */
    g_assert_cmpuint(ia64_rse_spill_excess_dirty(
                         &env, 40, test_rse_write_backing_store_register,
                         &capture),
                     ==, 0);
    g_assert_cmpuint(capture.count, ==, 0);
    g_assert_cmphex(env.rse.bspstore, ==, 0x6000);

    /* An uninitialized backing store never spills. */
    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_cmpuint(ia64_rse_spill_excess_dirty(
                         &env, 96, test_rse_write_backing_store_register,
                         &capture),
                     ==, 0);
    g_assert_cmpuint(capture.count, ==, 0);
}

static uint64_t test_rse_walk_forward(uint64_t address, uint32_t registers)
{
    while (registers-- != 0) {
        if (((address >> 3) & 0x3f) == 0x3f) {
            address += 8;
        }
        address += 8;
    }
    return address;
}

static uint64_t test_rse_walk_backward(uint64_t address, uint32_t registers)
{
    while (registers-- != 0) {
        address -= 8;
        if (((address >> 3) & 0x3f) == 0x3f) {
            address -= 8;
        }
    }
    return address;
}

static void test_rse_init_complete(CPUIA64State *env, uint32_t sof,
                                   uint32_t bol, uint32_t origin,
                                   uint64_t bsp, uint32_t dirty,
                                   uint32_t clean)
{
    uint64_t bspstore;
    uint64_t clean_start;

    g_assert_cmpuint(sof + dirty + clean, <=,
                     IA64_RSE_PHYS_STACKED_REGS);
    ia64_cpu_reset_synthetic_itanium2(env);
    env->rse.bol = bol;
    env->rse.current_frame_base = ia64_rse_wrap_slot(origin + bol);
    ia64_set_cfm(env, ia64_make_cfm(sof, 0, 0));

    bspstore = test_rse_walk_backward(bsp, dirty);
    clean_start = test_rse_walk_backward(bspstore, clean);
    env->rse.bsp = bsp;
    env->rse.bspstore = bspstore;
    env->rse.bsp_load = bspstore;
    env->rse.dirty = dirty;
    env->rse.dirty_nat = (bsp - bspstore) / 8 - dirty;
    env->rse.clean = clean;
    env->rse.clean_nat = (bspstore - clean_start) / 8 - clean;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS - sof - dirty - clean;
    env->ar[IA64_AR_BSP] = bsp;
    env->ar[IA64_AR_BSPSTORE] = bspstore;
    g_assert_true(ia64_rse_partitions_valid(env));
}

typedef struct TestRSEPristineReturnRow {
    const char *path;
    uint32_t sol;
    uint32_t expected_bol;
    int32_t expected_dirty;
    int32_t expected_invalid;
    uint64_t expected_bsp;
    bool expected_cfle;
} TestRSEPristineReturnRow;

static const TestRSEPristineReturnRow pristine_return_rows[] = {
    {
        .path = "/ia64-insn/rse-pristine-return/growth",
        .sol = 0,
        .expected_bol = 0,
        .expected_dirty = 0,
        .expected_invalid = IA64_RSE_PHYS_STACKED_REGS - 4,
        .expected_bsp = 0x1240,
        .expected_cfle = false,
    },
    {
        .path = "/ia64-insn/rse-pristine-return/missing-preserved",
        .sol = 4,
        .expected_bol = IA64_RSE_PHYS_STACKED_REGS - 4,
        .expected_dirty = -4,
        .expected_invalid = IA64_RSE_PHYS_STACKED_REGS,
        .expected_bsp = 0x1220,
        .expected_cfle = true,
    },
};

static void test_rse_pristine_return_row(gconstpointer opaque)
{
    const TestRSEPristineReturnRow *row = opaque;
    const uint64_t cfm = ia64_make_cfm(4, row->sol, 0);
    CPUIA64State env;

    test_rse_init_complete(&env, 0, 0, 0, 0x1240, 0, 0);

    g_assert_false(ia64_rse_return_frame_from_pfs(
        &env, ia64_make_pfs(cfm, 0x2a, 0)));

    g_assert_cmphex(env.cfm, ==, cfm);
    g_assert_cmpuint(env.rse.bol, ==, row->expected_bol);
    g_assert_cmpuint(env.rse.current_frame_base, ==, row->expected_bol);
    g_assert_cmpint(env.rse.dirty, ==, row->expected_dirty);
    g_assert_cmpint(env.rse.clean, ==, 0);
    g_assert_cmpint(env.rse.invalid, ==, row->expected_invalid);
    g_assert_cmphex(env.rse.bsp, ==, row->expected_bsp);
    g_assert_cmphex(env.rse.bspstore, ==, 0x1240);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, 0x2a);
    g_assert_cmpint(env.rse.cfle, ==, row->expected_cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_rse_return_partition_rows(void)
{
    CPUIA64State env;
    uint64_t pfs;
    uint64_t old_bspstore;
    uint64_t expected_bsp;
    uint32_t expected_bol;
    uint32_t origin = IA64_STACKED_GR_COUNT - 17;

    test_rse_init_complete(&env, 4, 94, origin, 0x3500, 10, 12);
    for (uint32_t physical = 0;
         physical < IA64_RSE_PHYS_STACKED_REGS; physical++) {
        env.rse.stacked_gr[
            ia64_rse_physical_to_storage(&env, physical)] =
            UINT64_C(0x5100000000000000) | physical;
    }
    ia64_rse_sync_logical_in(&env);
    old_bspstore = env.rse.bspstore;
    expected_bsp = test_rse_walk_backward(env.rse.bsp, 6);
    expected_bol = ia64_rse_wrap_physical(94 - 6);
    env.psr = UINT64_C(2) << IA64_PSR_CPL_SHIFT;
    pfs = ia64_make_pfs(
        ia64_make_cfm(12, 6, 1) | (UINT64_C(5) << 18) |
        (UINT64_C(13) << 25) | (UINT64_C(17) << 32), 0x2a, 3);

    g_assert_false(ia64_rse_return_frame_from_pfs(&env, pfs));
    g_assert_cmphex(env.cfm, ==, pfs & IA64_PFS_CFM_MASK);
    g_assert_cmpuint(env.rse.bol, ==, expected_bol);
    g_assert_cmpuint(env.rse.current_frame_base, ==,
                     ia64_rse_wrap_slot(origin + expected_bol));
    g_assert_cmphex(env.rse.bsp, ==, expected_bsp);
    g_assert_cmphex(env.rse.bspstore, ==, old_bspstore);
    g_assert_cmpint(env.rse.dirty, ==, 4);
    g_assert_cmpint(env.rse.clean, ==, 12);
    g_assert_cmpint(env.rse.invalid, ==, 68);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, 0x2a);
    g_assert_cmpuint((env.psr >> IA64_PSR_CPL_SHIFT) & 3, ==, 3);
    g_assert_false(env.rse.cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));
    /* Restored SOR=1 and RRB.GR=5 rename logical r32 to BOF+5. */
    g_assert_cmphex(ia64_read_gr(&env, 32), ==,
                    UINT64_C(0x5100000000000000) |
                    ia64_rse_wrap_physical(expected_bol + 5));

    test_rse_init_complete(&env, 40, 7, 100, 0x5000, 20, 0);
    old_bspstore = env.rse.bspstore;
    expected_bsp = test_rse_walk_backward(env.rse.bsp, 10);
    pfs = ia64_make_pfs(ia64_make_cfm(96, 10, 0), 0x15, 0);
    g_assert_true(ia64_rse_return_frame_from_pfs(&env, pfs));
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmphex(env.rse.bsp, ==, expected_bsp);
    g_assert_cmphex(env.rse.bspstore, ==, old_bspstore);
    g_assert_cmpint(env.rse.dirty, ==, 10);
    g_assert_cmpint(env.rse.invalid, ==, 86);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, 0x15);
    g_assert_false(env.rse.cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_rse_return_cpl_demotion_matrix(void)
{
    for (uint32_t cpl = 0; cpl < 4; cpl++) {
        for (uint32_t ppl = 0; ppl < 4; ppl++) {
            CPUIA64State env;
            uint32_t expected = cpl < ppl ? ppl : cpl;

            test_rse_init_complete(&env, 0, 0, 0, 0, 0, 0);
            env.psr = (uint64_t)cpl << IA64_PSR_CPL_SHIFT;
            g_assert_false(ia64_rse_return_frame_from_pfs(
                &env, ia64_make_pfs(0, 7, ppl)));
            g_assert_cmpuint((env.psr >> IA64_PSR_CPL_SHIFT) & 3,
                             ==, expected);
            g_assert_cmphex(env.ar[IA64_AR_EC], ==, 7);
            g_assert_true(ia64_rse_partitions_valid(&env));
        }
    }
}

typedef struct TestRSEBadPFSReturnRow {
    const char *path;
    uint32_t current_cpl;
    uint32_t restored_ppl;
    uint32_t restored_ec;
    uint64_t trap_bits;
    IA64ExceptionKind expected_trap;
    uint64_t expected_vector;
    uint64_t expected_isr_code;
} TestRSEBadPFSReturnRow;

static const TestRSEBadPFSReturnRow bad_pfs_return_rows[] = {
    {
        .path = "/ia64-insn/rse-bad-pfs-return/lp-demotion",
        .current_cpl = 0,
        .restored_ppl = 3,
        .restored_ec = 0x2a,
        .trap_bits = IA64_PSR_LP_BIT,
        .expected_trap = IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER,
        .expected_vector = 0x5e00,
        .expected_isr_code = UINT64_C(1) << 1,
    },
    {
        .path = "/ia64-insn/rse-bad-pfs-return/lp-priority-over-tb",
        .current_cpl = 1,
        .restored_ppl = 3,
        .restored_ec = 0x15,
        .trap_bits = IA64_PSR_LP_BIT | IA64_PSR_TB_BIT,
        .expected_trap = IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER,
        .expected_vector = 0x5e00,
        .expected_isr_code = (UINT64_C(1) << 1) | (UINT64_C(1) << 2),
    },
    {
        .path = "/ia64-insn/rse-bad-pfs-return/tb-with-lp-disabled",
        .current_cpl = 0,
        .restored_ppl = 3,
        .restored_ec = 0x3f,
        .trap_bits = IA64_PSR_TB_BIT,
        .expected_trap = IA64_EXCEPTION_TAKEN_BRANCH_TRAP,
        .expected_vector = 0x5f00,
        .expected_isr_code = UINT64_C(1) << 2,
    },
    {
        .path = "/ia64-insn/rse-bad-pfs-return/tb-without-demotion",
        .current_cpl = 2,
        .restored_ppl = 1,
        .restored_ec = 0x08,
        .trap_bits = IA64_PSR_LP_BIT | IA64_PSR_TB_BIT,
        .expected_trap = IA64_EXCEPTION_TAKEN_BRANCH_TRAP,
        .expected_vector = 0x5f00,
        .expected_isr_code = UINT64_C(1) << 2,
    },
    {
        .path = "/ia64-insn/rse-bad-pfs-return/lp-without-demotion",
        .current_cpl = 3,
        .restored_ppl = 0,
        .restored_ec = 0x01,
        .trap_bits = IA64_PSR_LP_BIT,
        .expected_trap = IA64_EXCEPTION_NONE,
    },
};

static void test_rse_bad_pfs_return_row(gconstpointer opaque)
{
    const TestRSEBadPFSReturnRow *row = opaque;
    const uint64_t source_bundle = UINT64_C(0xa000000100100000);
    const uint64_t requested_target = UINT64_C(0xa00000010020000f);
    const uint64_t committed_target = requested_target & ~UINT64_C(0xf);
    const uint32_t source_slot = row - bad_pfs_return_rows;
    const uint32_t expected_cpl = MAX(row->current_cpl, row->restored_ppl);
    const bool demoted = expected_cpl > row->current_cpl;
    const bool lower_privilege_eligible =
        demoted && (row->trap_bits & IA64_PSR_LP_BIT) != 0;
    const bool taken_branch_eligible =
        (row->trap_bits & IA64_PSR_TB_BIT) != 0;
    CPUIA64State env;
    uint64_t target_psr;

    /*
     * old SOF=40 leaves 36 invalid registers.  Restoring SOF=96/SOL=10
     * requires growth by 46, which cannot fit in invalid+clean and therefore
     * deterministically selects the SDM 6.5.5 bad-PFS return path.
     */
    test_rse_init_complete(&env, 40, 7, 100, 0x5000, 20, 0);
    env.ip = source_bundle;
    env.psr = IA64_PSR_IC_BIT | row->trap_bits |
              ((uint64_t)row->current_cpl << IA64_PSR_CPL_SHIFT);
    env.cr[IA64_CR_IVA] = UINT64_C(0xa000000000000000);
    env.last_successful_bundle = source_bundle;
    env.current_slot_valid = true;
    env.current_slot_ip = source_bundle;
    env.current_slot_ri = source_slot % 3;
    env.current_slot_type = IA64_SLOT_TYPE_B;
    env.current_slot_raw = UINT64_C(0x00108000100); /* br.ret b0 */
    env.ar[IA64_AR_PFS] = ia64_make_pfs(
        ia64_make_cfm(96, 10, 0), row->restored_ec, row->restored_ppl);

    /* Bad PFS changes the restored CFM to zero; it is not a fault. */
    g_assert_true(ia64_return_from_call_frame(&env, requested_target));
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_NONE);
    g_assert_false(env.exception.pending);
    g_assert_cmphex(env.ip, ==, committed_target);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, row->restored_ec);
    g_assert_cmpuint((env.psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT,
                     ==, expected_cpl);
    g_assert_cmphex(env.psr & (IA64_PSR_LP_BIT | IA64_PSR_TB_BIT), ==,
                    row->trap_bits);
    g_assert_false(env.rse.cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));

    /*
     * TCG implements this arbitration around the core return helper.  Keep
     * the helper/exception composition covered here: LP requires both an
     * actual CPL demotion and PSR.lp; otherwise PSR.tb remains eligible.
     */
    if (lower_privilege_eligible) {
        g_assert_cmpint(row->expected_trap, ==,
                        IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER);
    } else if (taken_branch_eligible) {
        g_assert_cmpint(row->expected_trap, ==,
                        IA64_EXCEPTION_TAKEN_BRANCH_TRAP);
    } else {
        g_assert_cmpint(row->expected_trap, ==, IA64_EXCEPTION_NONE);
    }

    if (row->expected_trap == IA64_EXCEPTION_NONE) {
        return;
    }

    target_psr = ia64_env_psr(&env);
    ia64_deliver_branch_trap(&env, row->expected_trap);

    g_assert_cmpint(env.exception.kind, ==, row->expected_trap);
    g_assert_cmphex(env.exception.vector, ==, row->expected_vector);
    g_assert_cmphex(env.exception.ip, ==, committed_target);
    g_assert_cmphex(env.exception.address, ==, committed_target);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, target_psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, committed_target);
    g_assert_cmphex(env.cr[IA64_CR_IIPA], ==, source_bundle);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & IA64_ISR_CODE_MASK, ==,
                    row->expected_isr_code);
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, source_slot % 3);
    g_assert_cmphex(env.ip, ==,
                    UINT64_C(0xa000000000000000) + row->expected_vector);
}

typedef struct TestRSEStepReader {
    uint64_t address[16];
    uint32_t word_count;
    uint32_t cursor;
    int32_t fail_at;
    int32_t interrupt_at;
    bool failed;
    bool interrupted;
    uint64_t rnat_value;
} TestRSEStepReader;

static uint64_t test_rse_step_value(const TestRSEStepReader *reader,
                                    uint64_t address)
{
    return ia64_rse_address_is_rnat_slot(address) ? reader->rnat_value :
        (UINT64_C(0xa500000000000000) ^ address);
}

static bool test_rse_step_read(CPUIA64State *env, uint64_t address,
                               uint64_t *value, void *opaque)
{
    TestRSEStepReader *reader = opaque;

    g_assert_nonnull(env);
    g_assert_cmpuint(reader->cursor, <, reader->word_count);
    g_assert_cmphex(address, ==, reader->address[reader->cursor]);
    if (!reader->failed && (int32_t)reader->cursor == reader->fail_at) {
        reader->failed = true;
        return false;
    }
    *value = test_rse_step_value(reader, address);
    reader->cursor++;
    return true;
}

static bool test_rse_step_interruption_pending(CPUIA64State *env,
                                               void *opaque)
{
    TestRSEStepReader *reader = opaque;

    g_assert_nonnull(env);
    if (!reader->interrupted && reader->interrupt_at >= 0 &&
        reader->cursor == (uint32_t)reader->interrupt_at) {
        reader->interrupted = true;
        return true;
    }
    return false;
}

static void test_rse_init_incomplete(CPUIA64State *env,
                                     TestRSEStepReader *reader,
                                     uint64_t bsp, uint32_t missing,
                                     uint32_t bol, uint32_t origin)
{
    uint64_t end = test_rse_walk_forward(bsp, missing);
    uint32_t words = (end - bsp) / 8;

    ia64_cpu_reset_synthetic_itanium2(env);
    env->rse.bol = bol;
    env->rse.current_frame_base = ia64_rse_wrap_slot(origin + bol);
    ia64_set_cfm(env, ia64_make_cfm(missing, 0, 0));
    env->rse.bsp = bsp;
    env->rse.bspstore = end;
    env->rse.bsp_load = end;
    env->rse.dirty = -(int32_t)missing;
    env->rse.dirty_nat = -(int32_t)(words - missing);
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS;
    env->rse.cfle = true;
    env->ar[IA64_AR_BSP] = bsp;
    env->ar[IA64_AR_BSPSTORE] = end;
    env->psr |= IA64_PSR_DA_BIT | IA64_PSR_DD_BIT;
    ia64_rse_sync_logical_in(env);

    memset(reader, 0, sizeof(*reader));
    reader->fail_at = -1;
    reader->interrupt_at = -1;
    reader->rnat_value = (UINT64_C(1) << 61) | (UINT64_C(1) << 62);
    reader->word_count = words;
    for (uint32_t i = 0; i < words; i++) {
        reader->address[i] = end - (uint64_t)(i + 1) * 8;
    }
    g_assert_true(ia64_rse_partitions_valid(env));
}

static void test_rse_assert_same_completed_frame(const CPUIA64State *left,
                                                 const CPUIA64State *right)
{
    g_assert_cmpint(left->rse.dirty, ==, right->rse.dirty);
    g_assert_cmpint(left->rse.dirty_nat, ==, right->rse.dirty_nat);
    g_assert_cmpint(left->rse.clean, ==, right->rse.clean);
    g_assert_cmpint(left->rse.clean_nat, ==, right->rse.clean_nat);
    g_assert_cmpint(left->rse.invalid, ==, right->rse.invalid);
    g_assert_cmphex(left->rse.bspstore, ==, right->rse.bspstore);
    g_assert_cmphex(left->rse.rnat, ==, right->rse.rnat);
    g_assert_cmpint(left->rse.cfle, ==, right->rse.cfle);
    g_assert_cmpint(memcmp(left->rse.stacked_gr, right->rse.stacked_gr,
                           sizeof(left->rse.stacked_gr)), ==, 0);
    g_assert_cmpint(memcmp(left->rse.stacked_nat, right->rse.stacked_nat,
                           sizeof(left->rse.stacked_nat)), ==, 0);
    g_assert_cmpint(memcmp(&left->gr[32], &right->gr[32],
                           96 * sizeof(left->gr[0])), ==, 0);
    g_assert_cmpint(memcmp(left->rse.logical_nat,
                           right->rse.logical_nat,
                           sizeof(left->rse.logical_nat)), ==, 0);
}

static void test_rse_fault_resume_register_rows(void)
{
    static const int32_t fault_rows[] = { 0, 2, 4 };

    for (uint32_t row = 0; row < G_N_ELEMENTS(fault_rows); row++) {
        CPUIA64State clean;
        CPUIA64State resumed;
        TestRSEStepReader clean_reader;
        TestRSEStepReader resumed_reader;
        int32_t fail_at = fault_rows[row];

        test_rse_init_incomplete(&clean, &clean_reader, 0x3000, 5, 13, 200);
        test_rse_init_incomplete(&resumed, &resumed_reader,
                                 0x3000, 5, 13, 200);
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &clean, test_rse_step_read, &clean_reader),
                        ==, IA64_RSE_STEP_DONE);

        resumed_reader.fail_at = fail_at;
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &resumed, test_rse_step_read, &resumed_reader),
                        ==, IA64_RSE_STEP_FAULT);
        g_assert_cmpint(resumed.rse.dirty, ==, -5 + fail_at);
        g_assert_cmphex(resumed.rse.bspstore, ==,
                        0x3000 + (uint64_t)(5 - fail_at) * 8);
        g_assert_true(resumed.rse.cfle);
        if (fail_at == 0) {
            g_assert_cmphex(resumed.psr &
                            (IA64_PSR_DA_BIT | IA64_PSR_DD_BIT), ==,
                            IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
        } else {
            g_assert_cmphex(resumed.psr &
                            (IA64_PSR_DA_BIT | IA64_PSR_DD_BIT), ==, 0);
        }
        g_assert_true(ia64_rse_partitions_valid(&resumed));

        /* Interruption delivery clears CFLE; rfi resumes the same next word. */
        resumed.rse.cfle = false;
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &resumed, test_rse_step_read, &resumed_reader),
                        ==, IA64_RSE_STEP_DONE);
        g_assert_cmpuint(resumed_reader.cursor, ==,
                         resumed_reader.word_count);
        test_rse_assert_same_completed_frame(&clean, &resumed);
        g_assert_true(ia64_rse_partitions_valid(&resumed));
    }
}

static void test_rse_fault_resume_rnat_rows(void)
{
    static const int32_t fault_rows[] = { 2, 3 };

    for (uint32_t row = 0; row < G_N_ELEMENTS(fault_rows); row++) {
        CPUIA64State clean;
        CPUIA64State resumed;
        TestRSEStepReader clean_reader;
        TestRSEStepReader resumed_reader;

        test_rse_init_incomplete(&clean, &clean_reader,
                                 0x1e8, 4, 94,
                                 IA64_STACKED_GR_COUNT - 6);
        test_rse_init_incomplete(&resumed, &resumed_reader,
                                 0x1e8, 4, 94,
                                 IA64_STACKED_GR_COUNT - 6);
        clean.rse.rnat = UINT64_C(1);
        resumed.rse.rnat = UINT64_C(1);
        clean_reader.rnat_value = resumed_reader.rnat_value =
            (UINT64_C(1) << 61) | (UINT64_C(1) << 62);
        g_assert_cmphex(clean_reader.address[2], ==, 0x1f8);

        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &clean, test_rse_step_read, &clean_reader),
                        ==, IA64_RSE_STEP_DONE);
        resumed_reader.fail_at = fault_rows[row];
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &resumed, test_rse_step_read, &resumed_reader),
                        ==, IA64_RSE_STEP_FAULT);
        g_assert_cmphex(resumed.rse.bspstore, ==,
                        0x210 - (uint64_t)fault_rows[row] * 8);
        if (fault_rows[row] == 2) {
            g_assert_cmpint(resumed.rse.dirty_nat, ==, -1);
        } else {
            g_assert_cmpint(resumed.rse.dirty_nat, ==, 0);
            g_assert_cmphex(resumed.rse.rnat, ==,
                            resumed_reader.rnat_value);
        }
        g_assert_true(resumed.rse.cfle);
        g_assert_true(ia64_rse_partitions_valid(&resumed));

        resumed.rse.cfle = false;
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &resumed, test_rse_step_read, &resumed_reader),
                        ==, IA64_RSE_STEP_DONE);
        test_rse_assert_same_completed_frame(&clean, &resumed);
        g_assert_true(ia64_read_gr_nat(&resumed, 32));
        g_assert_true(ia64_read_gr_nat(&resumed, 33));
        g_assert_true(ia64_read_gr_nat(&resumed, 34));
        g_assert_false(ia64_read_gr_nat(&resumed, 35));

        g_assert_cmphex(resumed.rse.stacked_gr[
                            ia64_rse_bof_offset_to_storage(&resumed, 0)], ==,
                        test_rse_step_value(&resumed_reader, 0x1e8));
        g_assert_cmphex(resumed.rse.stacked_gr[
                            ia64_rse_bof_offset_to_storage(&resumed, 3)], ==,
                        test_rse_step_value(&resumed_reader, 0x208));
        g_assert_cmpuint(ia64_rse_bof_offset_to_storage(&resumed, 2), ==,
                         IA64_STACKED_GR_COUNT - 6);
        g_assert_true(ia64_rse_partitions_valid(&resumed));
    }
}

static void test_rse_interruption_boundaries_for_frame(
    uint64_t bsp, uint32_t missing, uint32_t bol, uint32_t origin)
{
    TestRSEStepReader shape_reader;
    CPUIA64State shape;

    test_rse_init_incomplete(&shape, &shape_reader, bsp, missing, bol,
                             origin);
    for (uint32_t boundary = 0;
         boundary <= shape_reader.word_count; boundary++) {
        CPUIA64State clean;
        CPUIA64State interrupted;
        TestRSEStepReader clean_reader;
        TestRSEStepReader interrupted_reader;
        uint64_t prefix_bspstore;
        int32_t prefix_dirty;
        int32_t prefix_dirty_nat;

        test_rse_init_incomplete(&clean, &clean_reader, bsp, missing, bol,
                                 origin);
        test_rse_init_incomplete(&interrupted, &interrupted_reader,
                                 bsp, missing, bol, origin);
        clean.psr |= IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
        interrupted.psr |= IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
        clean.ip = interrupted.ip = UINT64_C(0x1230);
        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &clean, test_rse_step_read, &clean_reader),
                        ==, IA64_RSE_STEP_DONE);

        interrupted_reader.interrupt_at = boundary;
        g_assert_cmpint(
            ia64_rse_complete_mandatory_loads_interruptible(
                &interrupted, test_rse_step_read,
                test_rse_step_interruption_pending, &interrupted_reader),
            ==, IA64_RSE_STEP_INTERRUPTION);
        g_assert_true(interrupted_reader.interrupted);
        g_assert_cmpuint(interrupted_reader.cursor, ==, boundary);
        g_assert_true(interrupted.rse.cfle);
        g_assert_true(ia64_rse_partitions_valid(&interrupted));

        prefix_bspstore = interrupted.rse.bspstore;
        prefix_dirty = interrupted.rse.dirty;
        prefix_dirty_nat = interrupted.rse.dirty_nat;
        interrupted.rse.pending_fill_count = 1;
        interrupted.rse.pending_fill_ip = interrupted.ip;
        ia64_deliver_exception(&interrupted, IA64_EXCEPTION_EXTERNAL_INTERRUPT,
                               interrupted.ip, MMU_DATA_LOAD,
                               "mandatory RSE load boundary");
        g_assert_cmphex(interrupted.cr[IA64_CR_ISR] &
                        (UINT64_C(1) << IA64_ISR_IR_BIT), !=, 0);
        g_assert_cmphex(interrupted.cr[IA64_CR_ISR] &
                        (UINT64_C(1) << IA64_ISR_RS_BIT), ==, 0);
        g_assert_false(interrupted.rse.cfle);
        g_assert_false(interrupted.rse.reference);
        g_assert_cmpuint(interrupted.rse.pending_fill_count, ==, 0);
        g_assert_cmphex(interrupted.rse.pending_fill_ip, ==, 0);
        g_assert_cmphex(interrupted.rse.bspstore, ==, prefix_bspstore);
        g_assert_cmpint(interrupted.rse.dirty, ==, prefix_dirty);
        g_assert_cmpint(interrupted.rse.dirty_nat, ==, prefix_dirty_nat);

        g_assert_cmpint(ia64_rse_complete_mandatory_loads(
                            &interrupted, test_rse_step_read,
                            &interrupted_reader),
                        ==, IA64_RSE_STEP_DONE);
        g_assert_cmpuint(interrupted_reader.cursor, ==,
                         interrupted_reader.word_count);
        test_rse_assert_same_completed_frame(&clean, &interrupted);
        g_assert_true(ia64_rse_partitions_valid(&interrupted));
    }
}

static void test_rse_mandatory_load_interruption_boundaries(void)
{
    /* Five register-only loads, including before-first and after-final. */
    test_rse_interruption_boundaries_for_frame(0x3000, 5, 13, 200);
    /* Four registers plus the RNAT word at the 0x1f8 collection slot. */
    test_rse_interruption_boundaries_for_frame(
        0x1e8, 4, 94, IA64_STACKED_GR_COUNT - 6);
}

static void test_rse_incomplete_partition_validation(void)
{
    TestRSEStepReader reader;
    CPUIA64State valid;
    CPUIA64State corrupt;

    /* The unloaded span contains four registers and the 0x1f8 RNAT word. */
    test_rse_init_incomplete(&valid, &reader, 0x1e8, 4, 94,
                             IA64_STACKED_GR_COUNT - 6);
    g_assert_cmpint(valid.rse.dirty, ==, -4);
    g_assert_cmpint(valid.rse.dirty_nat, ==, -1);
    g_assert_true(ia64_rse_partitions_valid(&valid));

    /* Preserve the partition sum and byte span but misclassify the RNAT. */
    corrupt = valid;
    corrupt.rse.dirty = -5;
    corrupt.rse.dirty_nat = 0;
    corrupt.rse.invalid++;
    g_assert_false(ia64_rse_partitions_valid(&corrupt));

    /* A positive RNAT partition cannot coexist with missing registers. */
    corrupt = valid;
    corrupt.rse.dirty = -6;
    corrupt.rse.dirty_nat = 1;
    corrupt.rse.invalid += 2;
    g_assert_false(ia64_rse_partitions_valid(&corrupt));

    /* Returning makes the clean partition empty before counts go negative. */
    corrupt = valid;
    corrupt.rse.clean = 1;
    corrupt.rse.invalid--;
    g_assert_false(ia64_rse_partitions_valid(&corrupt));

    corrupt = valid;
    corrupt.rse.bsp++;
    corrupt.rse.bspstore++;
    g_assert_false(ia64_rse_partitions_valid(&corrupt));
}

typedef struct TestRSELargeLoad {
    uint32_t registers;
    uint32_t rnats;
} TestRSELargeLoad;

static uint64_t test_rse_large_load_read(CPUIA64State *env,
                                         uint64_t address, void *opaque)
{
    TestRSELargeLoad *load = opaque;

    g_assert_nonnull(env);
    if (ia64_rse_address_is_rnat_slot(address)) {
        load->rnats++;
        return 0;
    }
    load->registers++;
    return UINT64_C(0xc700000000000000) | address;
}

static void test_rse_load_partition_caps_at_physical_window(void)
{
    CPUIA64State env;
    TestRSELargeLoad load = { 0 };
    uint64_t start = 0x8000;
    uint64_t end = test_rse_walk_forward(start, 120);
    uint64_t expected = test_rse_walk_backward(end, 96);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.bol = 73;
    env.rse.current_frame_base = ia64_rse_wrap_slot(4000 + 73);
    env.rse.bspstore = 0;
    env.rse.bsp = 0;
    ia64_rse_load_dirty_partition(&env, start, end,
                                  test_rse_large_load_read, &load);

    g_assert_cmpuint(load.registers, ==, IA64_RSE_PHYS_STACKED_REGS);
    for (uint32_t i = 0; i < IA64_RSE_PHYS_STACKED_REGS; i++) {
        uint32_t slot = ia64_rse_bof_offset_to_storage(
            &env, -(int32_t)IA64_RSE_PHYS_STACKED_REGS + (int32_t)i);

        if (ia64_rse_address_is_rnat_slot(expected)) {
            expected += 8;
        }
        g_assert_cmphex(env.rse.stacked_gr[slot], ==,
                        UINT64_C(0xc700000000000000) | expected);
        expected += 8;
    }
    g_assert_cmphex(expected, ==, end);
}

static void test_i_unit_mov_ip_and_nop(void)
{
    const uint64_t mov_ip_r35_raw = 0x001800008c0ULL;
    const uint64_t mov_b_r35_b0_raw = 0x001880008c0ULL;
    const uint64_t nop_i_raw = 0x00008000000ULL;
    const uint64_t break_i_syscall_raw = 0x01000000000ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.br[0] = 0xfeedface;

    g_assert_true(ia64_slot_is_i_mov_ip(IA64_SLOT_TYPE_I, mov_ip_r35_raw));
    g_assert_true(ia64_exec_i_mov_ip(&env, mov_ip_r35_raw, 0x1001000));
    g_assert_cmphex(ia64_read_gr(&env, 35), ==, 0x1001000);

    g_assert_true(ia64_slot_is_i_mov_from_branch(IA64_SLOT_TYPE_I,
                                                 mov_b_r35_b0_raw));
    g_assert_true(ia64_exec_i_mov_from_branch(&env, mov_b_r35_b0_raw));
    g_assert_cmphex(ia64_read_gr(&env, 35), ==, 0xfeedface);

    g_assert_true(ia64_slot_is_i_nop(IA64_SLOT_TYPE_I, nop_i_raw));
    g_assert_true(ia64_slot_is_i_break(IA64_SLOT_TYPE_I,
                                       break_i_syscall_raw));
    g_assert_cmphex(ia64_i_break_immediate(break_i_syscall_raw),
                    ==, 0x100000);
}

static void test_performance_hint_family(void)
{
    const uint64_t immediate = (1ULL << 36) | (0xabcdeULL << 6);
    const uint64_t hint_m_raw = immediate | (1ULL << 27) | (1ULL << 26);
    const uint64_t hint_i_pause_raw = (1ULL << 27) | (1ULL << 26);
    const uint64_t hint_i_raw = immediate | (1ULL << 27) | (1ULL << 26);
    const uint64_t hint_f_raw = immediate | (1ULL << 27) | (1ULL << 26);
    const uint64_t hint_b_raw = (2ULL << 37) | immediate | (1ULL << 27);
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64InsnReport report;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x4000;

    g_assert_true(ia64_slot_is_nop_or_hint(IA64_SLOT_TYPE_M, hint_m_raw));
    g_assert_true(ia64_slot_is_nop_or_hint(IA64_SLOT_TYPE_I,
                                           hint_i_pause_raw));
    g_assert_true(ia64_slot_is_nop_or_hint(IA64_SLOT_TYPE_I, hint_i_raw));
    g_assert_true(ia64_slot_is_nop_or_hint(IA64_SLOT_TYPE_F, hint_f_raw));
    g_assert_true(ia64_slot_is_nop_or_hint(IA64_SLOT_TYPE_B, hint_b_raw));
    g_assert_true(ia64_insn_slot_supported(IA64_SLOT_TYPE_I,
                                           hint_i_pause_raw));

    g_assert_false(ia64_slot_is_nop_or_hint(
        IA64_SLOT_TYPE_I, hint_i_raw | (1ULL << 33)));
    g_assert_false(ia64_slot_is_nop_or_hint(
        IA64_SLOT_TYPE_M, hint_m_raw | (1ULL << 31)));
    g_assert_false(ia64_slot_is_nop_or_hint(
        IA64_SLOT_TYPE_F, hint_f_raw | (1ULL << 33)));
    g_assert_false(ia64_slot_is_nop_or_hint(
        IA64_SLOT_TYPE_B, hint_b_raw | (1ULL << 28)));

    make_bundle(bundle, 0x00, hint_m_raw, hint_i_pause_raw, hint_i_raw);
    g_assert_cmpint(ia64_insn_exec_bundle(&env, bundle, &report), ==,
                    IA64_INSN_OK);
    g_assert_cmphex(env.ip, ==, 0x4010);

    make_bundle(bundle, 0x1c, hint_m_raw, hint_f_raw, hint_b_raw);
    g_assert_cmpint(ia64_insn_exec_bundle(&env, bundle, &report), ==,
                    IA64_INSN_OK);
    g_assert_cmphex(env.ip, ==, 0x4020);
}

static void test_i_unit_break_delivers_interruption_state(void)
{
    const uint64_t bundle_ip = 0x200000;
    const uint64_t iva = 0x100000;
    const uint64_t psr_before = IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                                IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK;
    CPUIA64State env;
    uint64_t next_ip = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = bundle_ip;
    env.psr = ia64_psr_with_ri(psr_before, 1);
    env.cr[IA64_CR_IVA] = iva;
    env.cr[IA64_CR_IFS] = 0x8000000000001234ULL;
    ia64_deliver_break_interruption(&env, 0x100000, &next_ip,
                                    "break.i iim=0x100000");

    g_assert_cmphex(env.ip, ==, iva + 0x2c00);
    g_assert_cmphex(next_ip, ==, env.ip);
    g_assert_cmphex(env.cr[IA64_CR_IIM], ==, 0x100000);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, bundle_ip);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, ia64_psr_with_ri(psr_before, 1));
    g_assert_cmphex(env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK, ==,
                    UINT64_C(1) << IA64_ISR_EI_SHIFT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_X_BIT),
                    ==, UINT64_C(1) << IA64_ISR_X_BIT);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, 0);
    g_assert_cmphex(env.psr & (IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                               IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK |
                               IA64_PSR_RI_MASK), ==, 0);
}

static void test_i_unit_break_with_ic_clear_preserves_collection_state(void)
{
    const uint64_t bundle_ip = 0x200000;
    const uint64_t iva = 0x100000;
    const uint64_t saved_ipsr = 0x1111;
    const uint64_t saved_iip = 0xcafe0;
    const uint64_t saved_iipa = 0x2222;
    const uint64_t saved_ifs = 0x3333;
    const uint64_t saved_ifa = 0x5555;
    const uint64_t saved_itir = 0x6666;
    const uint64_t saved_iha = 0x7777;
    const uint64_t saved_iim = 0x8888;
    const uint64_t expected_isr = (UINT64_C(2) << IA64_ISR_EI_SHIFT) |
                                  (UINT64_C(1) << IA64_ISR_X_BIT) |
                                  (UINT64_C(1) << IA64_ISR_NI_BIT);
    CPUIA64State env;
    uint64_t next_ip = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = bundle_ip;
    env.psr = ia64_psr_with_ri(IA64_PSR_I_BIT | IA64_PSR_BN_BIT |
                               IA64_PSR_CPL_MASK, 2);
    env.cr[IA64_CR_IVA] = iva;
    env.cr[IA64_CR_IPSR] = saved_ipsr;
    env.cr[IA64_CR_IIP] = saved_iip;
    env.cr[IA64_CR_IIPA] = saved_iipa;
    env.cr[IA64_CR_IFS] = saved_ifs;
    env.cr[IA64_CR_IFA] = saved_ifa;
    env.cr[IA64_CR_ITIR] = saved_itir;
    env.cr[IA64_CR_IHA] = saved_iha;
    env.cr[IA64_CR_IIM] = saved_iim;

    ia64_deliver_break_interruption(&env, 0x100000, &next_ip,
                                    "break.i iim=0x100000");

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_BREAK);
    g_assert_cmphex(env.exception.vector, ==, 0x2c00);
    g_assert_cmphex(env.ip, ==, iva + 0x2c00);
    g_assert_cmphex(next_ip, ==, env.ip);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, saved_ipsr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, saved_iip);
    g_assert_cmphex(env.cr[IA64_CR_IIPA], ==, saved_iipa);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, saved_ifa);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, saved_itir);
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, saved_iha);
    g_assert_cmphex(env.cr[IA64_CR_IIM], ==, saved_iim);
    g_assert_cmphex(env.cr[IA64_CR_ISR], ==, expected_isr);
    g_assert_cmphex(env.psr & (IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                               IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK |
                               IA64_PSR_RI_MASK), ==, 0);
}

static void test_interruption_delivery_preserves_translation_state(void)
{
    const uint64_t bundle_ip = 0x200000;
    const uint64_t iva = 0x100000;
    const uint64_t preserved_bits =
        IA64_PSR_UP_BIT | IA64_PSR_MFL_BIT | IA64_PSR_MFH_BIT |
        IA64_PSR_PK_BIT | IA64_PSR_DT_BIT | IA64_PSR_RT_BIT |
        IA64_PSR_MC_BIT | IA64_PSR_IT_BIT;
    const uint64_t cleared_bits =
        IA64_PSR_AC_BIT | IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
        IA64_PSR_DFL_BIT | IA64_PSR_DFH_BIT | IA64_PSR_SP_BIT |
        IA64_PSR_DI_BIT | IA64_PSR_SI_BIT | IA64_PSR_DB_BIT |
        IA64_PSR_LP_BIT | IA64_PSR_TB_BIT | IA64_PSR_ID_BIT |
        IA64_PSR_DA_BIT | IA64_PSR_DD_BIT | IA64_PSR_SS_BIT |
        IA64_PSR_ED_BIT | IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK;
    const uint64_t psr_before = preserved_bits | cleared_bits;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = bundle_ip;
    env.psr = ia64_psr_with_ri(psr_before, 1);
    env.cr[IA64_CR_DCR] = IA64_DCR_BE_BIT | IA64_DCR_PP_BIT;
    env.cr[IA64_CR_IVA] = iva;

    ia64_deliver_exception(&env, IA64_EXCEPTION_EXTERNAL_INTERRUPT, env.ip,
                           MMU_DATA_LOAD, "external interrupt");

    g_assert_cmphex(env.ip, ==, iva + 0x3000);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==,
                    ia64_psr_with_ri(psr_before, 1));
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, bundle_ip);
    g_assert_cmphex(env.psr, ==,
                    preserved_bits | IA64_PSR_BE_BIT | IA64_PSR_PP_BIT);
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
    g_assert_cmphex(ia64_read_gr(&env, 62), ==, 0x41);
}

static void test_i_unit_mov_to_predicate_mask(void)
{
    const uint64_t mov_pr_r29_all_mask_raw = 0x016ff03bfc0ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr = (1ULL << 15) | (1ULL << 1) | 1;
    ia64_write_gr(&env, 29, (1ULL << 8) | (1ULL << 63));

    g_assert_true(ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I,
                                                  mov_pr_r29_all_mask_raw));
    g_assert_true(ia64_exec_i_mov_to_predicate(&env,
                                               mov_pr_r29_all_mask_raw));
    g_assert_cmphex(env.pr & 1, ==, 1);
    g_assert_cmphex(env.pr & (1ULL << 1), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 8), ==, 1ULL << 8);
    g_assert_cmphex(env.pr & (1ULL << 15), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 63), ==, 1ULL << 63);
}

static void test_i_unit_mov_to_predicate_mask_fsys_clock(void)
{
    const uint64_t mov_pr_r30_c000_raw = 0x006c003c000ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr = (1ULL << 16) | (1ULL << 14) | (1ULL << 13) | 1;
    ia64_write_gr(&env, 30, 1ULL << 15);

    g_assert_true(ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I,
                                                  mov_pr_r30_c000_raw));
    g_assert_true(ia64_exec_i_mov_to_predicate(&env,
                                               mov_pr_r30_c000_raw));
    g_assert_cmphex(env.pr & 1, ==, 1);
    g_assert_cmphex(env.pr & (1ULL << 13), ==, 1ULL << 13);
    g_assert_cmphex(env.pr & (1ULL << 14), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 15), ==, 1ULL << 15);
    g_assert_cmphex(env.pr & (1ULL << 16), ==, 1ULL << 16);
}

static void test_i_unit_mov_to_predicate_mask_high_restore(void)
{
    const uint64_t mov_pr_r29_high_mask_raw = 0x0160003a000ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr = (1ULL << 16) | (1ULL << 15) | (1ULL << 1) | 1;
    ia64_write_gr(&env, 29, (1ULL << 17) | (1ULL << 63));

    g_assert_true(ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I,
                                                  mov_pr_r29_high_mask_raw));
    g_assert_true(ia64_exec_i_mov_to_predicate(&env,
                                               mov_pr_r29_high_mask_raw));
    g_assert_cmphex(env.pr & 1, ==, 1);
    g_assert_cmphex(env.pr & (1ULL << 1), ==, 1ULL << 1);
    g_assert_cmphex(env.pr & (1ULL << 15), ==, 1ULL << 15);
    g_assert_cmphex(env.pr & (1ULL << 16), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 17), ==, 1ULL << 17);
    g_assert_cmphex(env.pr & (1ULL << 63), ==, 1ULL << 63);
}

static void test_i_unit_mov_to_branch(void)
{
    const uint64_t mov_b6_r14_raw = 0x00e0011c180ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 14, 0x10203040);

    g_assert_true(ia64_slot_is_i_mov_to_branch(IA64_SLOT_TYPE_I,
                                               mov_b6_r14_raw));
    g_assert_true(ia64_exec_i_mov_to_branch(&env, mov_b6_r14_raw));
    g_assert_cmphex(env.br[6], ==, 0x10203040);
}

static void test_application_register_moves(void)
{
    const uint64_t mov_i_ar_pfs_r33_raw = 0x00154042000ULL;
    const uint64_t mov_i_r35_ar_pfs_raw =
        (0x32ULL << 27) | (64ULL << 20) | (35ULL << 6);
    const uint64_t mov_i_ar_ec_imm_raw =
        (1ULL << 36) | (0x0aULL << 27) | (66ULL << 20) | (0x7eULL << 13);
    const uint64_t mov_m_ar_pfs_r36_raw =
        (1ULL << 37) | (0x2aULL << 27) | (64ULL << 20) | (36ULL << 13);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 33, 0x309);
    ia64_write_gr(&env, 36, 0x456);

    g_assert_true(ia64_slot_is_mov_to_application(IA64_SLOT_TYPE_I,
                                                  mov_i_ar_pfs_r33_raw));
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_i_ar_pfs_r33_raw));
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, 0x309);

    g_assert_true(ia64_slot_is_mov_from_application(IA64_SLOT_TYPE_I,
                                                    mov_i_r35_ar_pfs_raw));
    g_assert_true(ia64_exec_mov_from_application(&env, IA64_SLOT_TYPE_I,
                                                 mov_i_r35_ar_pfs_raw));
    g_assert_cmphex(ia64_read_gr(&env, 35), ==, 0x309);

    g_assert_true(ia64_slot_is_i_mov_to_application_immediate(
                      IA64_SLOT_TYPE_I, mov_i_ar_ec_imm_raw));
    g_assert_true(ia64_exec_i_mov_to_application_immediate(
                      &env, mov_i_ar_ec_imm_raw));
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, (uint64_t)-2);

    g_assert_true(ia64_slot_is_mov_to_application(IA64_SLOT_TYPE_M,
                                                  mov_m_ar_pfs_r36_raw));
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_M,
                                               mov_m_ar_pfs_r36_raw));
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, 0x456);
}

static void test_rnat_application_register_masks_only_slot63(void)
{
    const uint64_t mov_ar_rnat_r33_raw =
        (0x2aULL << 27) | (IA64_AR_RNAT << 20) | (33ULL << 13);
    const uint64_t expected = (UINT64_C(1) << 62) | UINT64_C(1);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 33, expected | (UINT64_C(1) << 63));

    g_assert_true(ia64_slot_is_mov_to_application(IA64_SLOT_TYPE_I,
                                                  mov_ar_rnat_r33_raw));
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_ar_rnat_r33_raw));
    g_assert_cmphex(env.rse.rnat, ==, expected);
    g_assert_cmphex(env.ar[IA64_AR_RNAT], ==, expected);
    g_assert_cmphex(env.nat.rnat, ==, expected);
}

static void test_m_unit_system_memory_management(void)
{
    const uint64_t chk_a_clr_r10_raw = 0x00a00018280ULL;
    const uint64_t sync_i_raw = (3ULL << 31) | (3ULL << 27);
    const uint64_t elilo_fc_r32_raw = 0x02182000000ULL;
    const uint64_t kernel_rsm_0x6000_raw = 0x00038180000ULL;
    const uint64_t kernel_ssm_0x6000_raw =
        (kernel_rsm_0x6000_raw & ~(0xfULL << 27)) | (6ULL << 27);
    const uint64_t kernel_rsm_psr_dt_raw =
        (7ULL << 27) | (UINT64_C(0x20000) << 6);
    const uint64_t kernel_ssm_psr_dt_raw =
        (6ULL << 27) | (UINT64_C(0x20000) << 6);
    const uint64_t kernel_mov_r47_psr_raw = 0x02128000bc0ULL;
    const uint64_t mov_r8_psr_um_raw =
        (1ULL << 37) | (0x21ULL << 27) | (8ULL << 6);
    const uint64_t mov_psr_um_r9_raw =
        (1ULL << 37) | (0x29ULL << 27) | (9ULL << 13);
    const uint64_t mov_psr_l_r10_raw =
        (1ULL << 37) | (0x2dULL << 27) | (10ULL << 13);
    const uint64_t userspace_chk_s_m_r22_raw = 0x0220002c140ULL;
    const uint64_t chk_s_i_r22_raw =
        (1ULL << 33) | (22ULL << 13) | (5ULL << 6);
    const uint64_t chk_s_i_equal_fallthrough_raw =
        (1ULL << 33) | (22ULL << 13) | (1ULL << 6);
    const uint64_t chk_s_f8_raw =
        (1ULL << 37) | (3ULL << 33) | (8ULL << 13) | (5ULL << 6);
    const uint64_t kernel_break_m_0_raw = 0;
    const uint64_t break_m_immediate_raw =
        (1ULL << 36) | (0x34567ULL << 6);
    const uint64_t kernel_mov_r8_rr_r2_raw = 0x02080200200ULL;
    const uint64_t mov_rr_r41_r40_raw =
        (1ULL << 37) | (40ULL << 13) | (41ULL << 20);
    const uint64_t mov_r8_rr_r41_raw =
        (1ULL << 37) | (0x10ULL << 27) | (8ULL << 6) | (41ULL << 20);
    const uint64_t kernel_mov_cr21_r18_raw = 0x02161524000ULL;
    const uint64_t kernel_mov_cr20_r17_raw = 0x02161422000ULL;
    const uint64_t mov_r8_cr20_raw =
        (1ULL << 37) | (0x24ULL << 27) | (8ULL << 6) | (20ULL << 20);
    const uint64_t kernel_itr_i_r16_r18_raw = 0x02079024000ULL;
    const uint64_t kernel_tpa_r3_r2_raw = 0x020f02000c0ULL;
    const uint64_t probe_r_r8_r33_imm3_raw =
        (1ULL << 37) | (0x18ULL << 27) | (33ULL << 20) |
        (3ULL << 13) | (8ULL << 6);
    const uint64_t probe_w_r8_r33_imm3_raw =
        (1ULL << 37) | (0x19ULL << 27) | (33ULL << 20) |
        (3ULL << 13) | (8ULL << 6);
    const uint64_t probe_r_r8_r33_r9_raw =
        (1ULL << 37) | (0x38ULL << 27) | (33ULL << 20) |
        (9ULL << 13) | (8ULL << 6);
    const uint64_t probe_rw_fault_r33_imm3_raw =
        (1ULL << 37) | (0x31ULL << 27) | (33ULL << 20) |
        (3ULL << 13);
    const uint64_t probe_r_fault_r33_imm3_raw =
        (1ULL << 37) | (0x32ULL << 27) | (33ULL << 20) |
        (3ULL << 13);
    const uint64_t probe_w_fault_r33_imm3_raw =
        (1ULL << 37) | (0x33ULL << 27) | (33ULL << 20) |
        (3ULL << 13);
    const uint64_t kernel_thash_r4_r2_raw =
        (1ULL << 37) | (0x1aULL << 27) | (2ULL << 20) | (4ULL << 6);
    const uint64_t kernel_ttag_r5_r2_raw =
        (1ULL << 37) | (0x1bULL << 27) | (2ULL << 20) | (5ULL << 6);
    const uint64_t kernel_mov_r15_cpuid_r0_raw = 0x020b80003c0ULL;
    const uint64_t linux_mov_pmc_r2_r15_raw = 0x0202021e000ULL;
    const uint64_t mov_r16_pmc_r2_raw =
        (1ULL << 37) | (0x14ULL << 27) | (2ULL << 20) | (16ULL << 6);
    const uint64_t mov_pmd_r3_r17_raw =
        (1ULL << 37) | (0x05ULL << 27) | (3ULL << 20) | (17ULL << 13);
    const uint64_t mov_r18_pmd_r3_raw =
        (1ULL << 37) | (0x15ULL << 27) | (3ULL << 20) | (18ULL << 6);
    const uint64_t mov_dbr_r4_r19_raw =
        (1ULL << 37) | (0x01ULL << 27) | (4ULL << 20) | (19ULL << 13);
    const uint64_t mov_r20_dbr_r4_raw =
        (1ULL << 37) | (0x11ULL << 27) | (4ULL << 20) | (20ULL << 6);
    const uint64_t mov_ibr_r5_r21_raw =
        (1ULL << 37) | (0x02ULL << 27) | (5ULL << 20) | (21ULL << 13);
    const uint64_t mov_r22_ibr_r5_raw =
        (1ULL << 37) | (0x12ULL << 27) | (5ULL << 20) | (22ULL << 6);
    const uint64_t mov_pkr_r6_r23_raw =
        (1ULL << 37) | (0x03ULL << 27) | (6ULL << 20) | (23ULL << 13);
    const uint64_t mov_r24_pkr_r6_raw =
        (1ULL << 37) | (0x13ULL << 27) | (6ULL << 20) | (24ULL << 6);
    const uint64_t kernel_mov_m_ar_rsc_0_raw = 0x00141000000ULL;
    const uint64_t kernel_invala_raw = 0x00080000000ULL;
    const uint64_t invala_e_r12_raw =
        (1ULL << 31) | (2ULL << 27) | (12ULL << 6);
    const uint64_t invala_e_f12_raw =
        (1ULL << 31) | (3ULL << 27) | (12ULL << 6);
    const uint64_t kernel_loadrs_raw = 0x00050000000ULL;
    const uint64_t kernel_flushrs_raw = 0x00060000000ULL;
    CPUIA64State env;
    IA64TranslateResult fault;
    uint64_t target = 0;
    bool branch_taken = false;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_slot_is_check_speculative(
                      IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw));
    g_assert_cmpint(ia64_check_speculative_displacement(
                        userspace_chk_s_m_r22_raw), ==, 80);
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw,
                      0x2000000000032370ULL, &target, NULL));
    g_assert_cmphex(target, ==, 0x2000000000032380ULL);

    env.nat.gr_nat[22 / 64] |= 1ULL << (22 % 64);
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw,
                      0x2000000000032370ULL, &target, NULL));
    g_assert_cmphex(target, ==, 0x20000000000323c0ULL);
    env.nat.gr_nat[22 / 64] = 0;

    g_assert_true(ia64_slot_is_check_speculative(IA64_SLOT_TYPE_I,
                                                chk_s_i_r22_raw));
    g_assert_cmpint(ia64_check_speculative_displacement(chk_s_i_r22_raw),
                    ==, 80);
    env.nat.gr_nat[22 / 64] |= 1ULL << (22 % 64);
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_I, chk_s_i_r22_raw, 0x1000,
                      &target, NULL));
    g_assert_cmphex(target, ==, 0x1050);

    target = 0;
    branch_taken = false;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_I,
                      chk_s_i_equal_fallthrough_raw, 0x1000,
                      &target, &branch_taken));
    g_assert_true(branch_taken);
    g_assert_cmphex(target, ==, 0x1010);
    env.nat.gr_nat[22 / 64] = 0;

    g_assert_true(ia64_slot_is_check_speculative(IA64_SLOT_TYPE_M,
                                                chk_s_f8_raw));
    g_assert_cmpint(ia64_check_speculative_displacement(chk_s_f8_raw),
                    ==, 80);
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, chk_s_f8_raw, 0x2000,
                      &target, NULL));
    g_assert_cmphex(target, ==, 0x2010);
    env.fr[8].raw[0] = 0;
    env.fr[8].raw[1] = 0x1fffe;
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, chk_s_f8_raw, 0x2000,
                      &target, NULL));
    g_assert_cmphex(target, ==, 0x2050);

    g_assert_true(ia64_slot_is_m_check_advanced(IA64_SLOT_TYPE_M,
                                                chk_a_clr_r10_raw));
    g_assert_cmpint(ia64_branch_displacement(chk_a_clr_r10_raw), ==, 192);
    g_assert_true(ia64_exec_m_check_advanced(&env, chk_a_clr_r10_raw,
                                             0x100eb30, &target, NULL));
    g_assert_cmphex(target, ==, 0x100ebf0);

    env.alat.entries[0].valid = true;
    env.alat.entries[0].target = 10;
    env.alat.entries[0].width = 4;
    env.alat.entries[0].physical = true;
    env.alat.entries[0].address = 0x1000;
    env.alat.valid_mask = 1u << 0;
    ia64_alat_reconstruct_transients(&env);
    target = 0;
    g_assert_true(ia64_exec_m_check_advanced(&env, chk_a_clr_r10_raw,
                                             0x100eb30, &target, NULL));
    g_assert_cmphex(target, ==, 0x100eb40);
    g_assert_false(env.alat.entries[0].valid);

    g_assert_true(ia64_slot_is_m_serialization(IA64_SLOT_TYPE_M, sync_i_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M, sync_i_raw));
    g_assert_true(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                             elilo_fc_r32_raw));
    env.alat.next = 2;
    env.alat.entries[0].valid = true;
    env.alat.entries[0].target = 12;
    env.alat.entries[0].width = 8;
    env.alat.entries[0].physical = true;
    env.alat.entries[0].address = 0x2000;
    env.alat.entries[1].valid = true;
    env.alat.entries[1].target = 13;
    env.alat.entries[1].width = 4;
    env.alat.entries[1].address = 0x3000;
    env.alat.valid_mask = (1u << 0) | (1u << 1);
    ia64_alat_reconstruct_transients(&env);
    g_assert_true(ia64_slot_is_m_invala(IA64_SLOT_TYPE_M,
                                        kernel_invala_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              kernel_invala_raw));
    g_assert_true(ia64_exec_m_invala(&env, kernel_invala_raw));
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        g_assert_false(env.alat.entries[i].valid);
    }
    g_assert_cmpuint(env.alat.next, ==, 0);

    env.alat.next = 2;
    env.alat.entries[0].valid = true;
    env.alat.entries[0].target = 12;
    env.alat.entries[0].width = 8;
    env.alat.entries[0].physical = true;
    env.alat.entries[0].address = 0x2000;
    env.alat.entries[1].valid = true;
    env.alat.entries[1].target = 13;
    env.alat.entries[1].width = 4;
    env.alat.entries[1].address = 0x3000;
    env.alat.valid_mask = (1u << 0) | (1u << 1);
    ia64_alat_reconstruct_transients(&env);
    g_assert_true(ia64_slot_is_m_invala(IA64_SLOT_TYPE_M,
                                        invala_e_r12_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              invala_e_r12_raw));
    g_assert_true(ia64_exec_m_invala(&env, invala_e_r12_raw));
    g_assert_false(env.alat.entries[0].valid);
    g_assert_true(env.alat.entries[1].valid);
    g_assert_cmpuint(env.alat.valid_mask, ==, 1u << 1);
    g_assert_cmpuint(env.alat.next, ==, 2);

    g_assert_true(ia64_slot_is_m_invala(IA64_SLOT_TYPE_M,
                                        invala_e_f12_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              invala_e_f12_raw));
    g_assert_true(ia64_exec_m_invala(&env, invala_e_f12_raw));
    g_assert_true(env.alat.entries[1].valid);
    g_assert_cmpuint(env.alat.valid_mask, ==, 1u << 1);

    g_assert_true(ia64_slot_is_m_processor_mask(IA64_SLOT_TYPE_M,
                                                kernel_rsm_0x6000_raw));
    g_assert_cmphex(ia64_processor_mask_immediate(kernel_rsm_0x6000_raw),
                    ==, 0x6000);
    env.psr = 0xffff;
    g_assert_true(ia64_exec_m_processor_mask(&env, kernel_rsm_0x6000_raw));
    g_assert_cmphex(env.psr, ==, 0x9fff);

    env.psr = 0;
    g_assert_true(ia64_exec_m_processor_mask(&env, kernel_ssm_0x6000_raw));
    g_assert_cmphex(env.psr, ==, 0x6000);

    env.psr = 0x20000;
    g_assert_true(ia64_exec_m_processor_mask(&env, kernel_rsm_psr_dt_raw));
    g_assert_cmphex(env.psr & 0x20000, ==, 0);
    g_assert_true(ia64_exec_m_processor_mask(&env, kernel_ssm_psr_dt_raw));
    g_assert_cmphex(env.psr & 0x20000, ==, 0x20000);

    env.psr = 0x00001010084a2008ULL;
    g_assert_true(ia64_slot_is_m_mov_from_processor_status(
        IA64_SLOT_TYPE_M, kernel_mov_r47_psr_raw));
    g_assert_true(ia64_exec_m_mov_from_processor_status(
        &env, kernel_mov_r47_psr_raw));
    g_assert_cmphex(ia64_read_gr(&env, 47), ==, 0x00000010084a2008ULL);
    g_assert_true(ia64_exec_m_mov_from_processor_status(
        &env, mov_r8_psr_um_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x8);
    ia64_write_gr(&env, 9, 0x35);
    g_assert_true(ia64_exec_m_mov_to_processor_status(&env,
                                                      mov_psr_um_r9_raw));
    g_assert_cmphex(env.psr & 0x3f, ==, 0x35);
    ia64_write_gr(&env, 10, 0x12345678);
    g_assert_true(ia64_exec_m_mov_to_processor_status(&env,
                                                      mov_psr_l_r10_raw));
    g_assert_cmphex(env.psr & 0xffffffffULL, ==, 0x12345678);
    g_assert_true(ia64_slot_is_m_break(IA64_SLOT_TYPE_M,
                                       kernel_break_m_0_raw));
    g_assert_cmphex(ia64_m_break_immediate(kernel_break_m_0_raw), ==, 0);
    g_assert_true(ia64_slot_is_m_break(IA64_SLOT_TYPE_M,
                                       break_m_immediate_raw));
    g_assert_cmphex(ia64_m_break_immediate(break_m_immediate_raw),
                    ==, 0x134567);

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_cmphex(env.rr[0], ==, 0x30);
    g_assert_true(ia64_slot_is_m_mov_from_region_register(
        IA64_SLOT_TYPE_M, kernel_mov_r8_rr_r2_raw));
    g_assert_true(ia64_exec_m_mov_from_region_register(
        &env, kernel_mov_r8_rr_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x30);

    ia64_write_gr(&env, 40, 0x539);
    ia64_write_gr(&env, 41, 5ULL << 61);
    g_assert_true(ia64_slot_is_m_mov_to_region_register(
        IA64_SLOT_TYPE_M, mov_rr_r41_r40_raw));
    g_assert_true(ia64_exec_m_mov_to_region_register(
        &env, mov_rr_r41_r40_raw));
    g_assert_true(ia64_exec_m_mov_from_region_register(
        &env, mov_r8_rr_r41_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x539);

    ia64_write_gr(&env, 17, 0xa000000100000000ULL);
    ia64_write_gr(&env, 18, 0x68);
    g_assert_true(ia64_slot_is_m_mov_to_control(IA64_SLOT_TYPE_M,
                                                kernel_mov_cr21_r18_raw));
    g_assert_true(ia64_exec_m_mov_to_control(&env,
                                             kernel_mov_cr21_r18_raw));
    g_assert_true(ia64_exec_m_mov_to_control(&env,
                                             kernel_mov_cr20_r17_raw));
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, 0x68);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, 0xa000000100000000ULL);
    g_assert_true(ia64_exec_m_mov_from_control(&env, mov_r8_cr20_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0xa000000100000000ULL);

    ia64_write_gr(&env, 16, 2);
    ia64_write_gr(&env, 18, 0x0010000004000661ULL);
    g_assert_true(ia64_slot_is_m_insert_translation(IA64_SLOT_TYPE_M,
                                                    kernel_itr_i_r16_r18_raw));
    g_assert_true(ia64_exec_m_insert_translation(&env,
                                                 kernel_itr_i_r16_r18_raw));
    g_assert_cmphex(env.itr[2], ==, 0x0010000004000661ULL);

    g_assert_true(ia64_install_translation(
                      &env, false, true, 2, 0xa000000100bc0000ULL,
                      0x0010000100bc0661ULL, 12ULL << 2));
    ia64_write_gr(&env, 2, 0xa000000100bc0000ULL);
    g_assert_true(ia64_slot_is_m_virtual_translation(IA64_SLOT_TYPE_M,
                                                     kernel_tpa_r3_r2_raw));
    g_assert_true(ia64_exec_m_virtual_translation(&env,
                                                  kernel_tpa_r3_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 3), ==, 0x0000000100bc0000ULL);

    ia64_cpu_reset_synthetic_itanium2(&env);
    memset(&fault, 0, sizeof(fault));
    env.psr = IA64_PSR_DT_BIT;
    ia64_write_gr(&env, 2, 0xa000000000040a10ULL);
    g_assert_cmpint(ia64_exec_m_virtual_translation_checked(
                        &env, kernel_tpa_r3_r2_raw, &fault),
                    ==, IA64_VIRTUAL_TRANSLATION_FAULT);
    g_assert_cmpint(fault.status, ==, IA64_TRANSLATE_TLB_MISS);
    g_assert_cmphex(fault.vaddr, ==, 0xa000000000040a10ULL);
    g_assert_cmphex(ia64_read_gr(&env, 3), ==, 0);

    g_assert_true(ia64_install_translation(
                      &env, false, true, 0, 0xa000000000040000ULL,
                      0x0000000004b48000ULL | (7ULL << 9) | 1ULL,
                      12ULL << 2));
    g_assert_cmpint(ia64_exec_m_virtual_translation_checked(
                        &env, kernel_tpa_r3_r2_raw, &fault),
                    ==, IA64_VIRTUAL_TRANSLATION_OK);
    g_assert_cmphex(ia64_read_gr(&env, 3), ==, 0x0000000004b48a10ULL);

    env.psr &= ~IA64_PSR_DT_BIT;
    ia64_write_gr(&env, 3, 0);
    g_assert_cmpint(ia64_exec_m_virtual_translation_checked(
                        &env, kernel_tpa_r3_r2_raw, &fault),
                    ==, IA64_VIRTUAL_TRANSLATION_OK);
    g_assert_cmphex(ia64_read_gr(&env, 3), ==, 0x0000000004b48a10ULL);

    ia64_cpu_reset_synthetic_itanium2(&env);
    memset(&fault, 0, sizeof(fault));
    env.psr = IA64_PSR_DT_BIT;
    ia64_write_gr(&env, 33, 0x2000000000012000ULL);
    g_assert_true(ia64_install_translation(
                      &env, false, true, 0, 0x2000000000012000ULL,
                      0x0000000004c00000ULL | (3ULL << 7) |
                      (2ULL << 9) | 1ULL,
                      12ULL << 2));
    g_assert_true(ia64_slot_is_m_probe(IA64_SLOT_TYPE_M,
                                       probe_r_fault_r33_imm3_raw));
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_r_fault_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_w_fault_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_rw_fault_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_r_r8_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 1);

    ia64_write_gr(&env, 9, 3);
    ia64_write_gr(&env, 8, 0);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_r_r8_r33_r9_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 1);

    g_assert_true(ia64_install_translation(
                      &env, false, true, 0, 0x2000000000012000ULL,
                      0x0000000004d00000ULL | (2ULL << 9) | 1ULL,
                      12ULL << 2));
    ia64_write_gr(&env, 8, 0xfeed);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_r_r8_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_w_r8_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_OK);
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_w_fault_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_FAULT);
    g_assert_cmpint(fault.status, ==, IA64_TRANSLATE_ACCESS_DENIED);
    g_assert_cmpint(fault.access_type, ==, MMU_DATA_STORE);
    g_assert_nonnull(strstr(fault.message, "cpl=3"));

    ia64_write_gr(&env, 33, 0x2000000000030000ULL);
    g_assert_cmpint(ia64_exec_m_probe_checked(
                        &env, probe_r_r8_r33_imm3_raw, &fault),
                    ==, IA64_PROBE_FAULT);
    g_assert_cmpint(fault.status, ==, IA64_TRANSLATE_TLB_MISS);

    ia64_write_gr(&env, 2, 0xa000000100bc0000ULL);
    env.cr[IA64_CR_PTA] = (20ULL << 2) | (1ULL << 15);
    g_assert_true(ia64_exec_m_virtual_translation(&env,
                                                  kernel_thash_r4_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 4),
                    ==, ia64_vhpt_hash_address(&env,
                                               0xa000000100bc0000ULL));
    g_assert_true(ia64_exec_m_virtual_translation(&env,
                                                  kernel_ttag_r5_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 5),
                    ==, ia64_vhpt_tag(&env, 0xa000000100bc0000ULL));

    g_assert_true(ia64_slot_is_m_mov_from_processor_identifier(
        IA64_SLOT_TYPE_M, kernel_mov_r15_cpuid_r0_raw));
    g_assert_true(ia64_exec_m_mov_from_processor_identifier(
        &env, kernel_mov_r15_cpuid_r0_raw));
    g_assert_cmphex(ia64_read_gr(&env, 15), ==,
                    0x49656e69756e6547ULL);

    ia64_write_gr(&env, 19, 1);
    g_assert_true(ia64_exec_m_mov_from_processor_identifier(
        &env, (1ULL << 37) | (0x17ULL << 27) | (19ULL << 20) |
              (16ULL << 6)));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==,
                    0x000000006c65746eULL);

    ia64_write_gr(&env, 2, 2);
    ia64_write_gr(&env, 15, 0x123456789abcdef0ULL);
    g_assert_true(ia64_slot_is_m_mov_to_indexed_system_register(
        IA64_SLOT_TYPE_M, linux_mov_pmc_r2_r15_raw));
    g_assert_true(ia64_exec_m_mov_to_indexed_system_register(
        &env, linux_mov_pmc_r2_r15_raw));
    g_assert_cmphex(env.pmc[2], ==, 0x123456789abcdef0ULL);
    g_assert_true(ia64_slot_is_m_mov_from_indexed_system_register(
        IA64_SLOT_TYPE_M, mov_r16_pmc_r2_raw));
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r16_pmc_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x123456789abcdef0ULL);

    ia64_write_gr(&env, 3, 4);
    ia64_write_gr(&env, 17, 0xfeedfaceULL);
    g_assert_true(ia64_exec_m_mov_to_indexed_system_register(
        &env, mov_pmd_r3_r17_raw));
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r18_pmd_r3_raw));
    g_assert_cmphex(ia64_read_gr(&env, 18), ==, 0xfeedfaceULL);

    ia64_write_gr(&env, 4, 7);
    ia64_write_gr(&env, 19, 0xd0d0ULL);
    g_assert_true(ia64_exec_m_mov_to_indexed_system_register(
        &env, mov_dbr_r4_r19_raw));
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r20_dbr_r4_raw));
    g_assert_cmphex(ia64_read_gr(&env, 20), ==, 0xd0d0ULL);

    ia64_write_gr(&env, 5, 6);
    ia64_write_gr(&env, 21, 0x1b1bULL);
    g_assert_true(ia64_exec_m_mov_to_indexed_system_register(
        &env, mov_ibr_r5_r21_raw));
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r22_ibr_r5_raw));
    g_assert_cmphex(ia64_read_gr(&env, 22), ==, 0x1b1bULL);

    ia64_write_gr(&env, 6, 12);
    ia64_write_gr(&env, 23, 0x0badf00dULL);
    g_assert_true(ia64_exec_m_mov_to_indexed_system_register(
        &env, mov_pkr_r6_r23_raw));
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r24_pkr_r6_raw));
    g_assert_cmphex(ia64_read_gr(&env, 24), ==, 0x0badf00dULL);

    ia64_write_gr(&env, 2, IA64_PMC_COUNT);
    g_assert_true(ia64_exec_m_mov_from_indexed_system_register(
        &env, mov_r16_pmc_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0);

    env.ar[IA64_AR_RSC] = 0x3;
    env.rse.rsc = 0x3;
    g_assert_true(ia64_slot_is_mov_to_application_immediate(
        IA64_SLOT_TYPE_M, kernel_mov_m_ar_rsc_0_raw));
    g_assert_true(ia64_exec_mov_to_application_immediate(
        &env, IA64_SLOT_TYPE_M, kernel_mov_m_ar_rsc_0_raw));
    g_assert_cmphex(env.ar[IA64_AR_RSC], ==, 0);
    g_assert_cmphex(env.rse.rsc, ==, 0);
    g_assert_true(ia64_slot_is_m_loadrs(IA64_SLOT_TYPE_M, kernel_loadrs_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              kernel_loadrs_raw));
    g_assert_true(ia64_slot_is_m_flushrs(IA64_SLOT_TYPE_M,
                                         kernel_flushrs_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              kernel_flushrs_raw));
}

static void test_translation_access_dirty_bits(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    uint64_t address = 0x2000000000042000ULL;
    uint64_t pte = 0x0000000005000000ULL | (3ULL << 7) | (2ULL << 9) |
                   IA64_PTE_P_BIT | IA64_PTE_A_BIT;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_DT_BIT | (3ULL << IA64_PSR_CPL_SHIFT);

    g_assert_true(ia64_install_translation(&env, false, true, 0, address,
                                           pte, 12ULL << 2));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD, 0,
                                         false, &result));
    g_assert_cmphex(result.prot & PAGE_READ, !=, 0);
    g_assert_cmphex(result.prot & PAGE_WRITE, ==, 0);

    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_STORE, 0,
                                          false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_DIRTY_BIT);
    g_assert_nonnull(strstr(result.message, "dirty bit clear"));

    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_STORE, 0,
                                         true, &result));
    g_assert_cmphex(result.prot & PAGE_WRITE, ==, 0);

    g_assert_true(ia64_install_translation(&env, false, true, 0, address,
                                           pte | IA64_PTE_D_BIT,
                                           12ULL << 2));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_STORE, 0,
                                         false, &result));
    g_assert_cmphex(result.prot & PAGE_WRITE, !=, 0);

    g_assert_true(ia64_install_translation(&env, false, true, 0, address,
                                           pte & ~IA64_PTE_A_BIT,
                                           12ULL << 2));
    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_LOAD, 0,
                                          false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_ACCESS_BIT);
    g_assert_nonnull(strstr(result.message, "access bit clear"));

    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD, 0,
                                         true, &result));
    g_assert_cmphex(result.prot, ==, 0);
}

static void test_interrupt_control_registers(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);
    g_assert_false(ia64_queue_external_interrupt(&env, 0));
    g_assert_false(ia64_external_interrupt_pending(&env));

    env.cr[IA64_CR_ITV] = 0xef;
    env.cr[IA64_CR_ITM] = 10;
    env.ar[IA64_AR_ITC] = 9;
    g_assert_false(ia64_timer_interrupt_due(&env));

    /* Without an ITM deadline timer, ia64_itc_set stays fully manual. */
    ia64_itc_set(&env, 10);
    g_assert_true(ia64_timer_interrupt_due(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    env.psr |= IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
    g_assert_true(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IRR3) &
                    (1ULL << (0xef & 63)), !=, 0);
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IRR3) &
                    (1ULL << (0xef & 63)), ==, 0);
    g_assert_false(ia64_external_interrupt_pending(&env));

    ia64_write_control_register(&env, IA64_CR_EOI, 0);
    g_assert_false(ia64_external_interrupt_pending(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);

    g_assert_true(ia64_queue_external_interrupt(&env, 0xef));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IRR3) &
                    (1ULL << (0xef & 63)), !=, 0);
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
    ia64_write_control_register(&env, IA64_CR_EOI, 0);

    env.cr[IA64_CR_ITV] = (1ULL << 16) | 0xef;
    g_assert_false(ia64_timer_interrupt_due(&env));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ar[IA64_AR_ITC] = 1000;
    env.cr[IA64_CR_ITM] = 0;
    ia64_write_control_register(&env, IA64_CR_ITV, 0xef);
    g_assert_true(ia64_timer_interrupt_due(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));

    ia64_write_control_register(&env, IA64_CR_ITM, 2000);
    g_assert_false(ia64_timer_interrupt_due(&env));
    g_assert_false(ia64_external_interrupt_pending(&env));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_ITV] = 0xef;
    env.cr[IA64_CR_ITM] = 10;
    env.ar[IA64_AR_ITC] = 9;
    g_assert_false(ia64_itc_timer_poll(&env));
    ia64_itc_set(&env, 10);
    g_assert_true(ia64_itc_timer_poll(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_ITV] = (1ULL << 16) | 0xef;
    env.cr[IA64_CR_ITM] = 0;
    env.ar[IA64_AR_ITC] = 1000;
    g_assert_false(ia64_itc_timer_poll(&env));
    g_assert_false(ia64_external_interrupt_pending(&env));
}

static void test_itc_warp_moves_forward_only(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_itc_set(&env, 100);
    ia64_itc_warp_to(&env, 90);
    g_assert_cmphex(env.ar[IA64_AR_ITC], ==, 100);
    ia64_itc_warp_to(&env, 250);
    g_assert_cmphex(env.ar[IA64_AR_ITC], ==, 250);
    ia64_itc_warp_to(&env, 250);
    g_assert_cmphex(env.ar[IA64_AR_ITC], ==, 250);
}

static void test_timer_compare_rearms_only_on_itm_programming(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
    env.cr[IA64_CR_ITV] = 0xef;
    env.cr[IA64_CR_ITM] = 10;
    env.ar[IA64_AR_ITC] = 10;

    g_assert_true(ia64_timer_interrupt_due(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
    ia64_write_control_register(&env, IA64_CR_EOI, 0);

    g_assert_false(ia64_timer_interrupt_due(&env));
    ia64_itc_set(&env, 11);
    g_assert_false(ia64_itc_timer_poll(&env));
    g_assert_false(ia64_external_interrupt_pending(&env));

    ia64_write_control_register(&env, IA64_CR_ITM, 13);
    ia64_itc_set(&env, 12);
    g_assert_false(ia64_itc_timer_poll(&env));
    ia64_itc_set(&env, 13);
    g_assert_true(ia64_itc_timer_poll(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
}

static void test_interrupt_unmask_exposes_pending_external_interrupt(void)
{
    const uint64_t ssm_i_raw = (6ULL << 27) | (IA64_PSR_I_BIT << 6);
    const uint64_t rsm_i_raw = (7ULL << 27) | (IA64_PSR_I_BIT << 6);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT;
    g_assert_true(ia64_queue_external_interrupt(&env, 0xef));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    g_assert_true(ia64_exec_m_processor_mask(&env, ssm_i_raw));
    g_assert_true(ia64_external_interrupt_enabled(&env));

    g_assert_true(ia64_exec_m_processor_mask(&env, rsm_i_raw));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));
}

static void test_external_interrupt_delivery_masks(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_true(ia64_queue_external_interrupt(&env, 0xef));

    env.psr = IA64_PSR_I_BIT;
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    env.psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
    env.cr[IA64_CR_TPR] = IA64_TPR_MIC(14);
    g_assert_false(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);
    g_assert_true(ia64_external_interrupt_pending(&env));

    env.cr[IA64_CR_TPR] = IA64_TPR_MIC(13);
    g_assert_true(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
    g_assert_false(ia64_external_interrupt_pending(&env));

    env.cr[IA64_CR_TPR] = 0;
    g_assert_true(ia64_queue_external_interrupt(&env, 0x20));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);
    g_assert_true(ia64_external_interrupt_pending(&env));

    ia64_write_control_register(&env, IA64_CR_EOI, 0);
    g_assert_true(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x20);
    ia64_write_control_register(&env, IA64_CR_EOI, 0);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
    env.cr[IA64_CR_TPR] = IA64_TPR_MMI_BIT;
    g_assert_true(ia64_queue_external_interrupt(&env, 0x20));
    g_assert_false(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);

    g_assert_true(ia64_queue_external_interrupt(&env, 2));
    g_assert_true(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 2);
}

static void test_interrupt_reconcile_drops_invalid_active_vector(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT;
    env.interrupt.pending_interruption = 1;
    env.cr[IA64_CR_IVR] = 0;

    g_assert_true(ia64_queue_external_interrupt(&env, 0xef));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    ia64_reconcile_interrupt_state(&env);

    g_assert_false(env.interrupt.pending_interruption);
    g_assert_true(ia64_external_interrupt_enabled(&env));
    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0xef);
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
    g_assert_cmphex(ia64_read_gr(&env, 36), ==, 0xffffffffffdc8000ULL);
}

static void test_lx_nop_hint_pair(void)
{
    const uint64_t l_raw = 0x00000000000ULL;
    const uint64_t linux_frontier_nop_x_raw = 0x00008000000ULL;
    const uint64_t hint_x_raw = linux_frontier_nop_x_raw | (1ULL << 26);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 8, 0x12345678ULL);

    g_assert_true(ia64_slot_pair_is_lx_nop_or_hint(
        l_raw, linux_frontier_nop_x_raw));
    g_assert_true(ia64_exec_lx_nop_or_hint(&env, l_raw,
                                           linux_frontier_nop_x_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x12345678ULL);

    g_assert_true(ia64_slot_pair_is_lx_nop_or_hint(l_raw, hint_x_raw));
    g_assert_true(ia64_exec_lx_nop_or_hint(&env, l_raw, hint_x_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0x12345678ULL);
}

static void test_alu_add_register_form(void)
{
    const uint64_t add_r36_r36_r1_raw = 0x10000148900ULL;
    const uint64_t adds_r36_0_r32_raw = 0x10802000900ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 1, 0x1238000);
    ia64_write_gr(&env, 36, 0xffffffffffdc8000ULL);

    g_assert_true(ia64_slot_is_alu_add(IA64_SLOT_TYPE_M,
                                       add_r36_r36_r1_raw));
    g_assert_true(ia64_exec_alu_add(&env, add_r36_r36_r1_raw));
    g_assert_cmphex(ia64_read_gr(&env, 36), ==, 0x1000000);

    ia64_write_gr(&env, 32, 0xfeedface);
    g_assert_true(ia64_slot_is_alu_add(IA64_SLOT_TYPE_M,
                                       adds_r36_0_r32_raw));
    g_assert_true(ia64_exec_alu_add(&env, adds_r36_0_r32_raw));
    g_assert_cmphex(ia64_read_gr(&env, 36), ==, 0xfeedface);
}

static void test_alu_sub_register_form(void)
{
    const uint64_t sub_r19_r19_r20_raw = 0x100294264c0ULL;
    const uint64_t sub_r16_8_r17_raw = 0x10129110407ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 19, 0x1c98);
    ia64_write_gr(&env, 20, 0x18);

    g_assert_true(ia64_slot_is_alu_sub(IA64_SLOT_TYPE_I,
                                       sub_r19_r19_r20_raw));
    g_assert_true(ia64_exec_alu_sub(&env, sub_r19_r19_r20_raw));
    g_assert_cmphex(ia64_read_gr(&env, 19), ==, 0x1c80);

    ia64_write_gr(&env, 17, 3);
    g_assert_true(ia64_slot_is_alu_sub(IA64_SLOT_TYPE_I,
                                       sub_r16_8_r17_raw));
    g_assert_true(ia64_exec_alu_sub(&env, sub_r16_8_r17_raw));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 5);
}

static void test_alu_logic_addp4_and_shladd(void)
{
    const uint64_t and_r14_r14_r15_raw = 0x10060f1c380ULL;
    const uint64_t addp4_r16_r17_r18_raw =
        (8ULL << 37) | (2ULL << 29) | (18ULL << 20) |
        (17ULL << 13) | (16ULL << 6);
    const uint64_t shladd_r19_r20_r21_raw =
        (8ULL << 37) | (4ULL << 29) | (1ULL << 27) |
        (21ULL << 20) | (20ULL << 13) | (19ULL << 6);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 14, 0xf0);
    ia64_write_gr(&env, 15, 0xcc);
    ia64_write_gr(&env, 17, 0x10);
    ia64_write_gr(&env, 18, (3ULL << 30) | 0x20);
    ia64_write_gr(&env, 20, 3);
    ia64_write_gr(&env, 21, 5);

    g_assert_true(ia64_slot_is_alu_logic(IA64_SLOT_TYPE_M,
                                         and_r14_r14_r15_raw));
    g_assert_true(ia64_exec_alu_logic(&env, and_r14_r14_r15_raw));
    g_assert_cmphex(ia64_read_gr(&env, 14), ==, 0xc0);

    g_assert_true(ia64_slot_is_alu_addp4(IA64_SLOT_TYPE_M,
                                         addp4_r16_r17_r18_raw));
    g_assert_true(ia64_exec_alu_addp4(&env, addp4_r16_r17_r18_raw));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==,
                    (3ULL << 61) | 0xc0000030);

    g_assert_true(ia64_slot_is_alu_shladd(IA64_SLOT_TYPE_M,
                                          shladd_r19_r20_r21_raw));
    g_assert_true(ia64_exec_alu_shladd(&env, shladd_r19_r20_r21_raw));
    g_assert_cmphex(ia64_read_gr(&env, 19), ==, 17);
}

static void test_packed_alu_a9_a10_family(void)
{
    /* The Debian base-install frontier: pcmp1.eq r57 = r62, r63 (qp p2). */
    const uint64_t debian_pcmp1_eq_raw = make_packed_alu_raw(0, 0, 9, 0,
                                                             57, 62, 63) | 2;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    /* The scalar ALU predicates must not claim this x2a==1 encoding. */
    g_assert_cmphex(debian_pcmp1_eq_raw, ==, 0x10523f7ce42ULL);
    g_assert_false(ia64_slot_is_alu_add(IA64_SLOT_TYPE_M, debian_pcmp1_eq_raw));
    g_assert_true(ia64_slot_is_packed_alu(IA64_SLOT_TYPE_M,
                                          debian_pcmp1_eq_raw));

    ia64_write_gr(&env, 62, 0x0011223344556677ULL);
    ia64_write_gr(&env, 63, 0x00ff223344ff6677ULL);
    g_assert_true(ia64_exec_packed_alu(&env, debian_pcmp1_eq_raw));
    g_assert_cmphex(ia64_read_gr(&env, 57), ==, 0xff00ffffff00ffffULL);

    /* pcmp1.gt r1 = r2, r3 (signed per byte). */
    const uint64_t pcmp1_gt_raw = make_packed_alu_raw(0, 0, 9, 1, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x7f00000000000080ULL);
    ia64_write_gr(&env, 3, 0x0100000000000001ULL);
    g_assert_true(ia64_exec_packed_alu(&env, pcmp1_gt_raw));
    /* lane0: (s8)0x80=-128 > 1? no. lane7: 0x7f=127 > 1? yes. */
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0xff00000000000000ULL);

    /* padd1 modulo. */
    const uint64_t padd1_raw = make_packed_alu_raw(0, 0, 0, 0, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x0102030405060708ULL);
    ia64_write_gr(&env, 3, 0x1020304050607080ULL);
    g_assert_true(ia64_exec_packed_alu(&env, padd1_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x1122334455667788ULL);

    /* padd1.uuu saturates each unsigned byte to 0xff. */
    const uint64_t padd1_uuu_raw = make_packed_alu_raw(0, 0, 0, 2, 1, 2, 3);
    ia64_write_gr(&env, 2, 0xffffffffffffffffULL);
    ia64_write_gr(&env, 3, 0x0101010101010101ULL);
    g_assert_true(ia64_exec_packed_alu(&env, padd1_uuu_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0xffffffffffffffffULL);

    /* padd2.sss saturates a positive overflow to 0x7fff. */
    const uint64_t padd2_sss_raw = make_packed_alu_raw(0, 1, 0, 1, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x0000000000007fffULL);
    ia64_write_gr(&env, 3, 0x0000000000000001ULL);
    g_assert_true(ia64_exec_packed_alu(&env, padd2_sss_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0000000000007fffULL);

    /* psub1 modulo, per byte. */
    const uint64_t psub1_raw = make_packed_alu_raw(0, 0, 1, 0, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x1020304050607080ULL);
    ia64_write_gr(&env, 3, 0x0102030405060708ULL);
    g_assert_true(ia64_exec_packed_alu(&env, psub1_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0f1e2d3c4b5a6978ULL);

    /* pavg1 vs pavg1.raz differ on the round bit. */
    const uint64_t pavg1_raw = make_packed_alu_raw(0, 0, 2, 2, 1, 2, 3);
    const uint64_t pavg1_raz_raw = make_packed_alu_raw(0, 0, 2, 3, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x0000000000000003ULL);
    ia64_write_gr(&env, 3, 0x0000000000000004ULL);
    g_assert_true(ia64_exec_packed_alu(&env, pavg1_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0000000000000003ULL);
    g_assert_true(ia64_exec_packed_alu(&env, pavg1_raz_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0000000000000004ULL);

    /* pshladd2 count=1: sat((s16)r2 << 1) + (s16)r3, per 16-bit lane. */
    const uint64_t pshladd2_raw = make_packed_alu_raw(0, 1, 4, 1, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x0000000000000002ULL);
    ia64_write_gr(&env, 3, 0x0000000000000003ULL);
    g_assert_true(ia64_exec_packed_alu(&env, pshladd2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0000000000000007ULL);

    /* pshradd2 count=1: ((s16)r2 >> 1) + (s16)r3, per 16-bit lane. */
    const uint64_t pshradd2_raw = make_packed_alu_raw(0, 1, 6, 1, 1, 2, 3);
    ia64_write_gr(&env, 2, 0x0000000000000008ULL);
    ia64_write_gr(&env, 3, 0x0000000000000001ULL);
    g_assert_true(ia64_exec_packed_alu(&env, pshradd2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 1), ==, 0x0000000000000005ULL);
}

static void test_i_unit_mux_permutations(void)
{
    const uint64_t elilo_mux1_r33_r33_bcast0_raw = 0x0eca0042840ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 33, 0x1122334455667788ULL);

    g_assert_true(ia64_slot_is_i_mux(IA64_SLOT_TYPE_I,
                                     elilo_mux1_r33_r33_bcast0_raw));
    g_assert_true(ia64_exec_i_mux(&env, elilo_mux1_r33_r33_bcast0_raw));
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0x8888888888888888ULL);
}

static void test_i_unit_packed_i2_frontier_mix4r(void)
{
    const uint64_t linux_mix4r_r2_r8_r8_raw = 0x0f880810080ULL;
    const uint64_t md5_extr_u_r9_r2_25_39_raw =
        make_extract_raw(false, 9, 2, 25, 39);
    IA64ExtractInstruction decoded;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 8, 0x1122334455667788ULL);

    g_assert_true(ia64_slot_is_i_packed_i2(IA64_SLOT_TYPE_I,
                                           linux_mix4r_r2_r8_r8_raw));
    g_assert_false(ia64_slot_is_i_mux(IA64_SLOT_TYPE_I,
                                      linux_mix4r_r2_r8_r8_raw));
    g_assert_true(ia64_exec_i_packed_i2(&env, linux_mix4r_r2_r8_r8_raw));
    g_assert_cmphex(ia64_read_gr(&env, 2), ==, 0x5566778855667788ULL);

    ia64_write_gr(&env, 8, 0x0000000089abcdefULL);
    g_assert_true(ia64_exec_i_packed_i2(&env, linux_mix4r_r2_r8_r8_raw));
    g_assert_cmphex(ia64_read_gr(&env, 2), ==, 0x89abcdef89abcdefULL);
    g_assert_true(ia64_decode_extract(IA64_SLOT_TYPE_I,
                                      md5_extr_u_r9_r2_25_39_raw,
                                      &decoded));
    g_assert_true(ia64_exec_extract(&env, &decoded));
    g_assert_cmphex(ia64_read_gr(&env, 9), ==, 0x44d5e6f7c4ULL);
    g_assert_cmphex(ia64_read_gr(&env, 9) & 0xffffffffULL, ==,
                    0xd5e6f7c4ULL);
}

typedef struct PackedI2Case {
    const char *name;
    uint8_t za;
    uint8_t zb;
    uint8_t x2b;
    uint8_t x2c;
    uint64_t source2;
    uint64_t source3;
    uint64_t expected;
} PackedI2Case;

static void test_i_unit_packed_i2_operations(void)
{
    static const PackedI2Case cases[] = {
        { "mix1.r", 0, 0, 0, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x06f604f402f200f0ULL },
        { "mix1.l", 0, 0, 2, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x07f705f503f301f1ULL },
        { "mix2.r", 0, 1, 0, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x0504f5f40100f1f0ULL },
        { "mix2.l", 0, 1, 2, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x0706f7f60302f3f2ULL },
        { "mix4.r", 1, 0, 0, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x03020100f3f2f1f0ULL },
        { "mix4.l", 1, 0, 2, 2, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x07060504f7f6f5f4ULL },
        { "pack2.uss", 0, 1, 0, 0, 0x00ff007f0000ffffULL,
          0x01900080ff7fff38ULL, 0xff800000ff7f0000ULL },
        { "pack2.sss", 0, 1, 2, 0, 0x00ff007f0000ffffULL,
          0x01900080ff7fff38ULL, 0x7f7f80807f7f00ffULL },
        { "pack4.sss", 1, 0, 2, 0, 0x00007fffffff63c0ULL,
          0xffff7fff00009c40ULL, 0x80007fff7fff8000ULL },
        { "unpack1.h", 0, 0, 0, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x07f706f605f504f4ULL },
        { "unpack1.l", 0, 0, 2, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x03f302f201f100f0ULL },
        { "unpack2.h", 0, 1, 0, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x0706f7f60504f5f4ULL },
        { "unpack2.l", 0, 1, 2, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x0302f3f20100f1f0ULL },
        { "unpack4.h", 1, 0, 0, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x07060504f7f6f5f4ULL },
        { "unpack4.l", 1, 0, 2, 1, 0x0706050403020100ULL,
          0xf7f6f5f4f3f2f1f0ULL, 0x03020100f3f2f1f0ULL },
        { "pmin1.u", 0, 0, 1, 0, 0x80017f00ff105522ULL,
          0x7f0180ffff001133ULL, 0x7f017f00ff001122ULL },
        { "pmax1.u", 0, 0, 1, 1, 0x80017f00ff105522ULL,
          0x7f0180ffff001133ULL, 0x800180ffff105533ULL },
        { "pmin2", 0, 1, 3, 0, 0xfe70012c000afffdULL,
          0x01f4fed40014fffcULL, 0xfe70fed4000afffcULL },
        { "pmax2", 0, 1, 3, 1, 0xfe70012c000afffdULL,
          0x01f4fed40014fffcULL, 0x01f4012c0014fffdULL },
        { "pmpy2.r", 0, 1, 1, 3, 0xfffb0004fffd0002ULL,
          0xfff7fff800070006ULL, 0xffffffe00000000cULL },
        { "pmpy2.l", 0, 1, 3, 3, 0xfffb0004fffd0002ULL,
          0xfff7fff800070006ULL, 0x0000002dffffffebULL },
        { "psad1", 0, 0, 3, 2, 0x0001020304050607ULL,
          0x0706050403020100ULL, 0x20ULL },
    };

    for (unsigned i = 0; i < G_N_ELEMENTS(cases); i++) {
        const PackedI2Case *tc = &cases[i];
        uint64_t raw = make_i2_packed_raw(tc->za, tc->zb, tc->x2b, tc->x2c,
                                          10, 8, 9);
        CPUIA64State env;

        ia64_cpu_reset_synthetic_itanium2(&env);
        ia64_write_gr(&env, 8, tc->source2);
        ia64_write_gr(&env, 9, tc->source3);

        g_test_message("checking %s", tc->name);
        g_assert_true(ia64_slot_is_i_packed_i2(IA64_SLOT_TYPE_I, raw));
        g_assert_true(ia64_exec_i_packed_i2(&env, raw));
        g_assert_cmphex(ia64_read_gr(&env, 10), ==, tc->expected);
        g_assert_false(ia64_read_gr_nat(&env, 10));
    }

    {
        uint64_t raw = make_i2_packed_raw(0, 1, 1, 3, 10, 8, 9);
        CPUIA64State env;

        ia64_cpu_reset_synthetic_itanium2(&env);
        ia64_write_gr(&env, 8, 0xfffb0004fffd0002ULL);
        ia64_write_gr(&env, 9, 0xfff7fff800070006ULL);
        ia64_write_gr_nat(&env, 8, true);
        g_assert_true(ia64_exec_i_packed_i2(&env, raw));
        g_assert_true(ia64_read_gr_nat(&env, 10));
    }
}

typedef struct MultiplyShiftCase {
    const char *name;
    uint8_t za;
    uint8_t zb;
    uint8_t x2b;
    uint8_t x2c;
    uint64_t source2;
    uint64_t source3;
    uint64_t expected;
} MultiplyShiftCase;

static void test_i_unit_multiply_shift_family(void)
{
    static const MultiplyShiftCase cases[] = {
        { "pmpyshr2.u-0",  0, 1, 1, 0, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xff0134000000fffeULL },
        { "pmpyshr2.u-7",  0, 1, 1, 1, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xfdfe2468020003ffULL },
        { "pmpyshr2.u-15", 0, 1, 1, 2, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0x01fd002400020003ULL },
        { "pmpyshr2.u-16", 0, 1, 1, 3, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0x00fe001200010001ULL },
        { "pmpyshr2-0",    0, 1, 3, 0, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xff0134000000fffeULL },
        { "pmpyshr2-7",    0, 1, 3, 1, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xfffe2468fe00ffffULL },
        { "pmpyshr2-15",   0, 1, 3, 2, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xffff0024fffeffffULL },
        { "pmpyshr2-16",   0, 1, 3, 3, 0x00ff12348000ffffULL,
          0xffff010000020002ULL, 0xffff0012ffffffffULL },
        { "mpy4",          1, 0, 1, 3, 0x1234567889abcdefULL,
          0xfedcba9876543210ULL, 0x3fa27837e5618cf0ULL },
        { "mpyshl4",       1, 0, 3, 3, 0x1234567889abcdefULL,
          0xfedcba9876543210ULL, 0x0b88d78000000000ULL },
    };
    const uint64_t windows_pmpyshr2_u_0_raw =
        make_i_multiply_shift_raw(0, 1, 1, 0, 30, 22, 11);
    const uint64_t windows_pmpyshr2_u_16_raw =
        make_i_multiply_shift_raw(0, 1, 1, 3, 10, 22, 11);

    g_assert_cmphex(windows_pmpyshr2_u_0_raw, ==, 0x0e210b2c780ULL);
    g_assert_cmphex(windows_pmpyshr2_u_16_raw, ==, 0x0e2d0b2c280ULL);

    for (unsigned i = 0; i < G_N_ELEMENTS(cases); i++) {
        const MultiplyShiftCase *tc = &cases[i];
        uint64_t raw = make_i_multiply_shift_raw(
            tc->za, tc->zb, tc->x2b, tc->x2c, 10, 8, 9);
        CPUIA64State env;

        ia64_cpu_reset_synthetic_itanium2(&env);
        ia64_write_gr(&env, 8, tc->source2);
        ia64_write_gr(&env, 9, tc->source3);

        g_test_message("checking %s", tc->name);
        g_assert_true(ia64_slot_is_i_multiply_shift(IA64_SLOT_TYPE_I, raw));
        g_assert_true(ia64_exec_i_multiply_shift(&env, raw));
        g_assert_cmphex(ia64_read_gr(&env, 10), ==, tc->expected);
        g_assert_false(ia64_read_gr_nat(&env, 10));

        ia64_write_gr_nat(&env, 9, true);
        g_assert_true(ia64_exec_i_multiply_shift(&env, raw));
        g_assert_true(ia64_read_gr_nat(&env, 10));
    }

    g_assert_false(ia64_slot_is_i_multiply_shift(
        IA64_SLOT_TYPE_I, make_i_multiply_shift_raw(1, 0, 1, 2,
                                                    10, 8, 9)));
    g_assert_false(ia64_slot_is_i_multiply_shift(
        IA64_SLOT_TYPE_M, windows_pmpyshr2_u_0_raw));
}

static void test_i_unit_variable_shifts(void)
{
    const uint64_t elilo_shl_r15_r17_r2_raw = 0x0f2402223c0ULL;
    const uint64_t shr_u_r10_r12_r11_raw =
        (7ULL << 37) | (1ULL << 36) | (1ULL << 33) |
        (12ULL << 20) | (11ULL << 13) | (10ULL << 6);
    const uint64_t shr_r13_r14_r15_raw =
        (7ULL << 37) | (1ULL << 36) | (1ULL << 33) |
        (2ULL << 28) | (14ULL << 20) | (15ULL << 13) |
        (13ULL << 6);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 17, 0x21);
    ia64_write_gr(&env, 2, 8);

    g_assert_true(ia64_slot_is_i_variable_shift(IA64_SLOT_TYPE_I,
                                                elilo_shl_r15_r17_r2_raw));
    g_assert_true(ia64_exec_i_variable_shift(&env, elilo_shl_r15_r17_r2_raw));
    g_assert_cmphex(ia64_read_gr(&env, 15), ==, 0x2100);

    ia64_write_gr(&env, 12, 0x8000000000000000ULL);
    ia64_write_gr(&env, 11, 63);
    g_assert_true(ia64_slot_is_i_variable_shift(IA64_SLOT_TYPE_I,
                                                shr_u_r10_r12_r11_raw));
    g_assert_true(ia64_exec_i_variable_shift(&env, shr_u_r10_r12_r11_raw));
    g_assert_cmphex(ia64_read_gr(&env, 10), ==, 1);

    ia64_write_gr(&env, 14, 0x8000000000000000ULL);
    ia64_write_gr(&env, 15, 64);
    g_assert_true(ia64_slot_is_i_variable_shift(IA64_SLOT_TYPE_I,
                                                shr_r13_r14_r15_raw));
    g_assert_true(ia64_exec_i_variable_shift(&env, shr_r13_r14_r15_raw));
    g_assert_cmphex(ia64_read_gr(&env, 13), ==, UINT64_MAX);
}

static void test_i_unit_bit_count(void)
{
    const uint64_t linux_popcnt_r8_r8_raw = 0x0e690800200ULL;
    const uint64_t clz_r9_r10_raw =
        (7ULL << 37) | (1ULL << 34) | (1ULL << 33) |
        (1ULL << 28) | (3ULL << 30) | (10ULL << 20) |
        (9ULL << 6);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 8, 0xf0f0ULL);

    g_assert_true(ia64_slot_is_i_bit_count(IA64_SLOT_TYPE_I,
                                           linux_popcnt_r8_r8_raw));
    g_assert_true(ia64_exec_i_bit_count(&env, linux_popcnt_r8_r8_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 8);

    ia64_write_gr(&env, 10, 0x000000000000f000ULL);
    g_assert_true(ia64_slot_is_i_bit_count(IA64_SLOT_TYPE_I,
                                           clz_r9_r10_raw));
    g_assert_true(ia64_exec_i_bit_count(&env, clz_r9_r10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 9), ==, 48);
}

static void test_addl_immediate_form(void)
{
    const uint64_t addl_r8_0_r0_raw = 0x12000000200ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 8, 0xdeadbeef);

    g_assert_true(ia64_slot_is_addl(IA64_SLOT_TYPE_M, addl_r8_0_r0_raw));
    g_assert_cmpint(ia64_addl_immediate(addl_r8_0_r0_raw), ==, 0);
    g_assert_true(ia64_exec_addl(&env, addl_r8_0_r0_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0);
}

static void test_m_unit_setf_significand(void)
{
    const uint64_t setf_sig_f8_r17_raw = 0x0c70802220aULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 17, 0x105b000);

    g_assert_true(ia64_slot_is_m_setf(IA64_SLOT_TYPE_M,
                                      setf_sig_f8_r17_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_sig_f8_r17_raw));

    g_assert_cmphex(env.fr[8].raw[0], ==, 0x105b000);
    g_assert_cmphex(env.fr[8].raw[1], ==, 0x1003e);
}

static void test_m_unit_setf_exp_frontier(void)
{
    const uint64_t centos_setf_exp_f7_r2_raw = 0x0c7480041c0ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 2, 0xdead000000021234ULL);

    g_assert_true(ia64_slot_is_m_setf(IA64_SLOT_TYPE_M,
                                      centos_setf_exp_f7_r2_raw));
    g_assert_true(ia64_exec_m_setf(&env, centos_setf_exp_f7_r2_raw));

    g_assert_cmphex(env.fr[7].raw[0], ==, 0x8000000000000000ULL);
    g_assert_cmphex(env.fr[7].raw[1], ==, 0x21234);
}

static void test_m_unit_setf_single_and_double(void)
{
    const uint64_t setf_s_f8_r17_raw = 0x0c788022200ULL;
    const uint64_t setf_d_f8_r17_raw = 0x0c7c8022200ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_gr(&env, 17, 0xbfc00000);
    g_assert_true(ia64_slot_is_m_setf(IA64_SLOT_TYPE_M,
                                      setf_s_f8_r17_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_s_f8_r17_raw));
    g_assert_cmphex(env.fr[8].raw[0], ==, 0xc000000000000000ULL);
    g_assert_cmphex(env.fr[8].raw[1], ==, 0x2ffff);

    ia64_write_gr(&env, 17, 0x4004000000000000ULL);
    g_assert_true(ia64_slot_is_m_setf(IA64_SLOT_TYPE_M,
                                      setf_d_f8_r17_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_d_f8_r17_raw));
    g_assert_cmphex(env.fr[8].raw[0], ==, 0xa000000000000000ULL);
    g_assert_cmphex(env.fr[8].raw[1], ==, 0x10000);
}

static void test_m_unit_setf_nat_source(void)
{
    const uint64_t setf_d_f8_r17_raw = 0x0c7c8022200ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.nat.gr_nat[17 / 64] |= 1ULL << (17 % 64);

    g_assert_true(ia64_slot_is_m_setf(IA64_SLOT_TYPE_M,
                                      setf_d_f8_r17_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_d_f8_r17_raw));
    g_assert_cmphex(env.fr[8].raw[0], ==, 0);
    g_assert_cmphex(env.fr[8].raw[1], ==, 0x1fffe);
}

static void test_m_unit_getf_significand(void)
{
    const uint64_t getf_sig_r21_f10_raw = make_m_getf_raw(0x1c, 21, 10);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[10].raw[0] = 0x1234;
    env.fr[10].raw[1] = 0x1003e;

    g_assert_true(ia64_slot_is_m_getf(IA64_SLOT_TYPE_M,
                                      getf_sig_r21_f10_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_sig_r21_f10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 21), ==, 0x1234);
}

static void test_disabled_fp_register_fault(void)
{
    /* fma f32 = f33, f34, f35 (major 8, F1). */
    const uint64_t fma_high_raw = (0x8ULL << 37) | (35ULL << 27) |
                                  (33ULL << 20) | (34ULL << 13) |
                                  (32ULL << 6);
    /* fma f6 = f7, f8, f9: low partition only. */
    const uint64_t fma_low_raw = (0x8ULL << 37) | (9ULL << 27) |
                                 (8ULL << 20) | (7ULL << 13) |
                                 (6ULL << 6);
    const uint64_t getf_high_raw = make_m_getf_raw(0x1c, 21, 40);
    const uint64_t getf_low_raw = make_m_getf_raw(0x1c, 21, 10);
    CPUIA64State env;
    bool high = false;

    ia64_cpu_reset_synthetic_itanium2(&env);

    /* No dfl/dfh: nothing faults. */
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_F,
                                                fma_high_raw, &high));
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_M,
                                                getf_high_raw, &high));

    /* dfh: only f32-f127 accesses fault, with the high code. */
    env.psr |= IA64_PSR_DFH_BIT;
    g_assert_true(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_F,
                                               fma_high_raw, &high));
    g_assert_true(high);
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_F,
                                                fma_low_raw, &high));
    g_assert_true(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_M,
                                               getf_high_raw, &high));
    g_assert_true(high);
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_M,
                                                getf_low_raw, &high));

    /* dfl: f2-f31 accesses fault with the low code. */
    env.psr &= ~IA64_PSR_DFH_BIT;
    env.psr |= IA64_PSR_DFL_BIT;
    g_assert_true(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_F,
                                               fma_low_raw, &high));
    g_assert_false(high);
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_M,
                                                getf_high_raw, &high));

    /* Non-FP slots never fault. */
    g_assert_false(ia64_slot_raises_disabled_fp(&env, IA64_SLOT_TYPE_I,
                                                fma_low_raw, &high));
}

static void test_fp_write_sets_modified_bits(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_cmphex(env.psr & (IA64_PSR_MFL_BIT | IA64_PSR_MFH_BIT), ==, 0);

    ia64_note_fr_write(&env, 6);
    g_assert_cmphex(env.psr & IA64_PSR_MFL_BIT, ==, IA64_PSR_MFL_BIT);
    g_assert_cmphex(env.psr & IA64_PSR_MFH_BIT, ==, 0);

    ia64_note_fr_write(&env, 40);
    g_assert_cmphex(env.psr & IA64_PSR_MFH_BIT, ==, IA64_PSR_MFH_BIT);

    /* The setf exec path must set mfl via the shared write helper. */
    env.psr &= ~(IA64_PSR_MFL_BIT | IA64_PSR_MFH_BIT);
    ia64_write_gr(&env, 17, 0x1234);
    g_assert_true(ia64_exec_m_setf(&env, 0x0c70802220aULL));
    g_assert_cmphex(env.psr & IA64_PSR_MFL_BIT, ==, IA64_PSR_MFL_BIT);
}

static void test_m_unit_getf_all_memory_forms(void)
{
    const uint64_t getf_exp_r22_f10_raw = make_m_getf_raw(0x1d, 22, 10);
    const uint64_t getf_s_r23_f8_raw = make_m_getf_raw(0x1e, 23, 8);
    const uint64_t getf_d_r40_f6_raw = make_m_getf_raw(0x1f, 40, 6);
    CPUIA64State env;

    g_assert_cmphex(getf_d_r40_f6_raw, ==, 0x087c800ca00ULL);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[10].raw[0] = 0x0123456789abcdefULL;
    env.fr[10].raw[1] = 0x21234;
    env.fr[8].raw[0] = 0xc000000000000000ULL;
    env.fr[8].raw[1] = 0x2ffff;
    env.fr[6].raw[0] = 0xa000000000000000ULL;
    env.fr[6].raw[1] = 0x10000;

    g_assert_true(ia64_slot_is_m_getf(IA64_SLOT_TYPE_M,
                                      getf_exp_r22_f10_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_exp_r22_f10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 22), ==, 0x21234);

    g_assert_true(ia64_slot_is_m_getf(IA64_SLOT_TYPE_M,
                                      getf_s_r23_f8_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_s_r23_f8_raw));
    g_assert_cmphex(ia64_read_gr(&env, 23), ==, 0xbfc00000);

    g_assert_true(ia64_slot_is_m_getf(IA64_SLOT_TYPE_M,
                                      getf_d_r40_f6_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_d_r40_f6_raw));
    g_assert_cmphex(ia64_read_gr(&env, 40), ==, 0x4004000000000000ULL);
}

static void test_floating_ieee_memory_bit_conversions(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_fr_from_double_bits(&env, 8, 0x4014000000000000ULL);
    g_assert_cmphex(env.fr[8].raw[0], ==, 0xa000000000000000ULL);
    g_assert_cmphex(env.fr[8].raw[1], ==, 0x10001);
    g_assert_cmphex(ia64_read_fr_as_double_bits(&env.fr[8]), ==,
                    0x4014000000000000ULL);

    ia64_write_fr_from_single_bits(&env, 9, 0x40a00000);
    g_assert_cmphex(env.fr[9].raw[0], ==, 0xa000000000000000ULL);
    g_assert_cmphex(env.fr[9].raw[1], ==, 0x10001);
    g_assert_cmphex(ia64_read_fr_as_single_bits(&env.fr[9]), ==,
                    0x40a00000);

    env.fr[10].raw[0] = 0x4014000000000000ULL;
    env.fr[10].raw[1] = 0x1003e;
    g_assert_cmphex(ia64_read_fr_as_double_bits(&env.fr[10]), !=,
                    0x4014000000000000ULL);
}

static void test_floating_spill_format_constants(void)
{
    IA64FloatReg reg;
    CPUIA64State env;
    uint64_t sign_exponent;
    uint64_t mantissa;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_float_reg_to_spill(&env.fr[0], &sign_exponent, &mantissa);
    g_assert_cmphex(sign_exponent, ==, 0);
    g_assert_cmphex(mantissa, ==, 0);

    ia64_float_reg_to_spill(&env.fr[1], &sign_exponent, &mantissa);
    g_assert_cmphex(sign_exponent, ==, 0xffff);
    g_assert_cmphex(mantissa, ==, 0x8000000000000000ULL);

    ia64_float_reg_from_spill(0, 0, &reg);
    g_assert_cmphex(reg.raw[0], ==, 0);
    g_assert_cmphex(reg.raw[1], ==, 0x1ffff);

    ia64_float_reg_from_spill(0xffff, 0x8000000000000000ULL, &reg);
    g_assert_cmphex(reg.raw[0], ==, 0x8000000000000000ULL);
    g_assert_cmphex(reg.raw[1], ==, 0xffff);
}

static void test_extract_zero_extends_bitfield(void)
{
    const uint64_t extr_u_r25_r22_0_32_raw = 0x0a4f9600640ULL;
    IA64ExtractInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_extract(IA64_SLOT_TYPE_I,
                                      extr_u_r25_r22_0_32_raw, &decoded));
    g_assert_cmpuint(decoded.target, ==, 25);
    g_assert_cmpuint(decoded.source3, ==, 22);
    g_assert_cmpuint(decoded.position, ==, 0);
    g_assert_cmpuint(decoded.length, ==, 32);
    g_assert_false(decoded.sign_extend);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 22, 0xffffffff0000006fULL);
    g_assert_true(ia64_exec_extract(&env, &decoded));
    g_assert_cmphex(ia64_read_gr(&env, 25), ==, 0x6f);
}

static void test_deposit_zero_from_elilo_frontier(void)
{
    const uint64_t dep_z_r15_r15_8_56_raw = 0x0a7bb71e3c0ULL;
    IA64DepositInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_deposit(IA64_SLOT_TYPE_I,
                                      dep_z_r15_r15_8_56_raw, &decoded));
    g_assert_cmpuint(decoded.target, ==, 15);
    g_assert_cmpuint(decoded.source2, ==, 15);
    g_assert_cmpuint(decoded.position, ==, 8);
    g_assert_cmpuint(decoded.length, ==, 56);
    g_assert_true(decoded.deposit_zero);
    g_assert_false(decoded.source_immediate);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 15, 0x1122334455667788ULL);
    g_assert_true(ia64_exec_deposit(&env, &decoded));
    g_assert_cmphex(ia64_read_gr(&env, 15), ==, 0x2233445566778800ULL);
}

static void test_deposit_immediate_masks_inserted_field(void)
{
    const uint64_t dep_r21_imm_neg1_r0_30_1_raw =
        (UINT64_C(5) << 37) | (UINT64_C(1) << 36) |
        (UINT64_C(3) << 34) | (UINT64_C(1) << 33) |
        (UINT64_C(33) << 14) | (UINT64_C(21) << 6);
    IA64DepositInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_deposit(IA64_SLOT_TYPE_I,
                                      dep_r21_imm_neg1_r0_30_1_raw,
                                      &decoded));
    g_assert_cmpuint(decoded.target, ==, 21);
    g_assert_cmpuint(decoded.source3, ==, 0);
    g_assert_cmpuint(decoded.position, ==, 30);
    g_assert_cmpuint(decoded.length, ==, 1);
    g_assert_true(decoded.source_immediate);
    g_assert_cmphex(decoded.immediate, ==, UINT64_MAX);

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_true(ia64_exec_deposit(&env, &decoded));
    g_assert_cmphex(ia64_read_gr(&env, 21), ==, 0x40000000);
}

static void test_shift_right_pair_from_elilo_frontier(void)
{
    const uint64_t elilo_shrp_r59_r56_r57_16_raw = 0x0ac83970ee8ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 56, 0x1122334455667788ULL);
    ia64_write_gr(&env, 57, 0x99aabbccddeeff00ULL);

    g_assert_true(ia64_slot_is_i_shift_right_pair(
                      IA64_SLOT_TYPE_I,
                      elilo_shrp_r59_r56_r57_16_raw));
    g_assert_true(ia64_exec_i_shift_right_pair(
                      &env,
                      elilo_shrp_r59_r56_r57_16_raw));
    g_assert_cmphex(ia64_read_gr(&env, 59), ==, 0x778899aabbccddeeULL);
}

static void test_integer_extend_zero_extends_byte(void)
{
    const uint64_t zxt1_r8_r8_raw = 0x00080800200ULL;
    IA64IntegerExtendInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_integer_extend(IA64_SLOT_TYPE_I,
                                             zxt1_r8_r8_raw, &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_EXT_ZXT);
    g_assert_cmpuint(decoded.width, ==, 1);
    g_assert_cmpuint(decoded.target, ==, 8);
    g_assert_cmpuint(decoded.source3, ==, 8);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 8, 0x80000000000002ffULL);
    g_assert_true(ia64_exec_integer_extend(&env, &decoded));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0xff);
}

static void test_f_unit_xma_low(void)
{
    const uint64_t xma_l_f10_f8_f10_f9_raw = 0x1d048a10280ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[8].raw[0] = 5;
    env.fr[8].raw[1] = 0x1003e;
    env.fr[9].raw[0] = 7;
    env.fr[9].raw[1] = 0x1003e;
    env.fr[10].raw[0] = 11;
    env.fr[10].raw[1] = 0x1003e;

    g_assert_true(ia64_slot_is_f_select_or_xma(IA64_SLOT_TYPE_F,
                                               xma_l_f10_f8_f10_f9_raw));
    g_assert_true(ia64_exec_f_select_or_xma(&env,
                                            xma_l_f10_f8_f10_f9_raw));

    g_assert_cmphex(env.fr[10].raw[0], ==, 82);
    g_assert_cmphex(env.fr[10].raw[1], ==, 0x1003e);
}

static void test_f_unit_multiply_add_uses_ia64_operand_order(void)
{
    const uint64_t fma_f8_f0_f14_f1_raw = 0x10408e00200ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[14].raw[0] = 0x91a0000000000000ULL;
    env.fr[14].raw[1] = 0x1000b;

    g_assert_true(ia64_slot_is_f_multiply_add(IA64_SLOT_TYPE_F,
                                              fma_f8_f0_f14_f1_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_f8_f0_f14_f1_raw));
    g_assert_cmphex(env.fr[8].raw[0], ==, env.fr[14].raw[0]);
    g_assert_cmphex(env.fr[8].raw[1], ==, env.fr[14].raw[1]);
}

static uint64_t fma_slot_raw(uint8_t major, bool x, uint8_t sf,
                             uint8_t f1, uint8_t f2,
                             uint8_t f3, uint8_t f4)
{
    return ((uint64_t)major << 37) |
           ((uint64_t)(x ? 1 : 0) << 36) |
           ((uint64_t)sf << 34) |
           ((uint64_t)f4 << 27) |
           ((uint64_t)f3 << 20) |
           ((uint64_t)f2 << 13) |
           ((uint64_t)f1 << 6);
}

static uint64_t f_misc_slot_raw(uint8_t x6, uint8_t f1,
                                uint8_t f2, uint8_t f3)
{
    return ((uint64_t)x6 << 27) |
           ((uint64_t)f3 << 20) |
           ((uint64_t)f2 << 13) |
           ((uint64_t)f1 << 6);
}

static void test_f_unit_clear_status_flags(void)
{
    const uint64_t all_status_flags =
        (UINT64_C(0x3f) << 13) |
        (UINT64_C(0x3f) << 26) |
        (UINT64_C(0x3f) << 39) |
        (UINT64_C(0x3f) << 52);
    const uint64_t controls_and_traps = UINT64_C(0x0123456789abcdef) &
                                        ~all_status_flags;
    CPUIA64State env;

    for (unsigned sf = 0; sf < 4; sf++) {
        const uint64_t raw = (UINT64_C(5) << 27) |
                             ((uint64_t)sf << 34);
        const uint64_t selected_flags = UINT64_C(0x3f) << (13 + 13 * sf);
        bool high = false;

        ia64_cpu_reset_synthetic_itanium2(&env);
        env.ar[IA64_AR_FPSR] = controls_and_traps | all_status_flags;
        env.psr |= IA64_PSR_DFL_BIT | IA64_PSR_DFH_BIT;

        g_assert_true(ia64_slot_is_f_misc(IA64_SLOT_TYPE_F, raw));
        g_assert_false(ia64_slot_raises_disabled_fp(
                           &env, IA64_SLOT_TYPE_F, raw, &high));
        g_assert_true(ia64_exec_f_misc(&env, raw));
        g_assert_cmphex(env.ar[IA64_AR_FPSR], ==,
                        controls_and_traps |
                        (all_status_flags & ~selected_flags));
    }
}

static uint64_t test_pair32(uint32_t high, uint32_t low)
{
    return ((uint64_t)high << 32) | low;
}

static void test_f_unit_fma_double_completer_rounds_result(void)
{
    const uint64_t fnorm_d_s0_f7_f7_raw =
        fma_slot_raw(0x9, false, 0, 7, 0, 7, 1);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[7].raw[0] = UINT64_C(0x8000000000000400);
    env.fr[7].raw[1] = 0x10034;

    g_assert_true(ia64_slot_is_f_multiply_add(IA64_SLOT_TYPE_F,
                                              fnorm_d_s0_f7_f7_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnorm_d_s0_f7_f7_raw));
    g_assert_cmphex(env.fr[7].raw[0], ==, UINT64_C(0x8000000000000000));
    g_assert_cmphex(env.fr[7].raw[1], ==, 0x10034);
}

static void test_f_unit_fma_single_completer_rounds_result(void)
{
    const uint64_t fnorm_s_s0_f7_f7_raw =
        fma_slot_raw(0x8, true, 0, 7, 0, 7, 1);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[7].raw[0] = UINT64_C(0x8000008000000000);
    env.fr[7].raw[1] = 0x10017;

    g_assert_true(ia64_slot_is_f_multiply_add(IA64_SLOT_TYPE_F,
                                              fnorm_s_s0_f7_f7_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnorm_s_s0_f7_f7_raw));
    g_assert_cmphex(env.fr[7].raw[0], ==, UINT64_C(0x8000000000000000));
    g_assert_cmphex(env.fr[7].raw[1], ==, 0x10017);
}

static void test_f_unit_reciprocal_approx_sets_predicate(void)
{
    const uint64_t frcpa_f10_p6_f8_f9_raw = 0x00630910280ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[8].raw[0] = 0xa000000000000000ULL;
    env.fr[8].raw[1] = 0x10002;
    env.fr[9] = env.fr[1];

    g_assert_true(ia64_slot_is_f_reciprocal_approx(IA64_SLOT_TYPE_F,
                                                   frcpa_f10_p6_f8_f9_raw));
    g_assert_true(ia64_exec_f_reciprocal_approx(&env,
                                                frcpa_f10_p6_f8_f9_raw));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 1ULL << 6);
    g_assert_cmphex(env.fr[10].raw[0], ==, env.fr[1].raw[0]);
    g_assert_cmphex(env.fr[10].raw[1], ==, env.fr[1].raw[1]);
}

static void test_f_unit_unsigned_mod_helper_keeps_64bit_precision(void)
{
    const uint64_t setf_sig_f14_r32_raw = 0x0c708040380ULL;
    const uint64_t setf_sig_f9_r33_raw = 0x0c708042240ULL;
    const uint64_t fnorm_s1_f8_f14_raw = 0x10408e00200ULL;
    const uint64_t fnorm_s1_f9_f9_raw = 0x10408900240ULL;
    const uint64_t frcpa_s1_f10_p6_f8_f9_raw = 0x00630910280ULL;
    const uint64_t fmpy_s1_f12_f8_f10_raw = 0x10450800300ULL;
    const uint64_t fnma_s1_f11_f9_f10_f1_raw = 0x184509022c0ULL;
    const uint64_t fma_s1_f12_f11_f12_f12_raw = 0x10460b18300ULL;
    const uint64_t fmpy_s1_f13_f11_f11_raw = 0x10458b00340ULL;
    const uint64_t fma_s1_f10_f11_f10_f10_raw = 0x10450b14280ULL;
    const uint64_t fma_s1_f11_f13_f12_f12_raw = 0x10460d182c0ULL;
    const uint64_t fma_s1_f10_f13_f10_f10_raw = 0x10450d14280ULL;
    const uint64_t fnma_s1_f12_f9_f11_f8_raw = 0x18458910300ULL;
    const uint64_t fma_s1_f10_f12_f10_f11_raw = 0x10450c16280ULL;
    const uint64_t fcvt_fxu_trunc_f10_f10_raw = 0x004d8014280ULL;
    const uint64_t xma_l_f10_f10_f9_f14_raw = 0x1d048a1c280ULL;
    const uint64_t getf_sig_r8_f10_raw = 0x08708014200ULL;
    const uint64_t target_addr = 0x600000000000ce00ULL;
    const uint64_t alignment = 0x200;
    const uint64_t quotient = target_addr / alignment;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_gr(&env, 32, target_addr);
    ia64_write_gr(&env, 33, alignment);

    g_assert_true(ia64_exec_m_setf(&env, setf_sig_f14_r32_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_sig_f9_r33_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnorm_s1_f8_f14_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnorm_s1_f9_f9_raw));
    g_assert_true(ia64_exec_f_reciprocal_approx(
                       &env, frcpa_s1_f10_p6_f8_f9_raw));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 1ULL << 6);

    g_assert_true(ia64_exec_f_multiply_add(&env, fmpy_s1_f12_f8_f10_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnma_s1_f11_f9_f10_f1_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_s1_f12_f11_f12_f12_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fmpy_s1_f13_f11_f11_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_s1_f10_f11_f10_f10_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_s1_f11_f13_f12_f12_raw));
    ia64_write_gr(&env, 33, 0 - alignment);
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_s1_f10_f13_f10_f10_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fnma_s1_f12_f9_f11_f8_raw));
    g_assert_true(ia64_exec_m_setf(&env, setf_sig_f9_r33_raw));
    g_assert_true(ia64_exec_f_multiply_add(&env, fma_s1_f10_f12_f10_f11_raw));
    g_assert_true(ia64_exec_f_misc(&env, fcvt_fxu_trunc_f10_f10_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_sig_r8_f10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, quotient);

    g_assert_true(ia64_exec_f_select_or_xma(&env,
                                            xma_l_f10_f10_f9_f14_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_sig_r8_f10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 8), ==, 0);
}

static void test_f_unit_misc_unsigned_trunc_conversion(void)
{
    const uint64_t fcvt_f10_f10_raw = 0x004d8014280ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[10].raw[0] = 0xf780000000000000ULL;
    env.fr[10].raw[1] = 0x10005;

    g_assert_true(ia64_slot_is_f_misc(IA64_SLOT_TYPE_F, fcvt_f10_f10_raw));
    g_assert_true(ia64_exec_f_misc(&env, fcvt_f10_f10_raw));
    g_assert_cmphex(env.fr[10].raw[0], ==, 123);
    g_assert_cmphex(env.fr[10].raw[1], ==, 0x1003e);
}

static void test_f_unit_misc_fsxt_r_frontier(void)
{
    const uint64_t fsxt_r_f6_f7_f7_raw = 0x001e070e180ULL;
    CPUIA64State env;

    g_assert_cmphex(fsxt_r_f6_f7_f7_raw, ==,
                    f_misc_slot_raw(0x3c, 6, 7, 7));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[7].raw[0] = UINT64_C(0x11223344800000aa);
    env.fr[7].raw[1] = 0x1003e;

    g_assert_true(ia64_slot_is_f_misc(IA64_SLOT_TYPE_F,
                                      fsxt_r_f6_f7_f7_raw));
    g_assert_true(ia64_exec_f_misc(&env, fsxt_r_f6_f7_f7_raw));
    g_assert_cmphex(env.fr[6].raw[0], ==,
                    UINT64_C(0xffffffff800000aa));
    g_assert_cmphex(env.fr[6].raw[1], ==, 0x1003e);
}

static void test_f_unit_misc_packed_data_family(void)
{
    static const struct {
        uint8_t x6;
        uint64_t expected;
    } cases[] = {
        { 0x2c, UINT64_C(0x11223344800000aa) &
                UINT64_C(0x556677887fffff55) },
        { 0x2d, UINT64_C(0x11223344800000aa) &
                ~UINT64_C(0x556677887fffff55) },
        { 0x2e, UINT64_C(0x11223344800000aa) |
                UINT64_C(0x556677887fffff55) },
        { 0x2f, UINT64_C(0x11223344800000aa) ^
                UINT64_C(0x556677887fffff55) },
        { 0x34, UINT64_C(0x7fffff5511223344) },
        { 0x35, UINT64_C(0xffffff5511223344) },
        { 0x36, UINT64_C(0x7fffff5591223344) },
        { 0x39, UINT64_C(0x112233447fffff55) },
        { 0x3a, UINT64_C(0x800000aa7fffff55) },
        { 0x3b, UINT64_C(0x1122334455667788) },
        { 0x3c, UINT64_C(0xffffffff7fffff55) },
        { 0x3d, UINT64_C(0x0000000055667788) },
    };
    CPUIA64State env;

    for (unsigned i = 0; i < G_N_ELEMENTS(cases); i++) {
        ia64_cpu_reset_synthetic_itanium2(&env);
        env.fr[8].raw[0] = UINT64_C(0x11223344800000aa);
        env.fr[8].raw[1] = 0x1003e;
        env.fr[9].raw[0] = UINT64_C(0x556677887fffff55);
        env.fr[9].raw[1] = 0x1003e;

        g_assert_true(ia64_slot_is_f_misc(
                          IA64_SLOT_TYPE_F,
                          f_misc_slot_raw(cases[i].x6, 10, 8, 9)));
        g_assert_true(ia64_exec_f_misc(
                          &env,
                          f_misc_slot_raw(cases[i].x6, 10, 8, 9)));
        g_assert_cmphex(env.fr[10].raw[0], ==, cases[i].expected);
        g_assert_cmphex(env.fr[10].raw[1], ==, 0x1003e);
    }

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_fr_from_single_bits(&env, 8, 0x3f800000);
    ia64_write_fr_from_single_bits(&env, 9, 0xc0200000);
    g_assert_true(ia64_exec_f_misc(&env, f_misc_slot_raw(0x28, 10, 8, 9)));
    g_assert_cmphex(env.fr[10].raw[0], ==,
                    test_pair32(0x3f800000, 0xc0200000));
    g_assert_cmphex(env.fr[10].raw[1], ==, 0x1003e);
}

static void test_f_unit_misc_minmax_family(void)
{
    const uint64_t windows_fmax_f10_f1_f10_raw =
        f_misc_slot_raw(0x15, 10, 1, 10);
    CPUIA64State env;
    IA64FloatReg expected_f10;

    g_assert_cmphex(windows_fmax_f10_f1_f10_raw, ==,
                    UINT64_C(0x000a8a02280));

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_fr_from_double_bits(&env, 8, UINT64_C(0x4008000000000000));
    ia64_write_fr_from_double_bits(&env, 9, UINT64_C(0xc010000000000000));
    ia64_write_fr_from_double_bits(&env, 10, UINT64_C(0x4000000000000000));

    g_assert_true(ia64_slot_is_f_misc(IA64_SLOT_TYPE_F,
                                      f_misc_slot_raw(0x14, 11, 8, 10)));
    g_assert_true(ia64_exec_f_misc(&env, f_misc_slot_raw(0x14, 11, 8, 10)));
    g_assert_cmphex(env.fr[11].raw[0], ==, env.fr[10].raw[0]);
    g_assert_cmphex(env.fr[11].raw[1], ==, env.fr[10].raw[1]);

    g_assert_true(ia64_exec_f_misc(&env, f_misc_slot_raw(0x15, 12, 8, 10)));
    g_assert_cmphex(env.fr[12].raw[0], ==, env.fr[8].raw[0]);
    g_assert_cmphex(env.fr[12].raw[1], ==, env.fr[8].raw[1]);

    g_assert_true(ia64_exec_f_misc(&env, f_misc_slot_raw(0x16, 13, 8, 9)));
    g_assert_cmphex(env.fr[13].raw[0], ==, env.fr[8].raw[0]);
    g_assert_cmphex(env.fr[13].raw[1], ==, env.fr[8].raw[1]);

    g_assert_true(ia64_exec_f_misc(&env, f_misc_slot_raw(0x17, 14, 8, 9)));
    g_assert_cmphex(env.fr[14].raw[0], ==, env.fr[9].raw[0]);
    g_assert_cmphex(env.fr[14].raw[1], ==, env.fr[9].raw[1]);

    expected_f10 = env.fr[10];
    g_assert_true(ia64_exec_f_misc(&env, windows_fmax_f10_f1_f10_raw));
    g_assert_cmphex(env.fr[10].raw[0], ==, expected_f10.raw[0]);
    g_assert_cmphex(env.fr[10].raw[1], ==, expected_f10.raw[1]);
}

static void test_f_unit_misc_noop(void)
{
    const uint64_t elilo_nop_f_raw = 0x00008000000ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[4].raw[0] = 0x123456789abcdef0ULL;
    env.fr[4].raw[1] = 0x1003e;

    g_assert_true(ia64_slot_is_f_misc(IA64_SLOT_TYPE_F, elilo_nop_f_raw));
    g_assert_true(ia64_exec_f_misc(&env, elilo_nop_f_raw));
    g_assert_cmphex(env.fr[4].raw[0], ==, 0x123456789abcdef0ULL);
    g_assert_cmphex(env.fr[4].raw[1], ==, 0x1003e);
}

static void test_ldst_immediate_decode(void)
{
    const uint64_t elilo_ld8_r16_r33_8_raw = 0x0a0c2110400ULL;
    const uint64_t elilo_ld8_r17_r33_8_raw = 0x0a0c2110440ULL;
    const uint64_t elilo_ld8_r16_r33_advanced_raw = 0x082c2100400ULL;
    const uint64_t ld8_s_r16_r33_raw =
        (0x4ULL << 37) | (((1ULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (16ULL << 6);
    const uint64_t ld8_sa_r16_r33_raw =
        (0x4ULL << 37) | (((3ULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (16ULL << 6);
    const uint64_t ld8_c_clr_r16_r33_raw =
        (0x4ULL << 37) | (((8ULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (16ULL << 6);
    const uint64_t ld8_c_nc_r16_r33_raw =
        (0x4ULL << 37) | (((9ULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (16ULL << 6);
    const uint64_t ld8_c_clr_acq_r16_r33_raw =
        (0x4ULL << 37) | (((0x0aULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (16ULL << 6);
    const uint64_t ld8_fill_r28_r33_raw =
        (0x4ULL << 37) | (((6ULL << 2) | 3ULL) << 30) |
        (33ULL << 20) | (28ULL << 6);
    const uint64_t ld4_fill_reserved_r28_r33_raw =
        (0x4ULL << 37) | (((6ULL << 2) | 2ULL) << 30) |
        (33ULL << 20) | (28ULL << 6);
    const uint64_t elilo_st8_spill_r39_r16_imm_raw = 0x0bec904fc00ULL;
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

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             elilo_ld8_r16_r33_advanced_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 16);
    g_assert_cmpuint(decoded.base, ==, 33);
    g_assert_cmpuint(decoded.memory_class, ==, 2);
    g_assert_false(decoded.base_update);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_s_r16_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.memory_class, ==, 1);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_sa_r16_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.memory_class, ==, 3);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_c_clr_r16_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 16);
    g_assert_cmpuint(decoded.base, ==, 33);
    g_assert_cmpuint(decoded.memory_class, ==, 8);
    g_assert_false(decoded.base_update);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_c_nc_r16_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.memory_class, ==, 9);

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_c_clr_acq_r16_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.memory_class, ==, 0x0a);
    g_assert_false(ia64_ldst_immediate_is_fill(&decoded));

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             ld8_fill_r28_r33_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_LOAD);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 28);
    g_assert_cmpuint(decoded.base, ==, 33);
    g_assert_cmpuint(decoded.memory_class, ==, 6);
    g_assert_true(ia64_ldst_immediate_is_fill(&decoded));
    g_assert_false(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                              ld4_fill_reserved_r28_r33_raw,
                                              &decoded));

    g_assert_true(ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M,
                                             elilo_st8_spill_r39_r16_imm_raw,
                                             &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_LDST_IMM_STORE);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.source, ==, 39);
    g_assert_cmpuint(decoded.base, ==, 16);
    g_assert_cmpuint(decoded.memory_class, ==, 0x0e);
    g_assert_true(decoded.base_update);
    g_assert_false(decoded.update_from_register);
    g_assert_cmpint(decoded.immediate, ==, -16);
    g_assert_true(ia64_ldst_immediate_is_spill(&decoded));
}

static void test_general_register_write_clears_nat(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr_nat(&env, 22, true);
    g_assert_true(ia64_read_gr_nat(&env, 22));

    ia64_write_gr(&env, 22, 0x1234);
    g_assert_false(ia64_read_gr_nat(&env, 22));

    ia64_write_gr_nat(&env, 0, true);
    g_assert_false(ia64_read_gr_nat(&env, 0));
}

static void test_ldst_base_update_helper(void)
{
    CPUIA64State env;
    IA64LdstImmediate decoded;

    ia64_cpu_reset_synthetic_itanium2(&env);
    memset(&decoded, 0, sizeof(decoded));
    decoded.kind = IA64_LDST_IMM_LOAD;
    decoded.base = 33;
    decoded.base_update = true;
    decoded.immediate = 8;

    ia64_write_gr(&env, 33, 0x1000);
    ia64_write_gr_nat(&env, 33, true);
    ia64_ldst_apply_base_update(&env, &decoded, ia64_read_gr(&env, 33));
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0x1008);
    g_assert_false(ia64_read_gr_nat(&env, 33));

    ia64_write_gr(&env, 33, 0x2000);
    ia64_write_gr(&env, 44, 0x30);
    ia64_write_gr_nat(&env, 44, true);
    decoded.update_from_register = true;
    decoded.update_source = 44;
    ia64_ldst_apply_base_update(&env, &decoded, ia64_read_gr(&env, 33));
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0x2000);
    g_assert_true(ia64_read_gr_nat(&env, 33));
}

static void test_stacked_register_nat_uses_physical_slot(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 10;
    ia64_set_cfm(&env, ia64_make_cfm(4, 4, 0));

    ia64_write_gr_nat(&env, 33, true);
    g_assert_true(ia64_read_gr_nat(&env, 33));
    g_assert_false(ia64_rse_read_physical_nat(&env, 11));

    ia64_rse_sync_logical_out(&env);

    g_assert_true(ia64_rse_read_physical_nat(&env, 11));

    env.rse.current_frame_base = 20;
    ia64_rse_sync_logical_in(&env);
    g_assert_false(ia64_read_gr_nat(&env, 33));
    g_assert_true(ia64_rse_read_physical_nat(&env, 11));
}

static void test_stacked_register_nat_high_slot_uses_rse_bitmap(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 424;
    ia64_set_cfm(&env, ia64_make_cfm(15, 10, 0));
    env.nat.gr_nat[0] = 0xaaaaaaaaaaaaaaaaULL;
    env.nat.gr_nat[1] = 0x5555555555555555ULL;
    env.nat.unat = 0x1111222233334444ULL;
    env.nat.rnat = 0x5555666677778888ULL;
    env.interrupt.pending_interruption = 0x0123456789abcdefULL;
    env.interrupt.pending_vector = 0xfedcba9876543210ULL;

    ia64_write_gr_nat(&env, 38, true);
    g_assert_true(ia64_read_gr_nat(&env, 38));
    g_assert_false(ia64_rse_read_physical_nat(&env, 430));
    ia64_rse_sync_logical_out(&env);
    g_assert_true(ia64_rse_read_physical_nat(&env, 430));
    g_assert_cmphex(env.nat.gr_nat[0], ==, 0xaaaaaaaaaaaaaaaaULL);
    g_assert_cmphex(env.nat.gr_nat[1], ==, 0x5555555555555555ULL);
    g_assert_cmphex(env.nat.unat, ==, 0x1111222233334444ULL);
    g_assert_cmphex(env.nat.rnat, ==, 0x5555666677778888ULL);
    g_assert_cmphex(env.interrupt.pending_interruption, ==,
                    0x0123456789abcdefULL);
    g_assert_cmphex(env.interrupt.pending_vector, ==, 0xfedcba9876543210ULL);

    ia64_write_gr(&env, 38, 0x10fee48);
    g_assert_false(ia64_read_gr_nat(&env, 38));
    g_assert_true(ia64_rse_read_physical_nat(&env, 430));
    ia64_rse_sync_logical_out(&env);
    g_assert_false(ia64_rse_read_physical_nat(&env, 430));
    g_assert_cmphex(env.nat.gr_nat[0], ==, 0xaaaaaaaaaaaaaaaaULL);
    g_assert_cmphex(env.nat.gr_nat[1], ==, 0x5555555555555555ULL);
    g_assert_cmphex(env.nat.unat, ==, 0x1111222233334444ULL);
    g_assert_cmphex(env.nat.rnat, ==, 0x5555666677778888ULL);
    g_assert_cmphex(env.interrupt.pending_interruption, ==,
                    0x0123456789abcdefULL);
    g_assert_cmphex(env.interrupt.pending_vector, ==, 0xfedcba9876543210ULL);
}

static void test_rse_logical_sync_covers_all_names_at_sof_zero(void)
{
    CPUIA64State env;
    uint32_t first_slot = IA64_STACKED_GR_COUNT - 6;
    uint32_t last_slot = ia64_rse_wrap_slot(first_slot + 95);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = first_slot;
    ia64_set_cfm(&env, 0);
    env.rse.stacked_gr[first_slot] = 0x3200;
    env.rse.stacked_gr[last_slot] = 0x12700;
    ia64_rse_write_physical_nat(&env, last_slot, true);

    ia64_rse_sync_logical_in(&env);

    g_assert_cmphex(ia64_read_gr(&env, 32), ==, 0x3200);
    g_assert_cmphex(ia64_read_gr(&env, 127), ==, 0x12700);
    g_assert_true(ia64_read_gr_nat(&env, 127));
    g_assert_cmphex(env.rse.logical_nat[1] & ~UINT64_C(0xffffffff), ==, 0);

    ia64_write_gr(&env, 127, 0xfeed127);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, UINT64_C(1) << 31);
    ia64_rse_sync_logical_out(&env);
    g_assert_cmphex(env.rse.stacked_gr[last_slot], ==, 0xfeed127);
    g_assert_false(ia64_rse_read_physical_nat(&env, last_slot));
}

static void test_rse_rotation_publishes_then_rebuilds_logical_names(void)
{
    const uint64_t br_ctop_raw = 0x080000001c0ULL;
    CPUIA64State env;
    uint64_t target = 0;
    bool taken = false;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = 40;
    ia64_set_cfm(&env, ia64_make_cfm(8, 8, 1));
    for (uint32_t i = 0; i < 8; i++) {
        env.rse.stacked_gr[40 + i] = 0x9000 + i;
    }
    ia64_rse_sync_logical_in(&env);
    ia64_write_gr(&env, 32, 0xa000);
    ia64_write_gr_nat(&env, 32, true);
    env.ar[IA64_AR_LC] = 1;

    g_assert_true(ia64_exec_b_branch_relative(
        &env, br_ctop_raw, 0x2000, &target, &taken));

    g_assert_true(taken);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 7);
    g_assert_cmphex(env.rse.stacked_gr[40], ==, 0xa000);
    g_assert_true(ia64_rse_read_physical_nat(&env, 40));
    g_assert_cmphex(ia64_read_gr(&env, 32), ==, 0x9007);
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0xa000);
    g_assert_true(ia64_read_gr_nat(&env, 33));
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
}

typedef struct IA64ModuloRotationRow {
    const char *path;
    uint32_t sor;
    uint32_t rrb_gr;
    uint32_t rrb_fr;
    uint32_t rrb_pr;
    uint32_t expected_rrb_gr;
    uint32_t expected_rrb_fr;
    uint32_t expected_rrb_pr;
} IA64ModuloRotationRow;

static const IA64ModuloRotationRow modulo_rotation_rows[] = {
    {
        .path = "/ia64-insn/modulo-rotation/sor-zero",
        .sor = 0,
        .rrb_gr = 0,
        .rrb_fr = 0,
        .rrb_pr = 0,
        .expected_rrb_gr = 0,
        .expected_rrb_fr = 95,
        .expected_rrb_pr = 47,
    },
    {
        .path = "/ia64-insn/modulo-rotation/sor-one-wrap",
        .sor = 1,
        .rrb_gr = 0,
        .rrb_fr = 0,
        .rrb_pr = 0,
        .expected_rrb_gr = 7,
        .expected_rrb_fr = 95,
        .expected_rrb_pr = 47,
    },
    {
        .path = "/ia64-insn/modulo-rotation/sor-one-nonwrap",
        .sor = 1,
        .rrb_gr = 5,
        .rrb_fr = 73,
        .rrb_pr = 35,
        .expected_rrb_gr = 4,
        .expected_rrb_fr = 72,
        .expected_rrb_pr = 34,
    },
    {
        .path = "/ia64-insn/modulo-rotation/sor-five-crossword",
        .sor = 5,
        .rrb_gr = 17,
        .rrb_fr = 2,
        .rrb_pr = 2,
        .expected_rrb_gr = 16,
        .expected_rrb_fr = 1,
        .expected_rrb_pr = 1,
    },
    {
        .path = "/ia64-insn/modulo-rotation/sor-max",
        .sor = 12,
        .rrb_gr = 0,
        .rrb_fr = 1,
        .rrb_pr = 1,
        .expected_rrb_gr = 95,
        .expected_rrb_fr = 0,
        .expected_rrb_pr = 0,
    },
};

static void test_modulo_rotation_row(gconstpointer opaque)
{
    const IA64ModuloRotationRow *row = opaque;
    const uint64_t rename_mask =
        (UINT64_C(0x7f) << 18) |
        (UINT64_C(0x7f) << 25) |
        (UINT64_C(0x3f) << 32);
    const uint32_t frame_base = 80;
    const uint32_t rotating_count = row->sor * 8;
    uint64_t old_gr[IA64_GR_COUNT - IA64_STATIC_GR_COUNT];
    bool old_nat[IA64_GR_COUNT - IA64_STATIC_GR_COUNT];
    CPUIA64State env;
    IA64IssueGroupState old_issue_group;
    uint64_t old_cfm;
    uint64_t expected_cfm;
    uint64_t old_pr;
    uint64_t old_lc;
    uint64_t old_ec;
    uint64_t old_ip;
    bool old_group_start;
    bool old_group_dirty;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = frame_base;
    old_cfm = ia64_make_cfm(96, 64, row->sor) |
              ((uint64_t)row->rrb_gr << 18) |
              ((uint64_t)row->rrb_fr << 25) |
              ((uint64_t)row->rrb_pr << 32) |
              UINT64_C(0x5a5a000000000000);
    ia64_set_cfm(&env, old_cfm);

    for (uint32_t logical = 0; logical < G_N_ELEMENTS(old_gr); logical++) {
        uint32_t reg = IA64_STATIC_GR_COUNT + logical;

        old_gr[logical] = UINT64_C(0x9000000000000000) | logical;
        old_nat[logical] = logical % 3 == 1 || logical == 95;
        ia64_write_gr(&env, reg, old_gr[logical]);
        ia64_write_gr_nat(&env, reg, old_nat[logical]);
    }
    g_assert_cmphex(env.rse.logical_dirty[0], ==, UINT64_MAX);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, UINT64_C(0xffffffff));

    env.pr = UINT64_C(0x8123456789abcdef) | 1;
    env.ar[IA64_AR_LC] = UINT64_C(0x1122334455667788);
    env.ar[IA64_AR_EC] = UINT64_C(0x8877665544332211);
    env.ip = UINT64_C(0x123456789abcdef0);
    env.instruction_group_start = false;
    env.instruction_group_dirty = true;
    for (uint32_t reg = 0; reg < IA64_GR_COUNT; reg++) {
        env.issue_group.saved_gr[reg] =
            UINT64_C(0x7000000000000000) | reg;
        env.issue_group.saved_nat[reg] = reg % 3 == 2;
    }
    for (uint32_t reg = 0; reg < IA64_BR_COUNT; reg++) {
        env.issue_group.saved_br[reg] =
            UINT64_C(0x6000000000000000) | reg;
    }
    env.issue_group.saved_gr_mask[0] = UINT64_C(0xa5a5a5a5a5a5a5a5);
    env.issue_group.saved_gr_mask[1] = UINT64_C(0x963c5aa50ff033cc);
    env.issue_group.saved_pr = UINT64_C(0x0f0ff0f05a5aa5a5);
    env.issue_group.branch_pr_forward_mask =
        UINT64_C(0x55aa33cc0ff0f00f);
    env.issue_group.saved_br_mask = 0x5a;
    env.issue_group.branch_br_forward_mask = 0xa5;
    env.issue_group.pr_saved = true;
    env.issue_group.typed_active = true;
    old_pr = env.pr;
    old_lc = env.ar[IA64_AR_LC];
    old_ec = env.ar[IA64_AR_EC];
    old_ip = env.ip;
    old_group_start = env.instruction_group_start;
    old_group_dirty = env.instruction_group_dirty;
    old_issue_group = env.issue_group;

    ia64_rotate_modulo_scheduled_registers(&env);

    g_assert_cmphex(env.pr, ==, old_pr);
    g_assert_cmphex(env.ar[IA64_AR_LC], ==, old_lc);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, old_ec);
    g_assert_cmphex(env.ip, ==, old_ip);
    g_assert_cmpint(env.instruction_group_start, ==, old_group_start);
    g_assert_cmpint(env.instruction_group_dirty, ==, old_group_dirty);
    for (uint32_t reg = 0; reg < IA64_GR_COUNT; reg++) {
        uint32_t source = reg;
        bool actual_mask;
        bool expected_mask;

        if (reg >= IA64_STATIC_GR_COUNT &&
            reg < IA64_STATIC_GR_COUNT + rotating_count) {
            source = IA64_STATIC_GR_COUNT +
                     (reg - IA64_STATIC_GR_COUNT + rotating_count - 1) %
                     rotating_count;
        }
        g_assert_cmphex(env.issue_group.saved_gr[reg], ==,
                        old_issue_group.saved_gr[source]);
        g_assert_cmphex(env.issue_group.saved_nat[reg], ==,
                        old_issue_group.saved_nat[source]);
        actual_mask = (env.issue_group.saved_gr_mask[reg / 64] &
                       (UINT64_C(1) << (reg % 64))) != 0;
        expected_mask = (old_issue_group.saved_gr_mask[source / 64] &
                         (UINT64_C(1) << (source % 64))) != 0;
        g_assert_cmpint(actual_mask, ==, expected_mask);
    }
    g_assert_cmpint(memcmp(env.issue_group.saved_br,
                           old_issue_group.saved_br,
                           sizeof(env.issue_group.saved_br)), ==, 0);
    g_assert_cmphex(env.issue_group.saved_pr, ==, old_issue_group.saved_pr);
    g_assert_cmphex(env.issue_group.branch_pr_forward_mask, ==,
                    old_issue_group.branch_pr_forward_mask);
    g_assert_cmphex(env.issue_group.saved_br_mask, ==,
                    old_issue_group.saved_br_mask);
    g_assert_cmphex(env.issue_group.branch_br_forward_mask, ==,
                    old_issue_group.branch_br_forward_mask);
    g_assert_cmpint(env.issue_group.pr_saved, ==,
                    old_issue_group.pr_saved);
    g_assert_cmpint(env.issue_group.typed_active, ==,
                    old_issue_group.typed_active);
    g_assert_cmpuint(env.rse.rrb_gr, ==, row->expected_rrb_gr);
    g_assert_cmpuint(env.rse.rrb_fr, ==, row->expected_rrb_fr);
    g_assert_cmpuint(env.rse.rrb_pr, ==, row->expected_rrb_pr);
    expected_cfm = (old_cfm & ~rename_mask) |
                   ((uint64_t)row->expected_rrb_gr << 18) |
                   ((uint64_t)row->expected_rrb_fr << 25) |
                   ((uint64_t)row->expected_rrb_pr << 32);
    g_assert_cmphex(env.cfm, ==, expected_cfm);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, 0);

    for (uint32_t logical = 0; logical < G_N_ELEMENTS(old_gr); logical++) {
        uint32_t source = logical;
        uint32_t old_slot_offset = logical;

        if (logical < rotating_count) {
            source = (logical + rotating_count - 1) % rotating_count;
            old_slot_offset =
                (logical + row->rrb_gr) % rotating_count;
        }
        g_assert_cmphex(ia64_read_gr(&env, IA64_STATIC_GR_COUNT + logical),
                        ==, old_gr[source]);
        g_assert_cmpint(ia64_read_gr_nat(
                            &env, IA64_STATIC_GR_COUNT + logical),
                        ==, old_nat[source]);
        g_assert_cmphex(env.rse.stacked_gr[frame_base + old_slot_offset],
                        ==, old_gr[logical]);
        g_assert_cmpint(ia64_rse_read_physical_nat(
                            &env, frame_base + old_slot_offset),
                        ==, old_nat[logical]);
    }

    /* A later authority rebuild must reproduce the fast logical rotation. */
    ia64_rse_sync_logical_in(&env);
    for (uint32_t logical = 0; logical < G_N_ELEMENTS(old_gr); logical++) {
        uint32_t source = logical < rotating_count ?
            (logical + rotating_count - 1) % rotating_count : logical;

        g_assert_cmphex(ia64_read_gr(&env, IA64_STATIC_GR_COUNT + logical),
                        ==, old_gr[source]);
        g_assert_cmpint(ia64_read_gr_nat(
                            &env, IA64_STATIC_GR_COUNT + logical),
                        ==, old_nat[source]);
    }
}

static void test_modulo_rotation_leaves_inactive_overlay_untouched(void)
{
    CPUIA64State env;
    IA64IssueGroupState old_issue_group;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(96, 64, 12));
    for (uint32_t reg = 0; reg < IA64_GR_COUNT; reg++) {
        env.issue_group.saved_gr[reg] = UINT64_C(0x8000) + reg;
        env.issue_group.saved_nat[reg] = reg & 1;
    }
    env.issue_group.saved_gr_mask[0] = UINT64_C(0xaaaaaaaa55555555);
    env.issue_group.saved_gr_mask[1] = UINT64_C(0x0123456789abcdef);
    env.issue_group.saved_pr = UINT64_C(0x55aa55aa55aa55aa);
    env.issue_group.branch_pr_forward_mask = UINT64_C(0xa55aa55aa55aa55a);
    env.issue_group.saved_br_mask = 0x5a;
    env.issue_group.branch_br_forward_mask = 0xa5;
    env.issue_group.pr_saved = true;
    env.issue_group.typed_active = false;
    old_issue_group = env.issue_group;

    ia64_rotate_modulo_scheduled_registers(&env);

    g_assert_cmpint(memcmp(&env.issue_group, &old_issue_group,
                           sizeof(old_issue_group)), ==, 0);
}

static void test_modulo_rotation_invalidates_only_rotating_alat(void)
{
    static const uint32_t targets[] = { 12, 32, 39, 40, 127 };
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(96, 64, 1));
    for (uint32_t i = 0; i < G_N_ELEMENTS(targets); i++) {
        ia64_alat_record_gr(&env, targets[i], 0x1000 + i * 0x10, 8, true);
    }

    ia64_rotate_modulo_scheduled_registers(&env);

    g_assert_true(env.alat.entries[0].valid);
    g_assert_false(env.alat.entries[1].valid);
    g_assert_false(env.alat.entries[2].valid);
    g_assert_true(env.alat.entries[3].valid);
    g_assert_true(env.alat.entries[4].valid);
    g_assert_cmphex(env.alat.valid_mask, ==,
                    (1u << 0) | (1u << 3) | (1u << 4));
    g_assert_cmphex(env.alat.gr_mask[0], ==,
                    (UINT64_C(1) << 12) | (UINT64_C(1) << 40));
    g_assert_cmphex(env.alat.gr_mask[1], ==, UINT64_C(1) << 63);
    g_assert_cmpuint(env.alat.gr_refcount[32], ==, 0);
    g_assert_cmpuint(env.alat.gr_refcount[39], ==, 0);
    g_assert_cmpuint(env.alat.gr_refcount[40], ==, 1);
    g_assert_cmpuint(env.alat.next, ==, G_N_ELEMENTS(targets));

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(96, 64, 0));
    ia64_alat_record_gr(&env, 32, 0x2000, 8, true);
    ia64_rotate_modulo_scheduled_registers(&env);
    g_assert_true(env.alat.entries[0].valid);
    g_assert_cmphex(env.alat.valid_mask, ==, 1);
}

static void test_loop_branch_slot_and_b2_legality(void)
{
    for (uint32_t btype = 2; btype <= 7; btype++) {
        uint64_t raw;

        if (btype == 4) {
            continue;
        }
        raw = (UINT64_C(0x4) << 37) | ((uint64_t)btype << 6);
        g_assert_true(ia64_b_loop_branch_is_legal(IA64_SLOT_TYPE_B,
                                                  raw, 2));
        g_assert_false(ia64_b_loop_branch_is_legal(IA64_SLOT_TYPE_B,
                                                   raw, 0));
        g_assert_false(ia64_b_loop_branch_is_legal(IA64_SLOT_TYPE_B,
                                                   raw, 1));
        if (btype >= 5) {
            g_assert_false(ia64_b_loop_branch_is_legal(
                               IA64_SLOT_TYPE_B, raw | 1, 2));
        } else {
            g_assert_true(ia64_b_loop_branch_is_legal(
                              IA64_SLOT_TYPE_B, raw | 17, 2));
        }
    }

    g_assert_true(ia64_b_loop_branch_is_legal(
                      IA64_SLOT_TYPE_B, UINT64_C(0x4) << 37, 0));
    g_assert_true(ia64_b_loop_branch_is_legal(
                      IA64_SLOT_TYPE_I,
                      (UINT64_C(0x4) << 37) | (UINT64_C(7) << 6) | 1, 0));
}

static void test_alat_check_load_helpers(void)
{
    CPUIA64State env;

    memset(&env, 0, sizeof(env));
    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_alat_record_gr(&env, 12, 0x2000, 8, true);
    g_assert_cmpuint(env.alat.valid_mask, !=, 0);
    g_assert_cmphex(env.alat.gr_mask[0], ==, 1ULL << 12);
    g_assert_cmpuint(env.alat.gr_refcount[12], ==, 1);
    g_assert_cmpuint(env.alat.valid_mask & (env.alat.valid_mask - 1), ==, 0);
    g_assert_true(ia64_alat_check_gr(&env, 12, 0x2000, 8, true, false));
    g_assert_cmpuint(env.alat.valid_mask, !=, 0);
    g_assert_cmpuint(env.alat.valid_mask & (env.alat.valid_mask - 1), ==, 0);

    g_assert_true(ia64_alat_check_gr(&env, 12, 0x2000, 8, true, true));
    g_assert_cmpuint(env.alat.valid_mask, ==, 0);

    ia64_alat_record_gr(&env, 12, 0x2000, 8, true);
    g_assert_false(ia64_alat_check_gr(&env, 12, 0x2008, 8, true, true));
    g_assert_cmpuint(env.alat.valid_mask, ==, 0);
    g_assert_cmphex(env.alat.gr_mask[0], ==, 0);
    g_assert_cmpuint(env.alat.gr_refcount[12], ==, 0);

    ia64_alat_record_gr(&env, 12, 0x2000, 8, true);
    ia64_alat_record_gr(&env, 12, 0x3000, 4, false);
    g_assert_cmpuint(env.alat.gr_refcount[12], ==, 1);
    g_assert_cmpuint(env.alat.valid_mask & (env.alat.valid_mask - 1), ==, 0);
    g_assert_true(ia64_alat_check_gr(&env, 12, 0x3000, 4, false, false));
    g_assert_false(ia64_alat_check_gr(&env, 12, 0x2000, 4, true, false));
    g_assert_cmpuint(env.alat.valid_mask, !=, 0);
    g_assert_cmpuint(env.alat.valid_mask & (env.alat.valid_mask - 1), ==, 0);
}

static void test_m_unit_atomic_decode(void)
{
    const uint64_t linux_fetchadd4_acq_r3_r32_raw = 0x0848a0060c0ULL;
    const uint64_t cmpxchg4_rel_r8_r9_r10_raw =
        (0x4ULL << 37) | (0x6ULL << 30) | (1ULL << 27) |
        (10ULL << 20) | (9ULL << 13) | (8ULL << 6);
    const uint64_t xchg8_r13_r12_r11_raw =
        (0x4ULL << 37) | (0x0bULL << 30) | (1ULL << 27) |
        (11ULL << 20) | (12ULL << 13) | (13ULL << 6);
    IA64AtomicInstruction decoded;

    g_assert_true(ia64_decode_m_atomic(IA64_SLOT_TYPE_M,
                                       linux_fetchadd4_acq_r3_r32_raw,
                                       &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_ATOMIC_FETCHADD);
    g_assert_cmpuint(decoded.width, ==, 4);
    g_assert_cmpuint(decoded.target, ==, 3);
    g_assert_cmpuint(decoded.base, ==, 32);
    g_assert_false(decoded.release);
    g_assert_cmpint(decoded.immediate, ==, 1);

    g_assert_true(ia64_decode_m_atomic(IA64_SLOT_TYPE_M,
                                       cmpxchg4_rel_r8_r9_r10_raw,
                                       &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_ATOMIC_CMPXCHG);
    g_assert_cmpuint(decoded.width, ==, 4);
    g_assert_cmpuint(decoded.target, ==, 8);
    g_assert_cmpuint(decoded.source, ==, 9);
    g_assert_cmpuint(decoded.base, ==, 10);
    g_assert_true(decoded.release);

    g_assert_true(ia64_decode_m_atomic(IA64_SLOT_TYPE_M,
                                       xchg8_r13_r12_r11_raw,
                                       &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_ATOMIC_XCHG);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.target, ==, 13);
    g_assert_cmpuint(decoded.source, ==, 12);
    g_assert_cmpuint(decoded.base, ==, 11);
    g_assert_false(decoded.release);
}

static void test_floating_memory_decode(void)
{
    const uint64_t stf_spill_f2_r17_raw = 0x0cec1104000ULL;
    const uint64_t elilo_stf_spill_f4_r8_imm32_raw = 0x0eef0808800ULL;
    const uint64_t linux_stf_spill_f0_r27_imm32_raw = 0x0eec1b00800ULL;
    const uint64_t linux_lfetch_r32_raw = 0x0cb12000000ULL;
    const uint64_t ldfp8_f32_f41_r21_update_raw = 0x0d049552810ULL;
    const uint64_t ldfpd_f8_f9_r10_raw = 0x0c0c8a12200ULL;
    IA64FloatingMemoryInstruction decoded;

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              stf_spill_f2_r17_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_STORE);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_SPILL_FILL);
    g_assert_cmpuint(decoded.width, ==, 16);
    g_assert_cmpuint(decoded.freg, ==, 2);
    g_assert_cmpuint(decoded.base, ==, 17);
    g_assert_cmpuint(decoded.memory_class, ==, 0x0e);
    g_assert_false(decoded.base_update);

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              elilo_stf_spill_f4_r8_imm32_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_STORE);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_SPILL_FILL);
    g_assert_cmpuint(decoded.width, ==, 16);
    g_assert_cmpuint(decoded.freg, ==, 4);
    g_assert_cmpuint(decoded.base, ==, 8);
    g_assert_cmpuint(decoded.memory_class, ==, 0x0e);
    g_assert_true(decoded.base_update);
    g_assert_false(decoded.update_from_register);
    g_assert_cmpint(decoded.immediate, ==, 32);

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              linux_stf_spill_f0_r27_imm32_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_STORE);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_SPILL_FILL);
    g_assert_cmpuint(decoded.width, ==, 16);
    g_assert_cmpuint(decoded.freg, ==, 0);
    g_assert_cmpuint(decoded.base, ==, 27);
    g_assert_true(decoded.base_update);
    g_assert_false(decoded.update_from_register);
    g_assert_cmpint(decoded.immediate, ==, 32);

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              linux_lfetch_r32_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_PREFETCH);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_EXTENDED);
    g_assert_cmpuint(decoded.width, ==, 16);
    g_assert_cmpuint(decoded.base, ==, 32);
    g_assert_cmpuint(decoded.memory_class, ==, 0x0b);
    g_assert_false(decoded.base_update);

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              ldfp8_f32_f41_r21_update_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_LOAD_PAIR);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_SIGNIFICAND);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.freg, ==, 32);
    g_assert_cmpuint(decoded.freg2, ==, 41);
    g_assert_cmpuint(decoded.base, ==, 21);
    g_assert_cmpuint(decoded.memory_class, ==, 0);
    g_assert_true(decoded.base_update);
    g_assert_false(decoded.update_from_register);
    g_assert_cmpint(decoded.immediate, ==, 16);

    g_assert_true(ia64_decode_floating_memory(IA64_SLOT_TYPE_M,
                                              ldfpd_f8_f9_r10_raw,
                                              &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_FLOAT_MEM_LOAD_PAIR);
    g_assert_cmpint(decoded.format, ==, IA64_FLOAT_FMT_DOUBLE);
    g_assert_cmpuint(decoded.width, ==, 8);
    g_assert_cmpuint(decoded.freg, ==, 8);
    g_assert_cmpuint(decoded.freg2, ==, 9);
    g_assert_cmpuint(decoded.base, ==, 10);
    g_assert_cmpuint(decoded.memory_class, ==, 0);
    g_assert_false(decoded.base_update);
}

static void assert_fr_natval(const CPUIA64State *env, uint32_t reg)
{
    g_assert_cmphex(env->fr[reg].raw[0], ==, 0);
    g_assert_cmphex(env->fr[reg].raw[1] & 0x1ffff, ==,
                    IA64_TEST_FR_NATVAL_EXPONENT);
    g_assert_cmphex(env->fr[reg].raw[1] >> 17, ==, 0);
}

static void test_floating_speculative_load_defer_writes_natval(void)
{
    CPUIA64State env;
    IA64FloatingMemoryInstruction decoded;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_ED_BIT;
    ia64_write_fr_from_double_bits(&env, 8, UINT64_C(0x3ff0000000000000));
    ia64_write_fr_from_double_bits(&env, 9, UINT64_C(0x4000000000000000));

    memset(&decoded, 0, sizeof(decoded));
    decoded.kind = IA64_FLOAT_MEM_LOAD_PAIR;
    decoded.memory_class = 1;
    decoded.freg = 8;
    decoded.freg2 = 9;

    g_assert_true(ia64_defer_floating_speculative_load(&env, &decoded,
                                                       0xdead0000, false));
    assert_fr_natval(&env, 8);
    assert_fr_natval(&env, 9);
    g_assert_cmphex(env.psr & IA64_PSR_ED_BIT, ==, 0);
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
    ia64_write_gr(&env, 16, 0);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 1ULL << 6);
    g_assert_cmphex(env.pr & 1, ==, 1);

    ia64_write_gr(&env, 16, 1);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 0);
    g_assert_cmphex(env.pr & 1, ==, 1);
}

static uint64_t make_cmp_eq_parallel_p6_p7_r20_r21(uint8_t major)
{
    return ((uint64_t)major << 37) | (1ULL << 33) | (7ULL << 27) |
           (21ULL << 20) | (20ULL << 13) | (6ULL << 6);
}

static void assert_p6_p7(CPUIA64State *env, bool p6, bool p7)
{
    g_assert_cmphex(env->pr & (1ULL << 6), ==, p6 ? 1ULL << 6 : 0);
    g_assert_cmphex(env->pr & (1ULL << 7), ==, p7 ? 1ULL << 7 : 0);
}

static uint64_t make_fclass_raw(uint16_t mask, uint8_t p1, uint8_t p2,
                                uint8_t f2, bool unc, uint8_t qp)
{
    return (5ULL << 37) | ((uint64_t)(mask & 0x3) << 35) |
           ((uint64_t)p2 << 27) |
           ((uint64_t)((mask >> 2) & 0x7f) << 20) |
           ((uint64_t)f2 << 13) | ((uint64_t)unc << 12) |
           ((uint64_t)p1 << 6) | qp;
}

static IA64FloatReg make_test_fr(bool sign, uint32_t exponent,
                                 uint64_t significand)
{
    IA64FloatReg reg = {
        .raw = {
            significand,
            (exponent & 0x1ffff) | ((uint64_t)sign << 17),
        },
    };

    return reg;
}

static void test_floating_compare_relation_decode_and_zero_equality(void)
{
    const uint64_t fcmp_lt_s0_p6_p7_f7_f6_raw = 0x903860e180ULL;
    const uint64_t fcmp_le_s0_p6_p7_f0_f8_raw = 0x8238800180ULL;
    IA64FloatingCompareInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_floating_compare(
                      IA64_SLOT_TYPE_F,
                      fcmp_lt_s0_p6_p7_f7_f6_raw,
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_FLOAT_CMP_LT);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_NORMAL);
    g_assert_cmpuint(decoded.p1, ==, 6);
    g_assert_cmpuint(decoded.p2, ==, 7);
    g_assert_cmpuint(decoded.source2, ==, 7);
    g_assert_cmpuint(decoded.source3, ==, 6);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_fr_from_single_bits(&env, 6, 0x3f800000);
    ia64_write_fr_from_single_bits(&env, 7, 0);
    g_assert_true(ia64_exec_floating_compare(&env, &decoded));
    assert_p6_p7(&env, true, false);

    g_assert_true(ia64_decode_floating_compare(
                      IA64_SLOT_TYPE_F,
                      fcmp_le_s0_p6_p7_f0_f8_raw,
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_FLOAT_CMP_LE);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_NORMAL);
    g_assert_cmpuint(decoded.p1, ==, 6);
    g_assert_cmpuint(decoded.p2, ==, 7);
    g_assert_cmpuint(decoded.source2, ==, 0);
    g_assert_cmpuint(decoded.source3, ==, 8);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_fr_from_single_bits(&env, 8, 0);
    g_assert_true(ia64_exec_floating_compare(&env, &decoded));
    assert_p6_p7(&env, true, false);
}

static void assert_fclass_p6_p7(IA64FloatReg reg, uint16_t mask,
                                bool p6, bool p7)
{
    IA64FloatingClassInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_floating_class(
                      IA64_SLOT_TYPE_F,
                      make_fclass_raw(mask, 6, 7, 8, false, 0),
                      &decoded));

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 6, true);
    ia64_write_pr(&env, 7, true);
    env.fr[8] = reg;

    g_assert_true(ia64_exec_floating_class(&env, &decoded));
    assert_p6_p7(&env, p6, p7);
    g_assert_cmphex(env.pr & 1, ==, 1);
}

static void test_compare_parallel_predicate_completers(void)
{
    IA64CompareInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_compare(
                      IA64_SLOT_TYPE_I,
                      make_cmp_eq_parallel_p6_p7_r20_r21(0xc),
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_AND);
    g_assert_false(decoded.source_immediate);
    g_assert_cmpuint(decoded.p1, ==, 6);
    g_assert_cmpuint(decoded.p2, ==, 7);
    g_assert_cmpuint(decoded.source2, ==, 20);
    g_assert_cmpuint(decoded.source3, ==, 21);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 6, true);
    ia64_write_pr(&env, 7, true);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x1234);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, true, true);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 6, true);
    ia64_write_pr(&env, 7, true);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x5678);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, false, false);

    g_assert_true(ia64_decode_compare(
                      IA64_SLOT_TYPE_I,
                      make_cmp_eq_parallel_p6_p7_r20_r21(0xd),
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_OR);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x1234);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, true, true);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x5678);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, false, false);

    g_assert_true(ia64_decode_compare(
                      IA64_SLOT_TYPE_I,
                      make_cmp_eq_parallel_p6_p7_r20_r21(0xe),
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_OR_ANDCM);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 7, true);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x5678);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, false, true);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 7, true);
    ia64_write_gr(&env, 20, 0x1234);
    ia64_write_gr(&env, 21, 0x1234);
    g_assert_true(ia64_exec_compare(&env, &decoded));
    assert_p6_p7(&env, true, false);
}

static void test_unc_compare_clears_targets_when_false_predicated(void)
{
    const uint64_t linux_strncpy_cmp_ne_unc_p8_p0_r33_r10_raw =
        (0xeULL << 37) | (1ULL << 12) | (8ULL << 27) |
        (10ULL << 20) | (33ULL << 13) | 6ULL;
    IA64CompareInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_compare(
                      IA64_SLOT_TYPE_I,
                      linux_strncpy_cmp_ne_unc_p8_p0_r33_r10_raw,
                      &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_CMP_EQ);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_UNCONDITIONAL);
    g_assert_cmpuint(decoded.p1, ==, 0);
    g_assert_cmpuint(decoded.p2, ==, 8);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 8, true);
    ia64_write_gr(&env, 33, 0x1000);
    ia64_write_gr(&env, 10, 0x2000);

    g_assert_true(ia64_exec_compare_qualified(&env, &decoded, false));
    g_assert_cmphex(env.pr & (1ULL << 8), ==, 0);
    g_assert_cmphex(env.pr & 1, ==, 1);
}

static void test_floating_class_decode_frontier(void)
{
    const uint64_t fclass_p6_p7_f8_0x1c0_raw =
        make_fclass_raw(0x1c0, 6, 7, 8, false, 0);
    IA64FloatingClassInstruction decoded;

    g_assert_cmphex(fclass_p6_p7_f8_0x1c0_raw, ==, 0x0a03f010180ULL);
    g_assert_true(ia64_decode_floating_class(
                      IA64_SLOT_TYPE_F,
                      fclass_p6_p7_f8_0x1c0_raw,
                      &decoded));
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_NORMAL);
    g_assert_cmpuint(decoded.p1, ==, 6);
    g_assert_cmpuint(decoded.p2, ==, 7);
    g_assert_cmpuint(decoded.source2, ==, 8);
    g_assert_cmpuint(decoded.mask, ==, 0x1c0);
    g_assert_false(ia64_decode_floating_class(
                       IA64_SLOT_TYPE_I,
                       fclass_p6_p7_f8_0x1c0_raw,
                       &decoded));
}

static void test_floating_class_nan_and_natval_masks(void)
{
    const IA64FloatReg qnan =
        make_test_fr(false, IA64_TEST_FR_SPECIAL_EXPONENT,
                     IA64_TEST_FR_INTEGER_BIT |
                     IA64_TEST_FR_QUIET_NAN_BIT);
    const IA64FloatReg snan =
        make_test_fr(false, IA64_TEST_FR_SPECIAL_EXPONENT,
                     IA64_TEST_FR_INTEGER_BIT | 1);
    const IA64FloatReg natval =
        make_test_fr(false, IA64_TEST_FR_NATVAL_EXPONENT, 0);

    assert_fclass_p6_p7(qnan, 0x1c0, true, false);
    assert_fclass_p6_p7(snan, 0x1c0, true, false);
    assert_fclass_p6_p7(natval, 0x1c0, true, false);
    assert_fclass_p6_p7(natval, 0x080, false, false);
}

static void test_floating_class_numeric_masks(void)
{
    const IA64FloatReg normal =
        make_test_fr(false, 0xffff, IA64_TEST_FR_INTEGER_BIT);
    const IA64FloatReg negative_zero =
        make_test_fr(true, IA64_TEST_FR_SPECIAL_EXPONENT, 0);
    const IA64FloatReg infinity =
        make_test_fr(false, IA64_TEST_FR_SPECIAL_EXPONENT,
                     IA64_TEST_FR_INTEGER_BIT);
    const IA64FloatReg unnormal =
        make_test_fr(false, 0xffff, IA64_TEST_FR_QUIET_NAN_BIT);

    assert_fclass_p6_p7(normal, 0x011, true, false);
    assert_fclass_p6_p7(normal, 0x012, false, true);
    assert_fclass_p6_p7(negative_zero, 0x006, true, false);
    assert_fclass_p6_p7(infinity, 0x021, true, false);
    assert_fclass_p6_p7(unnormal, 0x009, true, false);
}

static void test_unc_floating_class_clears_targets_when_false_predicated(void)
{
    IA64FloatingClassInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_floating_class(
                      IA64_SLOT_TYPE_F,
                      make_fclass_raw(0x011, 6, 7, 8, true, 8),
                      &decoded));
    g_assert_cmpint(decoded.write_kind, ==,
                    IA64_PRED_WRITE_UNCONDITIONAL);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 6, true);
    ia64_write_pr(&env, 7, true);

    g_assert_true(ia64_exec_floating_class_qualified(
                      &env, &decoded, false));
    assert_p6_p7(&env, false, false);
    g_assert_cmphex(env.pr & 1, ==, 1);
}

static void test_unc_predicate_test_clears_targets_when_false_predicated(void)
{
    const uint64_t tbit_z_unc_p8_p9_r33_0_raw =
        (0x5ULL << 37) | (1ULL << 12) | (9ULL << 27) |
        (33ULL << 20) | (8ULL << 6);
    IA64PredicateTestInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_predicate_test(
                      IA64_SLOT_TYPE_I,
                      tbit_z_unc_p8_p9_r33_0_raw,
                      &decoded));
    g_assert_cmpint(decoded.write_kind, ==,
                    IA64_PRED_WRITE_UNCONDITIONAL);
    g_assert_cmpuint(decoded.p1, ==, 8);
    g_assert_cmpuint(decoded.p2, ==, 9);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 8, true);
    ia64_write_pr(&env, 9, true);

    g_assert_true(ia64_exec_predicate_test_qualified(&env, &decoded, false));
    g_assert_cmphex(env.pr & (1ULL << 8), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 9), ==, 0);
}

static void test_predicate_test_bit_updates_predicates(void)
{
    const uint64_t elilo_tbit_z_p0_p6_r32_0_raw = 0x0a032000000ULL;
    const uint64_t tbit_nz_or_p10_p11_r20_2_raw =
        (0x5ULL << 37) | (1ULL << 33) | (11ULL << 27) |
        (20ULL << 20) | (2ULL << 14) | (1ULL << 12) |
        (10ULL << 6);
    IA64PredicateTestInstruction decoded;
    CPUIA64State env;

    g_assert_true(ia64_decode_predicate_test(
                      IA64_SLOT_TYPE_I, elilo_tbit_z_p0_p6_r32_0_raw,
                      &decoded));
    g_assert_cmpint(decoded.kind, ==, IA64_PRED_TEST_BIT);
    g_assert_cmpint(decoded.relation, ==, IA64_PRED_TEST_ZERO);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_NORMAL);
    g_assert_cmpuint(decoded.p1, ==, 0);
    g_assert_cmpuint(decoded.p2, ==, 6);
    g_assert_cmpuint(decoded.source3, ==, 32);
    g_assert_cmpuint(decoded.immediate, ==, 0);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr |= 1ULL << 6;
    ia64_write_gr(&env, 32, 0x2000300);
    g_assert_true(ia64_exec_predicate_test(&env, &decoded));
    g_assert_cmphex(env.pr & 1, ==, 1);
    g_assert_cmphex(env.pr & (1ULL << 6), ==, 0);

    g_assert_true(ia64_decode_predicate_test(IA64_SLOT_TYPE_I,
                                             tbit_nz_or_p10_p11_r20_2_raw,
                                             &decoded));
    g_assert_cmpint(decoded.relation, ==, IA64_PRED_TEST_NONZERO);
    g_assert_cmpint(decoded.write_kind, ==, IA64_PRED_WRITE_OR);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_gr(&env, 20, 1ULL << 2);
    g_assert_true(ia64_exec_predicate_test(&env, &decoded));
    g_assert_cmphex(env.pr & (1ULL << 10), ==, 1ULL << 10);
    g_assert_cmphex(env.pr & (1ULL << 11), ==, 1ULL << 11);
}

static void test_rotating_predicate_access_maps_through_rrb(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_write_pr(&env, 16, true);
    g_assert_cmphex(env.pr & (1ULL << 16), ==, 1ULL << 16);
    g_assert_true(ia64_read_pr(&env, 16));

    env.rse.rrb_pr = 47;
    ia64_write_pr(&env, 16, true);
    g_assert_cmphex(env.pr & (1ULL << 63), ==, 1ULL << 63);
    g_assert_true(ia64_read_pr(&env, 16));

    ia64_write_pr(&env, 16, false);
    g_assert_cmphex(env.pr & (1ULL << 63), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 16), ==, 1ULL << 16);
    g_assert_true(ia64_read_pr(&env, 17));
}

typedef struct IA64CallFrameRow {
    const char *path;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;
    uint32_t rrb_gr;
    uint32_t rrb_fr;
    uint32_t rrb_pr;
    uint32_t frame_base;
    uint64_t bsp;
} IA64CallFrameRow;

static const IA64CallFrameRow call_frame_rows[] = {
    {
        .path = "/ia64-insn/call-frame/outputs-rotating-caller",
        .sof = 12,
        .sol = 8,
        .sor = 1,
        .rrb_gr = 3,
        .rrb_fr = 77,
        .rrb_pr = 31,
        .frame_base = 100,
        .bsp = 0x1f0,
    },
    {
        .path = "/ia64-insn/call-frame/no-outputs-wrapped-base",
        .sof = 8,
        .sol = 8,
        .sor = 1,
        .rrb_gr = 7,
        .rrb_fr = 0,
        .rrb_pr = 0,
        .frame_base = IA64_STACKED_GR_COUNT - 4,
        .bsp = 0x2f8,
    },
    {
        .path = "/ia64-insn/call-frame/no-locals",
        .sof = 4,
        .sol = 0,
        .sor = 0,
        .rrb_gr = 0,
        .rrb_fr = 95,
        .rrb_pr = 47,
        .frame_base = 250,
        .bsp = 0x400,
    },
};

static void test_call_frame_transition_row(gconstpointer opaque)
{
    const IA64CallFrameRow *row = opaque;
    const uint32_t stacked_count = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
    const uint32_t rotating_count = row->sor * 8;
    const uint32_t output_count = row->sof - row->sol;
    const uint32_t new_frame_base =
        ia64_rse_wrap_slot(row->frame_base + row->sol);
    uint64_t old_value[IA64_GR_COUNT - IA64_STATIC_GR_COUNT];
    bool old_nat[IA64_GR_COUNT - IA64_STATIC_GR_COUNT];
    uint64_t old_br[IA64_BR_COUNT];
    CPUIA64State env;
    IA64IssueGroupState old_issue_group;
    uint64_t old_cfm;
    uint64_t old_psr;
    uint64_t old_pr;
    uint64_t old_ip;
    uint64_t old_ec;
    uint64_t old_lc;
    uint64_t old_static_gr;
    uint64_t old_bspstore;
    uint64_t old_bsp_load;
    uint64_t old_rsc;
    uint64_t old_rnat;
    uint64_t old_loadrs;
    uint64_t old_cr_iva;
    uint64_t expected_bsp;
    uint32_t expected_clean;
    bool old_static_nat;
    bool old_group_start;
    bool old_group_dirty;

    g_assert_cmpuint(row->sol, <=, row->sof);
    g_assert_cmpuint(rotating_count, <=, row->sol);
    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.current_frame_base = row->frame_base;
    old_cfm = ia64_make_cfm(row->sof, row->sol, row->sor) |
              ((uint64_t)row->rrb_gr << 18) |
              ((uint64_t)row->rrb_fr << 25) |
              ((uint64_t)row->rrb_pr << 32) |
              UINT64_C(0x0800000000000000);
    ia64_set_cfm(&env, old_cfm);

    env.rse.bspstore = row->bsp;
    env.rse.bsp = row->bsp;
    env.rse.bsp_load = 0x1550;
    env.rse.rsc = UINT64_C(0x1c);
    env.rse.rnat = UINT64_C(0x123456789abcdef);
    env.rse.loadrs = UINT64_C(0x2340);
    env.rse.clean_count = IA64_STACKED_GR_COUNT - 1;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.ar[IA64_AR_RSC] = env.rse.rsc;
    ia64_rse_sync_rnat(&env);
    expected_clean = 0;

    for (uint32_t logical = 0; logical < stacked_count; logical++) {
        uint32_t reg = IA64_STATIC_GR_COUNT + logical;
        uint32_t offset = logical < rotating_count ?
            (logical + row->rrb_gr) % rotating_count : logical;
        uint32_t slot = ia64_rse_wrap_slot(row->frame_base + offset);

        old_value[logical] = UINT64_C(0xd000000000000000) | logical;
        old_nat[logical] = logical % 5 == 2 || logical == row->sol;
        ia64_write_gr(&env, reg, old_value[logical]);
        ia64_write_gr_nat(&env, reg, old_nat[logical]);
    }

    ia64_write_gr(&env, 5, UINT64_C(0x5555000055550000));
    ia64_write_gr_nat(&env, 5, true);
    env.ar[IA64_AR_EC] = 0x2d;
    env.ar[IA64_AR_LC] = UINT64_C(0x123456789abcdef0);
    env.ar[IA64_AR_PFS] = UINT64_C(0xaaaaaaaa55555555);
    old_psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT | IA64_PSR_DT_BIT |
              (UINT64_C(2) << IA64_PSR_CPL_SHIFT);
    ia64_env_replace_psr(&env, old_psr);
    env.pr = UINT64_C(0xa5a55a5af00f0ff1);
    env.ip = UINT64_C(0x123456789abcde00);
    for (uint32_t reg = 0; reg < IA64_BR_COUNT; reg++) {
        env.br[reg] = UINT64_C(0xb000000000000000) | reg;
    }
    env.cr[IA64_CR_IVA] = UINT64_C(0x4000000000010000);
    env.instruction_group_start = false;
    env.instruction_group_dirty = true;
    env.issue_group.saved_gr[32] = UINT64_C(0x1111222233334444);
    env.issue_group.saved_nat[32] = 1;
    env.issue_group.saved_gr_mask[0] = UINT64_C(1) << 32;
    env.issue_group.saved_pr = UINT64_C(0x55aa55aa55aa55aa);
    env.issue_group.branch_pr_forward_mask = UINT64_C(0x0f0f0f0f0f0f0f0f);
    env.issue_group.saved_br_mask = 0x5a;
    env.issue_group.branch_br_forward_mask = 0xa5;
    env.issue_group.pr_saved = true;
    env.issue_group.typed_active = true;

    ia64_alat_record_gr(&env, 12, 0x1000, 8, true);
    ia64_alat_record_gr(&env, 32, 0x2000, 8, true);
    ia64_alat_record_gr(&env, 127, 0x3000, 8, true);

    old_pr = env.pr;
    old_ip = env.ip;
    old_ec = env.ar[IA64_AR_EC];
    old_lc = env.ar[IA64_AR_LC];
    old_static_gr = ia64_read_gr(&env, 5);
    old_static_nat = ia64_read_gr_nat(&env, 5);
    memcpy(old_br, env.br, sizeof(old_br));
    old_bspstore = env.rse.bspstore;
    old_bsp_load = env.rse.bsp_load;
    old_rsc = env.rse.rsc;
    old_rnat = env.rse.rnat;
    old_loadrs = env.rse.loadrs;
    old_cr_iva = env.cr[IA64_CR_IVA];
    old_group_start = env.instruction_group_start;
    old_group_dirty = env.instruction_group_dirty;
    old_issue_group = env.issue_group;
    expected_bsp = row->sol != 0 ?
        ia64_rse_skip_regs(row->bsp, row->sol) : row->bsp;

    ia64_enter_call_frame(&env);

    g_assert_cmphex(env.ar[IA64_AR_PFS], ==,
                    ia64_make_pfs(old_cfm, old_ec, 2));
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(output_count, 0, 0));
    g_assert_cmpuint(env.rse.sof, ==, output_count);
    g_assert_cmpuint(env.rse.sol, ==, 0);
    g_assert_cmpuint(env.rse.sor, ==, 0);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);
    g_assert_cmpuint(env.rse.current_frame_base, ==, new_frame_base);
    g_assert_cmphex(env.rse.bsp, ==, expected_bsp);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, expected_bsp);
    g_assert_cmpuint(env.rse.clean_count, ==, expected_clean);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, 0);

    for (uint32_t logical = 0; logical < stacked_count; logical++) {
        uint32_t offset = logical < rotating_count ?
            (logical + row->rrb_gr) % rotating_count : logical;
        uint32_t slot = ia64_rse_wrap_slot(row->frame_base + offset);

        g_assert_cmphex(env.rse.stacked_gr[slot], ==, old_value[logical]);
        g_assert_cmpint(ia64_rse_read_physical_nat(&env, slot), ==,
                        old_nat[logical]);
    }
    for (uint32_t output = 0; output < output_count; output++) {
        g_assert_cmphex(ia64_read_gr(&env, IA64_STATIC_GR_COUNT + output),
                        ==, old_value[row->sol + output]);
        g_assert_cmpint(ia64_read_gr_nat(
                            &env, IA64_STATIC_GR_COUNT + output),
                        ==, old_nat[row->sol + output]);
    }

    g_assert_true(env.alat.entries[0].valid);
    g_assert_false(env.alat.entries[1].valid);
    g_assert_false(env.alat.entries[2].valid);
    g_assert_cmphex(env.alat.valid_mask, ==, 1);
    g_assert_cmphex(env.alat.gr_mask[0], ==, UINT64_C(1) << 12);
    g_assert_cmphex(env.alat.gr_mask[1], ==, 0);
    g_assert_cmpuint(env.alat.gr_refcount[12], ==, 1);
    g_assert_cmpuint(env.alat.gr_refcount[32], ==, 0);
    g_assert_cmpuint(env.alat.gr_refcount[127], ==, 0);
    g_assert_cmpuint(env.alat.next, ==, 3);

    g_assert_cmphex(ia64_env_psr(&env), ==, old_psr);
    g_assert_cmphex(env.pr, ==, old_pr);
    g_assert_cmphex(env.ip, ==, old_ip);
    g_assert_cmphex(env.ar[IA64_AR_EC], ==, old_ec);
    g_assert_cmphex(env.ar[IA64_AR_LC], ==, old_lc);
    g_assert_cmphex(ia64_read_gr(&env, 5), ==, old_static_gr);
    g_assert_cmpint(ia64_read_gr_nat(&env, 5), ==, old_static_nat);
    g_assert_cmpint(memcmp(env.br, old_br, sizeof(old_br)), ==, 0);
    g_assert_cmphex(env.rse.bspstore, ==, old_bspstore);
    g_assert_cmphex(env.ar[IA64_AR_BSPSTORE], ==, old_bspstore);
    g_assert_cmphex(env.rse.bsp_load, ==, old_bsp_load);
    g_assert_cmphex(env.rse.rsc, ==, old_rsc);
    g_assert_cmphex(env.ar[IA64_AR_RSC], ==, old_rsc);
    g_assert_cmphex(env.rse.rnat, ==, old_rnat);
    g_assert_cmphex(env.ar[IA64_AR_RNAT], ==, old_rnat);
    g_assert_cmphex(env.rse.loadrs, ==, old_loadrs);
    g_assert_cmphex(env.cr[IA64_CR_IVA], ==, old_cr_iva);
    g_assert_cmpint(env.instruction_group_start, ==, old_group_start);
    g_assert_cmpint(env.instruction_group_dirty, ==, old_group_dirty);
    g_assert_cmpint(memcmp(&env.issue_group, &old_issue_group,
                           sizeof(old_issue_group)), ==, 0);
}

static void test_b_unit_relative_call_updates_link_and_frame(void)
{
    const uint64_t br_call_raw = 0x0a006ba6000ULL;
    CPUIA64State env;
    uint64_t target = 0;
    uint64_t old_cfm;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(6, 4, 0));
    ia64_write_gr(&env, 36, 0xaaaa);
    ia64_write_gr(&env, 37, 0xbbbb);
    ia64_alat_record_gr(&env, 12, 0x1000, 8, true);
    ia64_alat_record_gr(&env, 33, 0x2000, 8, true);
    old_cfm = env.cfm;

    g_assert_true(ia64_slot_is_b_call_relative(IA64_SLOT_TYPE_B,
                                               br_call_raw));
    g_assert_cmpint(ia64_branch_displacement(br_call_raw), ==, 220464);
    g_assert_true(ia64_exec_b_call_relative(&env, br_call_raw, 0x1001030,
                                            &target));

    g_assert_cmphex(target, ==, 0x1036d60);
    g_assert_cmphex(env.br[0], ==, 0x1001040);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, ia64_make_pfs(old_cfm, 0, 0));
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(2, 0, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==, 4);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==, 0xaaaa);
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0xbbbb);
    g_assert_true(env.alat.entries[0].valid);
    g_assert_false(env.alat.entries[1].valid);
    g_assert_cmphex(env.alat.valid_mask, ==, 1);
}

static void test_b_unit_relative_branch(void)
{
    const uint64_t br_cond_raw = 0x0800001a006ULL;
    const uint64_t br_cond_to_fallthrough_raw = 0x08600002006ULL;
    const uint64_t br_cloop_raw = 0x091ffffc140ULL;
    CPUIA64State env;
    uint64_t target = 0;
    bool taken = false;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B,
                                                 br_cond_raw));
    g_assert_cmpint(ia64_branch_displacement(br_cond_raw), ==, 208);
    g_assert_true(ia64_exec_b_branch_relative(&env, br_cond_raw, 0x1036da0,
                                              &target, &taken));

    g_assert_cmphex(target, ==, 0x1036e70);
    g_assert_true(taken);

    target = 0;
    taken = false;
    g_assert_true(ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B,
                                                 br_cond_to_fallthrough_raw));
    g_assert_cmpint(ia64_branch_displacement(br_cond_to_fallthrough_raw),
                    ==, 16);
    g_assert_true(ia64_exec_b_branch_relative(
                  &env, br_cond_to_fallthrough_raw, 0xa0000001003e9700ULL,
                  &target, &taken));

    g_assert_cmphex(target, ==, 0xa0000001003e9710ULL);
    g_assert_true(taken);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ar[IA64_AR_LC] = 2;
    target = 0;
    taken = false;
    g_assert_true(ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B,
                                                 br_cloop_raw));
    g_assert_cmpint(ia64_branch_displacement(br_cloop_raw), ==, -32);
    g_assert_true(ia64_exec_b_branch_relative(&env, br_cloop_raw, 0x100a120,
                                              &target, &taken));
    g_assert_cmphex(target, ==, 0x100a100);
    g_assert_cmphex(env.ar[IA64_AR_LC], ==, 1);
    g_assert_true(taken);

    env.ar[IA64_AR_LC] = 0;
    target = 0;
    taken = true;
    g_assert_true(ia64_exec_b_branch_relative(&env, br_cloop_raw, 0x100a120,
                                              &target, &taken));
    g_assert_cmphex(target, ==, 0x100a130);
    g_assert_false(taken);
}

static void test_b_unit_relative_branch_encoding_gate(void)
{
    const uint64_t major4 = UINT64_C(4) << 37;

    for (unsigned btype = 0; btype < 8; btype++) {
        for (unsigned low6 = 0; low6 < 64; low6++) {
            const uint64_t raw = major4 | ((uint64_t)btype << 6) | low6;
            const bool expected = btype == 0 || btype == 2 || btype == 3 ||
                                  (btype >= 5 && low6 == 0);

            g_assert_cmpint(ia64_slot_is_b_branch_relative(
                                IA64_SLOT_TYPE_B, raw), ==, expected);
            g_assert_false(ia64_slot_is_b_branch_relative(
                               IA64_SLOT_TYPE_I, raw));
        }
    }

    g_assert_false(ia64_slot_is_b_branch_relative(
                       IA64_SLOT_TYPE_B, UINT64_C(3) << 37));
}

static void test_counted_store_loop_decode_from_decompressor(void)
{
    const uint64_t st1_r0_r32_imm1_raw = 0x0ac02000040ULL;
    const uint64_t br_cloop_self_raw = 0x08000000140ULL;
    uint8_t bundle_bytes[IA64_BUNDLE_SIZE];
    IA64DecodedBundle bundle;
    IA64CountedStoreLoop decoded;

    make_bundle(bundle_bytes, 0x10, st1_r0_r32_imm1_raw,
                IA64_INSN_NOP_RAW, br_cloop_self_raw);

    g_assert_true(ia64_decode_bundle(bundle_bytes, &bundle));
    g_assert_true(ia64_decode_counted_store_loop(&bundle, 0x1034880,
                                                 &decoded));
    g_assert_cmpuint(decoded.store.kind, ==, IA64_LDST_IMM_STORE);
    g_assert_cmpuint(decoded.store.width, ==, 1);
    g_assert_cmpuint(decoded.store.source, ==, 0);
    g_assert_cmpuint(decoded.store.base, ==, 32);
    g_assert_true(decoded.store.base_update);
    g_assert_false(decoded.store.update_from_register);
    g_assert_cmpint(decoded.store.immediate, ==, 1);
    g_assert_cmphex(decoded.fallthrough_ip, ==, 0x1034890);

    make_bundle(bundle_bytes, 0x10, st1_r0_r32_imm1_raw | 1,
                IA64_INSN_NOP_RAW, br_cloop_self_raw);
    g_assert_true(ia64_decode_bundle(bundle_bytes, &bundle));
    g_assert_false(ia64_decode_counted_store_loop(&bundle, 0x1034880,
                                                  &decoded));
}

static void test_b_unit_indirect_return(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    /* A caller with SOL=4 leaves four dirty registers below the callee. */
    test_rse_init_complete(&env, 2, 4, 0, 0x1240, 4, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B,
                                                 br_ret_b0_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==, 0);
    g_assert_cmpuint(env.rse.bol, ==, 0);
    g_assert_true(ia64_rse_partitions_valid(&env));
    g_assert_cmpuint(env.rse.sof, ==, 6);
    g_assert_cmpuint(env.rse.sol, ==, 4);
}

static void test_b_unit_indirect_return_wraps_frame_base(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 2, 4,
                           IA64_STACKED_GR_COUNT - 3,
                           0x1240, 4, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;
    /* Physical p5 is caller r37 after the wrapped BOF retreat. */
    env.rse.stacked_gr[2] = 0x2222;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==,
                     IA64_STACKED_GR_COUNT - 3);
    g_assert_cmpuint(env.rse.bol, ==, 0);
    g_assert_cmphex(ia64_read_gr(&env, 37), ==, 0x2222);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_b_unit_indirect_return_invalidates_contiguous_window(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 1, 4, 16, 0x1240, 4, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(4, 4, 0);
    env.br[0] = 0x1001047;
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xfeed000000000000ULL | i;
    }

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmpuint(env.rse.current_frame_base, ==, 16);
    g_assert_cmpuint(env.rse.bol, ==, 0);
    g_assert_cmpint(env.rse.dirty, ==, 0);
    g_assert_cmpint(env.rse.invalid, ==, 92);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==,
                    0xfeed000000000000ULL | 16);
    g_assert_cmphex(ia64_read_gr(&env, 35), ==,
                    0xfeed000000000000ULL | 19);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_b_unit_indirect_return_invalidates_wrapped_window(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 1, 4,
                           IA64_STACKED_GR_COUNT - 8,
                           0x1240, 4, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(4, 4, 0);
    env.br[0] = 0x1001047;
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env.rse.stacked_gr[i] = 0xbeef000000000000ULL | i;
    }

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmpuint(env.rse.current_frame_base, ==,
                     IA64_STACKED_GR_COUNT - 8);
    g_assert_cmpuint(env.rse.bol, ==, 0);
    g_assert_cmpint(env.rse.dirty, ==, 0);
    g_assert_cmpint(env.rse.invalid, ==, 92);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==,
                    0xbeef000000000000ULL |
                    (IA64_STACKED_GR_COUNT - 8));
    g_assert_cmpuint(ia64_rse_physical_to_storage(&env, 95), ==, 87);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_b_unit_indirect_return_retreats_clean_bsp(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    /* No resident caller registers: return creates an incomplete frame. */
    test_rse_init_complete(&env, 2, 4, 0, 0x1240, 0, 0);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.rse.bsp, ==, ia64_rse_skip_regs(0x1240, -4));
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, env.rse.bsp);
    g_assert_cmphex(env.rse.bspstore, ==, 0x1240);
    g_assert_cmpint(env.rse.dirty, ==, -4);
    g_assert_true(env.rse.cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_b_unit_indirect_return_clamps_clean_boundary(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    /* The caller can be restored from four resident clean registers. */
    test_rse_init_complete(&env, 2, 4, 0, 0x1240, 0, 4);
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 0);
    g_assert_cmpuint(env.rse.clean_count, ==, 0);
    g_assert_cmpint(env.rse.clean, ==, 0);
    g_assert_cmphex(env.rse.bspstore, ==, env.rse.bsp);
    g_assert_false(env.rse.cfle);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_b_unit_return_from_interruption(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t ipsr = ia64_psr_with_ri(0x001010084a2008ULL, 2);
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 0, 8, 0, 0x1240, 8, 0);
    env.cr[IA64_CR_IPSR] = ipsr;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    env.cr[IA64_CR_IFS] = ia64_make_cfm(8, 3, 0) | IA64_IFS_VALID_BIT;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B, rfi_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x47f7e40,
                                               &target));
    g_assert_cmphex(target, ==, 0xa0000001007f7e50ULL);
    g_assert_cmphex(env.psr, ==, ipsr);
    g_assert_cmpuint(ia64_psr_ri(env.psr), ==, 2);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(8, 3, 0));
}

static void test_rfi_staged_control_registers(void)
{
    const uint64_t mov_cr_ipsr_r16_raw =
        (1ULL << 37) | (0x2cULL << 27) | (16ULL << 20) | (16ULL << 13);
    const uint64_t mov_cr_iip_r17_raw =
        (1ULL << 37) | (0x2cULL << 27) | (19ULL << 20) | (17ULL << 13);
    const uint64_t mov_cr_ifs_r18_raw =
        (1ULL << 37) | (0x2cULL << 27) | (23ULL << 20) | (18ULL << 13);
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t old_cfm = ia64_make_cfm(2, 1, 0);
    const uint64_t new_cfm = ia64_make_cfm(8, 3, 0);
    const uint64_t new_ifs = new_cfm | IA64_IFS_VALID_BIT;
    CPUIA64State env;
    uint64_t target = 0;

    /* The handler allocated two registers above the covered frame. */
    test_rse_init_complete(&env, 2, 8, 0, 0x1240, 8, 0);
    env.ip = 0x47f7e40;
    env.psr = 0;
    ia64_set_cfm(&env, old_cfm);
    ia64_write_gr(&env, 16, 0x001010084a2008ULL);
    ia64_write_gr(&env, 17, 0xa0000001007f7e57ULL);
    ia64_write_gr(&env, 18, new_ifs);

    g_assert_true(ia64_exec_m_mov_to_control(&env, mov_cr_ipsr_r16_raw));
    g_assert_true(ia64_exec_m_mov_to_control(&env, mov_cr_iip_r17_raw));
    g_assert_true(ia64_exec_m_mov_to_control(&env, mov_cr_ifs_r18_raw));
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, 0x001010084a2008ULL);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, 0xa0000001007f7e57ULL);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, new_ifs);
    g_assert_cmphex(env.ip, ==, 0x47f7e40);
    g_assert_cmphex(env.psr, ==, 0);
    g_assert_cmphex(env.cfm, ==, old_cfm);

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, env.ip,
                                              &target));
    g_assert_cmphex(target, ==, 0xa0000001007f7e50ULL);
    g_assert_cmphex(env.psr, ==, 0x001010084a2008ULL);
    g_assert_cmphex(env.cfm, ==, new_cfm);
}

static void test_rfi_uncovers_valid_interruption_frame(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t interrupted_cfm = ia64_make_cfm(8, 3, 0);
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 0, 8, 11, 0x1240, 8, 0);
    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    env.cr[IA64_CR_IFS] = interrupted_cfm | IA64_IFS_VALID_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x47f7e40,
                                              &target));
    g_assert_cmphex(env.cfm, ==, interrupted_cfm);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 11);
}

static void test_rfi_uncovers_valid_frame_clamps_clean_boundary(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t interrupted_cfm = ia64_make_cfm(8, 3, 0);
    CPUIA64State env;
    uint64_t target = 0;

    test_rse_init_complete(&env, 0, 8, 11, 0x1240, 0, 8);
    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    env.cr[IA64_CR_IFS] = interrupted_cfm | IA64_IFS_VALID_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x47f7e40,
                                              &target));
    g_assert_cmphex(target, ==, 0xa0000001007f7e50ULL);
    g_assert_cmphex(env.cfm, ==, interrupted_cfm);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 11);
    g_assert_cmpuint(env.rse.clean_count, ==, 0);
    g_assert_cmpint(env.rse.clean, ==, 0);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_rfi_ignores_invalid_ifs(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t handler_cfm = ia64_make_cfm(2, 1, 0);
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    ia64_set_cfm(&env, handler_cfm);
    env.cr[IA64_CR_IFS] = ia64_make_cfm(8, 3, 0);

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x47f7e40,
                                              &target));
    g_assert_cmphex(target, ==, 0xa0000001007f7e50ULL);
    g_assert_cmphex(env.psr, ==, 0x001010084a2008ULL);
    g_assert_cmphex(env.cfm, ==, handler_cfm);
}

static void test_b_unit_system_branch_extensions(void)
{
    const uint64_t cover_raw = 0x02ULL << 27;
    const uint64_t clrrrb_raw = 0x04ULL << 27;
    const uint64_t clrrrb_pr_raw = 0x05ULL << 27;
    const uint64_t bsw_0_raw = 0x0cULL << 27;
    const uint64_t bsw_1_raw = 0x0dULL << 27;
    const uint64_t epc_raw = 0x10ULL << 27;
    const uint64_t cfm_with_rrb = ia64_make_cfm(8, 3, 0) |
        (5ULL << 18) | (6ULL << 25) | (7ULL << 32);
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, cfm_with_rrb);
    env.rse.current_frame_base = 11;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B,
                                                 cover_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, cover_raw, 0x2000,
                                              &target));
    g_assert_cmphex(target, ==, 0x2010);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==,
                    cfm_with_rrb | IA64_IFS_VALID_BIT);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 19);

    ia64_set_cfm(&env, cfm_with_rrb);
    g_assert_true(ia64_exec_b_indirect_branch(&env, clrrrb_raw, 0x2010,
                                              &target));
    g_assert_cmphex(target, ==, 0x2020);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);

    ia64_set_cfm(&env, cfm_with_rrb);
    g_assert_true(ia64_exec_b_indirect_branch(&env, clrrrb_pr_raw, 0x2020,
                                              &target));
    g_assert_cmphex(target, ==, 0x2030);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 5);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 6);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);

    env.psr = 0;
    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x2030,
                                              &target));
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, IA64_PSR_BN_BIT);
    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_0_raw, 0x2040,
                                              &target));
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, 0);

    env.psr = UINT64_C(3) << 32;
    g_assert_true(ia64_exec_b_indirect_branch(&env, epc_raw, 0x2050,
                                              &target));
    g_assert_cmphex(env.psr & (UINT64_C(3) << 32), ==, 0);
    g_assert_cmphex(target, ==, 0x2060);
}

static void test_cover_sets_ifs_only_when_interruption_collection_off(void)
{
    const uint64_t cover_raw = 0x02ULL << 27;
    const uint64_t cfm = ia64_make_cfm(8, 3, 0);
    const uint64_t saved_ifs = 0x8000000000003333ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, cfm);
    env.cr[IA64_CR_IFS] = saved_ifs;
    env.psr = 0;
    g_assert_true(ia64_exec_b_indirect_branch(&env, cover_raw, 0x3000,
                                              &target));
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, cfm | IA64_IFS_VALID_BIT);
    g_assert_cmphex(env.cfm, ==, 0);

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, cfm);
    env.cr[IA64_CR_IFS] = saved_ifs;
    env.psr = IA64_PSR_IC_BIT;
    g_assert_true(ia64_exec_b_indirect_branch(&env, cover_raw, 0x3010,
                                              &target));
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);
    g_assert_cmphex(env.cfm, ==, 0);
}

static void test_b_unit_indirect_call_updates_link_and_frame(void)
{
    const uint64_t br_call_b0_b6_raw = 0x0210000d000ULL;
    CPUIA64State env;
    uint64_t target = 0;
    uint64_t old_cfm;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(9, 6, 0));
    ia64_write_gr(&env, 38, 0x1111);
    ia64_write_gr(&env, 39, 0x2222);
    env.br[6] = 0x10203047;
    old_cfm = env.cfm;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B,
                                                 br_call_b0_b6_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, br_call_b0_b6_raw,
                                              0x102efd0, &target));

    g_assert_cmphex(target, ==, 0x10203040);
    g_assert_cmphex(env.br[0], ==, 0x102efe0);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, ia64_make_pfs(old_cfm, 0, 0));
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(3, 0, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==, 6);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==, 0x1111);
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0x2222);
}

static void test_b_unit_predict_or_nop(void)
{
    const uint64_t brp_raw = 0x04000000000ULL;

    g_assert_true(ia64_slot_is_b_predict_or_nop(IA64_SLOT_TYPE_B, brp_raw));
    g_assert_false(ia64_slot_is_b_predict_or_nop(IA64_SLOT_TYPE_I, brp_raw));
}

static void test_b_unit_break_decode(void)
{
    const uint64_t centos_break_b_7_raw = 0x000000001c0ULL;
    const uint64_t break_b_high_immediate_raw =
        (1ULL << 36) | (0x34567ULL << 6);

    g_assert_true(ia64_slot_is_b_break(IA64_SLOT_TYPE_B,
                                       centos_break_b_7_raw));
    g_assert_false(ia64_slot_is_b_break(IA64_SLOT_TYPE_I,
                                        centos_break_b_7_raw));
    g_assert_cmphex(ia64_b_break_immediate(centos_break_b_7_raw), ==, 7);
    g_assert_true(ia64_slot_is_b_break(IA64_SLOT_TYPE_B,
                                       break_b_high_immediate_raw));
    g_assert_cmphex(ia64_b_break_immediate(break_b_high_immediate_raw),
                    ==, 0x134567);
}

static void test_reserved_template_message(void)
{
    CPUIA64State env;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64InsnReport report;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x3000;
    make_bundle(bundle, 0x06,
                IA64_INSN_NOP_RAW,
                IA64_INSN_NOP_RAW,
                IA64_INSN_NOP_RAW);

    g_assert_cmpint(ia64_insn_exec_bundle(&env, bundle, &report), ==,
                    IA64_INSN_RESERVED_TEMPLATE);
    g_assert_cmphex(env.ip, ==, 0x3000);
    g_assert_cmpint(report.failed_slot, ==, -1);
    g_assert_nonnull(strstr(report.message,
                           "reserved IA-64 template 0x06"));
}

static void test_physical_region_alias_translation(void)
{
    CPUIA64State env;
    IA64TranslateResult result;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_translate_address(&env, 0xe000000001234000,
                                          MMU_DATA_LOAD, 0, false, &result));
    g_assert_cmphex(result.paddr, ==, 0x1234000);
    g_assert_cmpuint(result.region, ==, 7);
    g_assert_false(result.identity);
}

static void test_psr_ic_inflight_state_machine(void)
{
    const uint64_t ssm_ic_raw = UINT64_C(0x00030080000);
    const uint64_t rsm_ic_raw = UINT64_C(0x00038080000);
    const uint64_t srlz_d_raw = UINT64_C(0x00180000000);
    const uint64_t srlz_i_raw = UINT64_C(0x00188000000);
    const uint64_t sync_i_raw = UINT64_C(0x00198000000);
    const uint64_t mov_psr_l_r10_raw = UINT64_C(0x02168014000);
    const uint64_t rfi_raw = UINT64_C(0x00040000000);
    CPUIA64State env;
    uint64_t target_ip = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_false(env.psr_ic_inflight);

    g_assert_true(ia64_exec_m_processor_mask(&env, ssm_ic_raw));
    g_assert_true((ia64_env_psr(&env) & IA64_PSR_IC_BIT) != 0);
    g_assert_true(env.psr_ic_inflight);

    g_assert_true(ia64_slot_is_m_serialization(IA64_SLOT_TYPE_M, srlz_i_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M, srlz_i_raw));
    g_assert_true(ia64_exec_m_serialization(&env, srlz_i_raw));
    g_assert_false(env.psr_ic_inflight);

    /* A same-value guest write does not manufacture a transition. */
    g_assert_true(ia64_exec_m_processor_mask(&env, ssm_ic_raw));
    g_assert_false(env.psr_ic_inflight);

    g_assert_true(ia64_exec_m_processor_mask(&env, rsm_ic_raw));
    g_assert_false((ia64_env_psr(&env) & IA64_PSR_IC_BIT) != 0);
    g_assert_true(env.psr_ic_inflight);
    g_assert_true(ia64_exec_m_serialization(&env, srlz_d_raw));
    g_assert_false(env.psr_ic_inflight);
    g_assert_true(ia64_exec_m_processor_mask(&env, rsm_ic_raw));
    g_assert_false(env.psr_ic_inflight);

    g_assert_true(ia64_exec_m_processor_mask(&env, ssm_ic_raw));
    g_assert_true(env.psr_ic_inflight);
    g_assert_true(ia64_slot_is_m_serialization(IA64_SLOT_TYPE_M, sync_i_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M, sync_i_raw));
    g_assert_true(ia64_exec_m_serialization(&env, sync_i_raw));
    g_assert_true(env.psr_ic_inflight);

    g_assert_true(ia64_exec_m_serialization(&env, srlz_d_raw));
    ia64_write_gr(&env, 10, 0);
    g_assert_true(ia64_exec_m_mov_to_processor_status(&env,
                                                     mov_psr_l_r10_raw));
    g_assert_false((ia64_env_psr(&env) & IA64_PSR_IC_BIT) != 0);
    g_assert_true(env.psr_ic_inflight);
    g_assert_true(ia64_exec_m_serialization(&env, srlz_i_raw));
    g_assert_false(env.psr_ic_inflight);
    g_assert_true(ia64_exec_m_mov_to_processor_status(&env,
                                                     mov_psr_l_r10_raw));
    g_assert_false(env.psr_ic_inflight);
    ia64_write_gr(&env, 10, IA64_PSR_IC_BIT);
    g_assert_true(ia64_exec_m_mov_to_processor_status(&env,
                                                     mov_psr_l_r10_raw));
    g_assert_true(env.psr_ic_inflight);

    env.cr[IA64_CR_IIP] = 0x2000;
    env.cr[IA64_CR_IPSR] = IA64_PSR_IC_BIT;
    env.cr[IA64_CR_IFS] = 0;
    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x1000,
                                              &target_ip));
    g_assert_cmphex(target_ip, ==, 0x2000);
    g_assert_false(env.psr_ic_inflight);

    env.psr_ic_inflight = true;
    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_false(env.psr_ic_inflight);
}

static uint64_t m_processor_mask_raw(uint8_t x4, uint32_t mask)
{
    return ((uint64_t)x4 << 27) |
           ((uint64_t)(mask & 0x7f) << 6) |
           ((uint64_t)((mask >> 7) & 0x7f) << 13) |
           ((uint64_t)((mask >> 14) & 0x7f) << 20) |
           ((uint64_t)((mask >> 21) & 0x3) << 31) |
           ((uint64_t)((mask >> 23) & 0x1) << 36);
}

static void test_m_processor_mask_reserved_fields(void)
{
    static const struct {
        uint8_t x4;
        uint32_t allowed;
    } rows[] = {
        { 4, UINT32_C(0x3e) },
        { 5, UINT32_C(0x3e) },
        { 6, UINT32_C(0x3e) | (UINT32_C(0x7) << 13) |
             (UINT32_C(0x7f) << 17) },
        { 7, UINT32_C(0x3e) | (UINT32_C(0x7) << 13) |
             (UINT32_C(0x7f) << 17) },
    };

    for (unsigned row = 0; row < ARRAY_SIZE(rows); row++) {
        for (unsigned bit = 0; bit < 24; bit++) {
            CPUIA64State env;
            uint64_t raw = m_processor_mask_raw(rows[row].x4,
                                                UINT32_C(1) << bit);
            uint64_t old_psr;

            if (rows[row].allowed & (UINT32_C(1) << bit)) {
                g_assert_true(ia64_slot_is_m_processor_mask(
                    IA64_SLOT_TYPE_M, raw));
                continue;
            }

            ia64_cpu_reset_synthetic_itanium2(&env);
            ia64_env_set_psr(&env, IA64_PSR_IC_BIT);
            env.psr_ic_inflight = true;
            old_psr = ia64_env_psr(&env);

            g_assert_false(ia64_slot_is_m_processor_mask(
                IA64_SLOT_TYPE_M, raw));
            g_assert_false(ia64_exec_m_processor_mask(&env, raw));
            g_assert_cmphex(ia64_env_psr(&env), ==, old_psr);
            g_assert_true(env.psr_ic_inflight);
        }
    }
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
            CPUIA64State env;
            uint64_t raw = serialization[i] |
                           (UINT64_C(1) << reserved_bits[j]);
            uint64_t old_psr;

            ia64_cpu_reset_synthetic_itanium2(&env);
            env.psr_ic_inflight = true;
            old_psr = ia64_env_psr(&env);

            g_assert_false(ia64_slot_is_m_serialization(
                IA64_SLOT_TYPE_M, raw));
            g_assert_false(ia64_slot_is_m_system_noop(
                IA64_SLOT_TYPE_M, raw));
            g_assert_false(ia64_exec_m_serialization(&env, raw));
            g_assert_true(env.psr_ic_inflight);
            g_assert_cmphex(ia64_env_psr(&env), ==, old_psr);
        }
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-insn/reset", test_reset);
    g_test_add_func("/ia64-insn/last-successful-bundle-pre-ic",
                    test_last_successful_bundle_uses_pre_instruction_ic);
    g_test_add_func("/ia64-insn/banked-static-gr",
                    test_banked_static_general_registers);
    g_test_add_func("/ia64-insn/pal-calling-convention-table",
                    test_pal_calling_convention_table);
    g_test_add_func("/ia64-insn/banked-bsw-visibility",
                    test_banked_register_switch_via_bsw);
    g_test_add_func("/ia64-insn/syscall-break-user-to-kernel",
                    test_syscall_break_user_to_kernel_transition);
    g_test_add_func("/ia64-insn/platform-break-handler-survives-reset",
                    test_platform_break_handler_survives_reset);
    g_test_add_func("/ia64-insn/syscall-rfi-kernel-to-user",
                    test_syscall_return_rfi_kernel_to_user_transition);
    g_test_add_func("/ia64-insn/epc-user-to-kernel",
                    test_epc_clears_user_cpl_for_kernel_entry);
    g_test_add_func("/ia64-insn/epc-gate-return-restores-pfs-privilege",
                    test_epc_gate_return_restores_pfs_privilege);
    g_test_add_func("/ia64-insn/bundle-fetch-decode",
                    test_bundle_fetch_decode);
    g_test_add_func("/ia64-insn/ip-advances-for-nop-bundle",
                    test_ip_advances_for_nop_bundle);
    g_test_add_func("/ia64-insn/unsupported-instruction-message",
                    test_unsupported_instruction_message);
    g_test_add_func("/ia64-insn/m34-alloc-updates-frame-state",
                    test_m34_alloc_updates_frame_state);
    g_test_add_func("/ia64-insn/frame-state-preserves-ifs",
                    test_frame_state_updates_preserve_interruption_frame_state);
    g_test_add_func("/ia64-insn/rse-backing-store-address-helpers",
                    test_rse_backing_store_address_helpers);
    g_test_add_func("/ia64-insn/rse-stacked-write-marks-clean-register-dirty",
                    test_rse_stacked_write_marks_clean_register_dirty);
    g_test_add_func("/ia64-insn/rse-bspstore-write-preserves-dirty-boundary",
                    test_rse_bspstore_write_preserves_dirty_boundary);
    g_test_add_func("/ia64-insn/rse-rsc-privilege-clamp-matrix",
                    test_rse_rsc_privilege_clamp_matrix);
    g_test_add_func("/ia64-insn/rse-loadrs-dirty-partition-bspstore-switch",
                    test_rse_loadrs_dirty_partition_survives_bspstore_switch);
    g_test_add_func("/ia64-insn/rse-loadrs-preserves-rfi-frame",
                    test_rse_loadrs_preserves_dirty_frame_uncovered_by_rfi);
    g_test_add_func("/ia64-insn/rse-loadrs-reads-clean-prefix-only",
                    test_rse_loadrs_reads_clean_prefix_only);
    g_test_add_func("/ia64-insn/rse-load-restores-rnat-collection",
                    test_rse_load_restores_nat_from_rnat_collection);
    g_test_add_func("/ia64-insn/rse-restored-frame-uses-bsp-load",
                    test_rse_restored_frame_uses_bsp_load);
    g_test_add_func("/ia64-insn/rse-reconstructs-clean-partition-after-load",
                    test_rse_reconstructs_clean_partition_after_load);
    g_test_add_func("/ia64-insn/rse-alloc-spill-keeps-physical-bound",
                    test_rse_alloc_spill_keeps_physical_bound);
    g_test_add_func("/ia64-insn/rse-alloc-spill-noop-paths",
                    test_rse_alloc_spill_noop_paths);
    for (uint32_t i = 0; i < G_N_ELEMENTS(pristine_return_rows); i++) {
        g_test_add_data_func(pristine_return_rows[i].path,
                             &pristine_return_rows[i],
                             test_rse_pristine_return_row);
    }
    g_test_add_func("/ia64-insn/rse-return-partition-rows",
                    test_rse_return_partition_rows);
    g_test_add_func("/ia64-insn/rse-return-cpl-demotion-matrix",
                    test_rse_return_cpl_demotion_matrix);
    for (uint32_t i = 0; i < G_N_ELEMENTS(bad_pfs_return_rows); i++) {
        g_test_add_data_func(bad_pfs_return_rows[i].path,
                             &bad_pfs_return_rows[i],
                             test_rse_bad_pfs_return_row);
    }
    g_test_add_func("/ia64-insn/rse-mandatory-load-register-fault-resume",
                    test_rse_fault_resume_register_rows);
    g_test_add_func("/ia64-insn/rse-mandatory-load-rnat-fault-resume-wrap",
                    test_rse_fault_resume_rnat_rows);
    g_test_add_func("/ia64-insn/rse-mandatory-load-interrupt-boundaries",
                    test_rse_mandatory_load_interruption_boundaries);
    g_test_add_func("/ia64-insn/rse-incomplete-partition-validation",
                    test_rse_incomplete_partition_validation);
    g_test_add_func("/ia64-insn/rse-load-partition-physical-window-cap",
                    test_rse_load_partition_caps_at_physical_window);
    g_test_add_func("/ia64-insn/i-unit-mov-ip-and-nop",
                    test_i_unit_mov_ip_and_nop);
    g_test_add_func("/ia64-insn/performance-hint-family",
                    test_performance_hint_family);
    g_test_add_func("/ia64-insn/i-unit-break-delivers-interruption-state",
                    test_i_unit_break_delivers_interruption_state);
    g_test_add_func("/ia64-insn/i-unit-break-ic-clear-preserves-state",
                    test_i_unit_break_with_ic_clear_preserves_collection_state);
    g_test_add_func("/ia64-insn/interruption-delivery-preserves-translation-state",
                    test_interruption_delivery_preserves_translation_state);
    g_test_add_func("/ia64-insn/i-unit-mov-from-predicate",
                    test_i_unit_mov_from_predicate);
    g_test_add_func("/ia64-insn/i-unit-mov-to-predicate-mask",
                    test_i_unit_mov_to_predicate_mask);
    g_test_add_func("/ia64-insn/i-unit-mov-to-predicate-mask-fsys-clock",
                    test_i_unit_mov_to_predicate_mask_fsys_clock);
    g_test_add_func("/ia64-insn/i-unit-mov-to-predicate-mask-high-restore",
                    test_i_unit_mov_to_predicate_mask_high_restore);
    g_test_add_func("/ia64-insn/i-unit-mov-to-branch",
                    test_i_unit_mov_to_branch);
    g_test_add_func("/ia64-insn/application-register-moves",
                    test_application_register_moves);
    g_test_add_func("/ia64-insn/rnat-application-register-mask",
                    test_rnat_application_register_masks_only_slot63);
    g_test_add_func("/ia64-insn/m-unit-system-memory-management",
                    test_m_unit_system_memory_management);
    g_test_add_func("/ia64-insn/psr-ic-inflight-state-machine",
                    test_psr_ic_inflight_state_machine);
    g_test_add_func("/ia64-insn/m-processor-mask-reserved-fields",
                    test_m_processor_mask_reserved_fields);
    g_test_add_func("/ia64-insn/m24-serialization-reserved-fields",
                    test_m24_serialization_reserved_fields);
    g_test_add_func("/ia64-insn/translation-access-dirty-bits",
                    test_translation_access_dirty_bits);
    g_test_add_func("/ia64-insn/interrupt-control-registers",
                    test_interrupt_control_registers);
    g_test_add_func("/ia64-insn/timer-compare-rearms-on-itm",
                    test_timer_compare_rearms_only_on_itm_programming);
    g_test_add_func("/ia64-insn/itc-warp-forward-only",
                    test_itc_warp_moves_forward_only);
    g_test_add_func("/ia64-insn/interrupt-unmask-pending",
                    test_interrupt_unmask_exposes_pending_external_interrupt);
    g_test_add_func("/ia64-insn/external-interrupt-delivery-masks",
                    test_external_interrupt_delivery_masks);
    g_test_add_func("/ia64-insn/interrupt-reconcile-invalid-active",
                    test_interrupt_reconcile_drops_invalid_active_vector);
    g_test_add_func("/ia64-insn/lx-movl-reconstructs-immediate",
                    test_lx_movl_reconstructs_immediate);
    g_test_add_func("/ia64-insn/lx-nop-hint-pair",
                    test_lx_nop_hint_pair);
    g_test_add_func("/ia64-insn/alu-add-register-form",
                    test_alu_add_register_form);
    g_test_add_func("/ia64-insn/alu-sub-register-form",
                    test_alu_sub_register_form);
    g_test_add_func("/ia64-insn/alu-logic-addp4-and-shladd",
                    test_alu_logic_addp4_and_shladd);
    g_test_add_func("/ia64-insn/packed-alu-a9-a10-family",
                    test_packed_alu_a9_a10_family);
    g_test_add_func("/ia64-insn/i-unit-mux-permutations",
                    test_i_unit_mux_permutations);
    g_test_add_func("/ia64-insn/i-unit-packed-i2-frontier-mix4r",
                    test_i_unit_packed_i2_frontier_mix4r);
    g_test_add_func("/ia64-insn/i-unit-packed-i2-operations",
                    test_i_unit_packed_i2_operations);
    g_test_add_func("/ia64-insn/i-unit-multiply-shift-family",
                    test_i_unit_multiply_shift_family);
    g_test_add_func("/ia64-insn/i-unit-variable-shifts",
                    test_i_unit_variable_shifts);
    g_test_add_func("/ia64-insn/i-unit-bit-count",
                    test_i_unit_bit_count);
    g_test_add_func("/ia64-insn/addl-immediate-form",
                    test_addl_immediate_form);
    g_test_add_func("/ia64-insn/m-unit-setf-significand",
                    test_m_unit_setf_significand);
    g_test_add_func("/ia64-insn/m-unit-setf-exp-frontier",
                    test_m_unit_setf_exp_frontier);
    g_test_add_func("/ia64-insn/m-unit-setf-single-double",
                    test_m_unit_setf_single_and_double);
    g_test_add_func("/ia64-insn/m-unit-setf-nat-source",
                    test_m_unit_setf_nat_source);
    g_test_add_func("/ia64-insn/m-unit-getf-significand",
                    test_m_unit_getf_significand);
    g_test_add_func("/ia64-insn/m-unit-getf-memory-forms",
                    test_m_unit_getf_all_memory_forms);
    g_test_add_func("/ia64-insn/disabled-fp-register-fault",
                    test_disabled_fp_register_fault);
    g_test_add_func("/ia64-insn/fp-write-sets-modified-bits",
                    test_fp_write_sets_modified_bits);
    g_test_add_func("/ia64-insn/floating-ieee-memory-bit-conversions",
                    test_floating_ieee_memory_bit_conversions);
    g_test_add_func("/ia64-insn/floating-spill-format-constants",
                    test_floating_spill_format_constants);
    g_test_add_func("/ia64-insn/extract-zero-extends-bitfield",
                    test_extract_zero_extends_bitfield);
    g_test_add_func("/ia64-insn/deposit-zero-elilo-frontier",
                    test_deposit_zero_from_elilo_frontier);
    g_test_add_func("/ia64-insn/deposit-immediate-masks-field",
                    test_deposit_immediate_masks_inserted_field);
    g_test_add_func("/ia64-insn/shift-right-pair-elilo-frontier",
                    test_shift_right_pair_from_elilo_frontier);
    g_test_add_func("/ia64-insn/integer-extend-zero-extends-byte",
                    test_integer_extend_zero_extends_byte);
    g_test_add_func("/ia64-insn/f-unit-xma-low",
                    test_f_unit_xma_low);
    g_test_add_func("/ia64-insn/f-unit-multiply-add-operand-order",
                    test_f_unit_multiply_add_uses_ia64_operand_order);
    g_test_add_func("/ia64-insn/f-unit-fma-double-completer-rounding",
                    test_f_unit_fma_double_completer_rounds_result);
    g_test_add_func("/ia64-insn/f-unit-fma-single-completer-rounding",
                    test_f_unit_fma_single_completer_rounds_result);
    g_test_add_func("/ia64-insn/f-unit-reciprocal-approx",
                    test_f_unit_reciprocal_approx_sets_predicate);
    g_test_add_func("/ia64-insn/f-unit-unsigned-mod-helper-precision",
                    test_f_unit_unsigned_mod_helper_keeps_64bit_precision);
    g_test_add_func("/ia64-insn/f-unit-misc-unsigned-trunc-conversion",
                    test_f_unit_misc_unsigned_trunc_conversion);
    g_test_add_func("/ia64-insn/f-unit-misc-fsxt-r-frontier",
                    test_f_unit_misc_fsxt_r_frontier);
    g_test_add_func("/ia64-insn/f-unit-misc-packed-data-family",
                    test_f_unit_misc_packed_data_family);
    g_test_add_func("/ia64-insn/f-unit-misc-minmax-family",
                    test_f_unit_misc_minmax_family);
    g_test_add_func("/ia64-insn/f-unit-clear-status-flags",
                    test_f_unit_clear_status_flags);
    g_test_add_func("/ia64-insn/f-unit-misc-noop",
                    test_f_unit_misc_noop);
    g_test_add_func("/ia64-insn/ldst-immediate-decode",
                    test_ldst_immediate_decode);
    g_test_add_func("/ia64-insn/gr-write-clears-nat",
                    test_general_register_write_clears_nat);
    g_test_add_func("/ia64-insn/ldst-base-update-helper",
                    test_ldst_base_update_helper);
    g_test_add_func("/ia64-insn/stacked-gr-nat-physical-slot",
                    test_stacked_register_nat_uses_physical_slot);
    g_test_add_func("/ia64-insn/stacked-gr-nat-high-slot-bitmap",
                    test_stacked_register_nat_high_slot_uses_rse_bitmap);
    g_test_add_func("/ia64-insn/rse-logical-sync-sof-zero-all-names",
                    test_rse_logical_sync_covers_all_names_at_sof_zero);
    g_test_add_func("/ia64-insn/rse-logical-rotation-sync",
                    test_rse_rotation_publishes_then_rebuilds_logical_names);
    for (uint32_t i = 0; i < G_N_ELEMENTS(modulo_rotation_rows); i++) {
        g_test_add_data_func(modulo_rotation_rows[i].path,
                             &modulo_rotation_rows[i],
                             test_modulo_rotation_row);
    }
    g_test_add_func("/ia64-insn/modulo-rotation/alat-range",
                    test_modulo_rotation_invalidates_only_rotating_alat);
    g_test_add_func("/ia64-insn/modulo-rotation/inactive-overlay",
                    test_modulo_rotation_leaves_inactive_overlay_untouched);
    g_test_add_func("/ia64-insn/loop-branch-legality",
                    test_loop_branch_slot_and_b2_legality);
    g_test_add_func("/ia64-insn/alat-check-load-helpers",
                    test_alat_check_load_helpers);
    g_test_add_func("/ia64-insn/m-unit-atomic-decode",
                    test_m_unit_atomic_decode);
    g_test_add_func("/ia64-insn/floating-memory-decode",
                    test_floating_memory_decode);
    g_test_add_func("/ia64-insn/floating-speculative-load-defer-natval",
                    test_floating_speculative_load_defer_writes_natval);
    g_test_add_func("/ia64-insn/compare-immediate-predicate-write",
                    test_compare_immediate_updates_predicates);
    g_test_add_func("/ia64-insn/compare-parallel-predicate-write",
                    test_compare_parallel_predicate_completers);
    g_test_add_func("/ia64-insn/unc-compare-false-predicate-clear",
                    test_unc_compare_clears_targets_when_false_predicated);
    g_test_add_func("/ia64-insn/floating-compare-relation-decode",
                    test_floating_compare_relation_decode_and_zero_equality);
    g_test_add_func("/ia64-insn/floating-class-decode-frontier",
                    test_floating_class_decode_frontier);
    g_test_add_func("/ia64-insn/floating-class-nan-natval-masks",
                    test_floating_class_nan_and_natval_masks);
    g_test_add_func("/ia64-insn/floating-class-numeric-masks",
                    test_floating_class_numeric_masks);
    g_test_add_func("/ia64-insn/unc-floating-class-false-predicate-clear",
                    test_unc_floating_class_clears_targets_when_false_predicated);
    g_test_add_func("/ia64-insn/unc-predicate-test-false-predicate-clear",
                    test_unc_predicate_test_clears_targets_when_false_predicated);
    g_test_add_func("/ia64-insn/predicate-test-bit",
                    test_predicate_test_bit_updates_predicates);
    g_test_add_func("/ia64-insn/rotating-predicate-access",
                    test_rotating_predicate_access_maps_through_rrb);
    for (uint32_t i = 0; i < G_N_ELEMENTS(call_frame_rows); i++) {
        g_test_add_data_func(call_frame_rows[i].path,
                             &call_frame_rows[i],
                             test_call_frame_transition_row);
    }
    g_test_add_func("/ia64-insn/b-unit-relative-call",
                    test_b_unit_relative_call_updates_link_and_frame);
    g_test_add_func("/ia64-insn/b-unit-relative-branch",
                    test_b_unit_relative_branch);
    g_test_add_func("/ia64-insn/b-unit-relative-branch-encoding-gate",
                    test_b_unit_relative_branch_encoding_gate);
    g_test_add_func("/ia64-insn/counted-store-loop-decode",
                    test_counted_store_loop_decode_from_decompressor);
    g_test_add_func("/ia64-insn/b-unit-indirect-return",
                    test_b_unit_indirect_return);
    g_test_add_func("/ia64-insn/b-unit-indirect-return-wrap",
                    test_b_unit_indirect_return_wraps_frame_base);
    g_test_add_func("/ia64-insn/b-unit-indirect-return-contiguous-invalidate",
                    test_b_unit_indirect_return_invalidates_contiguous_window);
    g_test_add_func("/ia64-insn/b-unit-indirect-return-wrapped-invalidate",
                    test_b_unit_indirect_return_invalidates_wrapped_window);
    g_test_add_func("/ia64-insn/b-unit-indirect-return-clean-bsp",
                    test_b_unit_indirect_return_retreats_clean_bsp);
    g_test_add_func("/ia64-insn/b-unit-indirect-return-clean-boundary",
                    test_b_unit_indirect_return_clamps_clean_boundary);
    g_test_add_func("/ia64-insn/b-unit-rfi",
                    test_b_unit_return_from_interruption);
    g_test_add_func("/ia64-insn/rfi-staged-control-registers",
                    test_rfi_staged_control_registers);
    g_test_add_func("/ia64-insn/rfi-valid-ifs-uncovers-frame",
                    test_rfi_uncovers_valid_interruption_frame);
    g_test_add_func("/ia64-insn/rfi-valid-ifs-clamps-clean-boundary",
                    test_rfi_uncovers_valid_frame_clamps_clean_boundary);
    g_test_add_func("/ia64-insn/rfi-invalid-ifs",
                    test_rfi_ignores_invalid_ifs);
    g_test_add_func("/ia64-insn/b-unit-system-branch-extensions",
                    test_b_unit_system_branch_extensions);
    g_test_add_func("/ia64-insn/cover-ifs-psr-ic",
                    test_cover_sets_ifs_only_when_interruption_collection_off);
    g_test_add_func("/ia64-insn/b-unit-indirect-call",
                    test_b_unit_indirect_call_updates_link_and_frame);
    g_test_add_func("/ia64-insn/b-unit-predict-or-nop",
                    test_b_unit_predict_or_nop);
    g_test_add_func("/ia64-insn/b-unit-break-decode",
                    test_b_unit_break_decode);
    g_test_add_func("/ia64-insn/reserved-template-message",
                    test_reserved_template_message);
    g_test_add_func("/ia64-insn/physical-region-alias-translation",
                    test_physical_region_alias_translation);

    return g_test_run();
}
