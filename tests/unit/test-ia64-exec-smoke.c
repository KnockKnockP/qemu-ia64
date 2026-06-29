/*
 * IA-64 minimal execution smoke tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/exec-smoke.h"
#include "target/ia64/mem.h"

#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT  UINT64_C(0x0000000000004000)
#define IA64_PSR_DT_BIT UINT64_C(0x0000000000020000)
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
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

static uint64_t make_i2_packed_raw(uint8_t za, uint8_t zb,
                                   uint8_t x2b, uint8_t x2c,
                                   uint8_t r1, uint8_t r2, uint8_t r3)
{
    return (7ULL << 37) | ((uint64_t)za << 36) | (2ULL << 34) |
           ((uint64_t)zb << 33) | ((uint64_t)x2c << 30) |
           ((uint64_t)x2b << 28) | ((uint64_t)r3 << 20) |
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
    g_assert_cmphex(env.fr[0].raw[0], ==, 0);
    g_assert_cmphex(env.fr[0].raw[1], ==, 0x1ffff);
    g_assert_cmphex(env.fr[1].raw[0], ==, 0x8000000000000000ULL);
    g_assert_cmphex(env.fr[1].raw[1], ==, 0xffff);
    g_assert_cmphex(env.cpuid[0], ==, 0x49656e69756e6547ULL);
    g_assert_cmphex(env.cpuid[1], ==, 0x000000006c65746eULL);
    g_assert_cmphex(env.cpuid[3], ==, 0x0000000200000004ULL);
    g_assert_cmphex(env.cpuid[4], ==, 0x0000000300000000ULL);
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

static void test_banked_register_switch_via_bsw(void)
{
    const uint64_t bsw_0_raw = 0x0cULL << 27;
    const uint64_t bsw_1_raw = 0x0dULL << 27;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);

    ia64_write_gr(&env, 16, 0x1111);
    env.psr |= IA64_PSR_BN_BIT;
    ia64_write_gr(&env, 16, 0x2222);
    env.psr &= ~IA64_PSR_BN_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x1000,
                                              &target));
    g_assert_cmphex(target, ==, 0x1010);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, IA64_PSR_BN_BIT);
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x2222);
    ia64_write_gr(&env, 16, 0x3333);

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_0_raw, 0x1010,
                                              &target));
    g_assert_cmphex(target, ==, 0x1020);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, 0);
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x1111);

    g_assert_true(ia64_exec_b_indirect_branch(&env, bsw_1_raw, 0x1020,
                                              &target));
    g_assert_cmphex(ia64_read_gr(&env, 16), ==, 0x3333);
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
    ia64_write_gr(&env, 33, 0x3018);

    g_assert_true(ia64_slot_is_mov_to_application(IA64_SLOT_TYPE_I,
                                                  mov_ar_bspstore_r33_raw));
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_ar_bspstore_r33_raw));
    g_assert_cmphex(env.rse.bspstore, ==, 0x3018);
    g_assert_cmpuint(env.rse.clean_count, ==, 101);
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
    g_assert_cmpuint(env.rse.clean_count, ==, 22);

    ia64_write_gr(&env, 33, 0x6000);
    g_assert_true(ia64_exec_mov_to_application(&env, IA64_SLOT_TYPE_I,
                                               mov_ar_bspstore_r33_raw));

    g_assert_cmphex(env.rse.bspstore, ==, 0x6000);
    g_assert_cmphex(env.rse.bsp, ==, ia64_rse_skip_regs(0x6000, 10));
    g_assert_cmpuint(ia64_rse_num_regs(env.rse.bspstore, env.rse.bsp), ==, 10);
}

typedef struct TestRSEBackingStore {
    uint64_t first_address;
    uint64_t value[8];
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
    g_assert_cmpuint(env.rse.clean_count, ==, 4);
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

    g_assert_cmpuint(env.rse.clean_count, ==, 17);

    env.rse.clean_count = 17;
    env.rse.bsp = ia64_rse_skip_regs(env.rse.bspstore, 3);

    ia64_rse_reconstruct_transients(&env);

    g_assert_cmpuint(env.rse.clean_count, ==, 14);

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
    const uint64_t mov_pr_r37_mask_raw = 0x016ff04bfc0ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.pr = (1ULL << 15) | (1ULL << 1) | 1;
    ia64_write_gr(&env, 37, 1ULL << 8);

    g_assert_true(ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I,
                                                  mov_pr_r37_mask_raw));
    g_assert_true(ia64_exec_i_mov_to_predicate(&env, mov_pr_r37_mask_raw));
    g_assert_cmphex(env.pr & 1, ==, 1);
    g_assert_cmphex(env.pr & (1ULL << 1), ==, 0);
    g_assert_cmphex(env.pr & (1ULL << 8), ==, 1ULL << 8);
    g_assert_cmphex(env.pr & (1ULL << 15), ==, 1ULL << 15);
    g_assert_cmphex(env.pr & (1ULL << 16), ==, 0);
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
    const uint64_t kernel_loadrs_raw = 0x00050000000ULL;
    const uint64_t kernel_flushrs_raw = 0x00060000000ULL;
    CPUIA64State env;
    IA64TranslateResult fault;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_slot_is_check_speculative(
                      IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw));
    g_assert_cmpint(ia64_check_speculative_displacement(
                        userspace_chk_s_m_r22_raw), ==, 80);
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw,
                      0x2000000000032370ULL, &target));
    g_assert_cmphex(target, ==, 0x2000000000032380ULL);

    env.nat.gr_nat[22 / 64] |= 1ULL << (22 % 64);
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, userspace_chk_s_m_r22_raw,
                      0x2000000000032370ULL, &target));
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
                      &target));
    g_assert_cmphex(target, ==, 0x1050);
    env.nat.gr_nat[22 / 64] = 0;

    g_assert_true(ia64_slot_is_check_speculative(IA64_SLOT_TYPE_M,
                                                chk_s_f8_raw));
    g_assert_cmpint(ia64_check_speculative_displacement(chk_s_f8_raw),
                    ==, 80);
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, chk_s_f8_raw, 0x2000,
                      &target));
    g_assert_cmphex(target, ==, 0x2010);
    env.fr[8].raw[0] = 0;
    env.fr[8].raw[1] = 0x1fffe;
    target = 0;
    g_assert_true(ia64_exec_check_speculative(
                      &env, IA64_SLOT_TYPE_M, chk_s_f8_raw, 0x2000,
                      &target));
    g_assert_cmphex(target, ==, 0x2050);

    g_assert_true(ia64_slot_is_m_check_advanced(IA64_SLOT_TYPE_M,
                                                chk_a_clr_r10_raw));
    g_assert_cmpint(ia64_branch_displacement(chk_a_clr_r10_raw), ==, 192);
    g_assert_true(ia64_exec_m_check_advanced(&env, chk_a_clr_r10_raw,
                                             0x100eb30, &target));
    g_assert_cmphex(target, ==, 0x100ebf0);

    env.alat.entries[0].valid = true;
    env.alat.entries[0].target = 10;
    env.alat.entries[0].width = 4;
    env.alat.entries[0].physical = true;
    env.alat.entries[0].address = 0x1000;
    target = 0;
    g_assert_true(ia64_exec_m_check_advanced(&env, chk_a_clr_r10_raw,
                                             0x100eb30, &target));
    g_assert_cmphex(target, ==, 0x100eb40);
    g_assert_false(env.alat.entries[0].valid);

    g_assert_true(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M, sync_i_raw));
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
    g_assert_true(ia64_slot_is_m_invala(IA64_SLOT_TYPE_M,
                                        kernel_invala_raw));
    g_assert_false(ia64_slot_is_m_system_noop(IA64_SLOT_TYPE_M,
                                              kernel_invala_raw));
    g_assert_true(ia64_exec_m_invala(&env, kernel_invala_raw));
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        g_assert_false(env.alat.entries[i].valid);
    }
    g_assert_cmpuint(env.alat.next, ==, 0);

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

static void test_interrupt_control_registers(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_cmphex(ia64_read_control_register(&env, IA64_CR_IVR), ==, 0x0f);

    env.cr[IA64_CR_ITV] = 0xef;
    env.cr[IA64_CR_ITM] = 10;
    env.ar[IA64_AR_ITC] = 9;
    g_assert_false(ia64_timer_interrupt_due(&env));

    ia64_advance_itc(&env, 1);
    g_assert_true(ia64_timer_interrupt_due(&env));
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    env.psr |= 0x4000;
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
    g_assert_true(ia64_advance_itc_and_check_timer(&env, 1));
    g_assert_cmphex(env.ar[IA64_AR_ITC], ==, 10);
    ia64_latch_timer_interrupt(&env);
    g_assert_true(ia64_external_interrupt_pending(&env));

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_ITV] = (1ULL << 16) | 0xef;
    env.cr[IA64_CR_ITM] = 0;
    env.ar[IA64_AR_ITC] = 1000;
    g_assert_false(ia64_advance_itc_and_check_timer(&env, 1));
    g_assert_cmphex(env.ar[IA64_AR_ITC], ==, 1001);
    g_assert_false(ia64_external_interrupt_pending(&env));
}

static void test_interrupt_unmask_exposes_pending_external_interrupt(void)
{
    const uint64_t ssm_i_raw = (6ULL << 27) | (IA64_PSR_I_BIT << 6);
    const uint64_t rsm_i_raw = (7ULL << 27) | (IA64_PSR_I_BIT << 6);
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    g_assert_true(ia64_queue_external_interrupt(&env, 0xef));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));

    g_assert_true(ia64_exec_m_processor_mask(&env, ssm_i_raw));
    g_assert_true(ia64_external_interrupt_enabled(&env));

    g_assert_true(ia64_exec_m_processor_mask(&env, rsm_i_raw));
    g_assert_true(ia64_external_interrupt_pending(&env));
    g_assert_false(ia64_external_interrupt_enabled(&env));
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
    }
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

static void test_m_unit_getf_significand(void)
{
    const uint64_t getf_sig_r21_f10_raw = 0x08708014540ULL;
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.fr[10].raw[0] = 0x1234;
    env.fr[10].raw[1] = 0x1003e;

    g_assert_true(ia64_slot_is_m_getf(IA64_SLOT_TYPE_M,
                                      getf_sig_r21_f10_raw));
    g_assert_true(ia64_exec_m_getf(&env, getf_sig_r21_f10_raw));
    g_assert_cmphex(ia64_read_gr(&env, 21), ==, 0x1234);
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
    g_assert_cmpuint(env.rse.current_frame_base, ==, 4);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==, 0xaaaa);
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, 0xbbbb);
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

static void test_counted_store_loop_decode_from_decompressor(void)
{
    const uint64_t st1_r0_r32_imm1_raw = 0x0ac02000040ULL;
    const uint64_t br_cloop_self_raw = 0x08000000140ULL;
    uint8_t bundle_bytes[IA64_BUNDLE_SIZE];
    IA64DecodedBundle bundle;
    IA64CountedStoreLoop decoded;

    make_bundle(bundle_bytes, 0x10, st1_r0_r32_imm1_raw,
                IA64_SMOKE_NOP_RAW, br_cloop_self_raw);

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
                IA64_SMOKE_NOP_RAW, br_cloop_self_raw);
    g_assert_true(ia64_decode_bundle(bundle_bytes, &bundle));
    g_assert_false(ia64_decode_counted_store_loop(&bundle, 0x1034880,
                                                  &decoded));
}

static void test_b_unit_indirect_return(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(2, 0, 0));
    env.rse.current_frame_base = 4;
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B,
                                                 br_ret_b0_raw));
    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==, 0);
    g_assert_cmpuint(env.rse.sof, ==, 6);
    g_assert_cmpuint(env.rse.sol, ==, 4);
}

static void test_b_unit_indirect_return_wraps_frame_base(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(2, 0, 0));
    env.rse.current_frame_base = 1;
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;
    env.rse.stacked_gr[2] = 0x2222;
    env.rse.stacked_gr[3] = 0x3333;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(6, 4, 0));
    g_assert_cmpuint(env.rse.current_frame_base, ==,
                     IA64_STACKED_GR_COUNT - 3);
    g_assert_cmphex(env.rse.stacked_gr[2], ==, 0x2222);
    g_assert_cmphex(env.rse.stacked_gr[3], ==, 0);
}

static void test_b_unit_indirect_return_retreats_clean_bsp(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(2, 0, 0));
    env.rse.current_frame_base = 4;
    env.rse.bspstore = 0x1200;
    env.rse.bsp = 0x1200;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmphex(env.rse.bsp, ==, ia64_rse_skip_regs(0x1200, -4));
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, env.rse.bsp);
    g_assert_cmphex(env.rse.bspstore, ==, 0x1200);
}

static void test_b_unit_indirect_return_clamps_clean_boundary(void)
{
    const uint64_t br_ret_b0_raw = 0x00108000100ULL;
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
    ia64_set_cfm(&env, ia64_make_cfm(2, 0, 0));
    env.rse.current_frame_base = 4;
    env.rse.clean_count = 2321;
    env.ar[IA64_AR_PFS] = ia64_make_cfm(6, 4, 0);
    env.br[0] = 0x1001047;

    g_assert_true(ia64_exec_b_indirect_branch(&env, br_ret_b0_raw, 0x2000,
                                              &target));

    g_assert_cmphex(target, ==, 0x1001040);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 0);
    g_assert_cmpuint(env.rse.clean_count, ==, 0);
}

static void test_b_unit_return_from_interruption(void)
{
    const uint64_t rfi_raw = 0x00040000000ULL;
    const uint64_t ipsr = ia64_psr_with_ri(0x001010084a2008ULL, 2);
    CPUIA64State env;
    uint64_t target = 0;

    ia64_cpu_reset_synthetic_itanium2(&env);
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

    ia64_cpu_reset_synthetic_itanium2(&env);
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

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    env.rse.current_frame_base = 19;
    ia64_set_cfm(&env, 0);
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

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.cr[IA64_CR_IPSR] = 0x001010084a2008ULL;
    env.cr[IA64_CR_IIP] = 0xa0000001007f7e57ULL;
    env.rse.current_frame_base = 19;
    env.rse.clean_count = 2321;
    ia64_set_cfm(&env, 0);
    env.cr[IA64_CR_IFS] = interrupted_cfm | IA64_IFS_VALID_BIT;

    g_assert_true(ia64_exec_b_indirect_branch(&env, rfi_raw, 0x47f7e40,
                                              &target));
    g_assert_cmphex(target, ==, 0xa0000001007f7e50ULL);
    g_assert_cmphex(env.cfm, ==, interrupted_cfm);
    g_assert_cmpuint(env.rse.current_frame_base, ==, 11);
    g_assert_cmpuint(env.rse.clean_count, ==, 11);
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
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, old_cfm);
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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-exec-smoke/reset", test_reset);
    g_test_add_func("/ia64-exec-smoke/banked-static-gr",
                    test_banked_static_general_registers);
    g_test_add_func("/ia64-exec-smoke/banked-bsw-visibility",
                    test_banked_register_switch_via_bsw);
    g_test_add_func("/ia64-exec-smoke/syscall-break-user-to-kernel",
                    test_syscall_break_user_to_kernel_transition);
    g_test_add_func("/ia64-exec-smoke/syscall-rfi-kernel-to-user",
                    test_syscall_return_rfi_kernel_to_user_transition);
    g_test_add_func("/ia64-exec-smoke/epc-user-to-kernel",
                    test_epc_clears_user_cpl_for_kernel_entry);
    g_test_add_func("/ia64-exec-smoke/bundle-fetch-decode",
                    test_bundle_fetch_decode);
    g_test_add_func("/ia64-exec-smoke/ip-advances-for-nop-bundle",
                    test_ip_advances_for_nop_bundle);
    g_test_add_func("/ia64-exec-smoke/unsupported-instruction-message",
                    test_unsupported_instruction_message);
    g_test_add_func("/ia64-exec-smoke/m34-alloc-updates-frame-state",
                    test_m34_alloc_updates_frame_state);
    g_test_add_func("/ia64-exec-smoke/frame-state-preserves-ifs",
                    test_frame_state_updates_preserve_interruption_frame_state);
    g_test_add_func("/ia64-exec-smoke/rse-backing-store-address-helpers",
                    test_rse_backing_store_address_helpers);
    g_test_add_func("/ia64-exec-smoke/rse-stacked-write-marks-clean-register-dirty",
                    test_rse_stacked_write_marks_clean_register_dirty);
    g_test_add_func("/ia64-exec-smoke/rse-bspstore-write-preserves-dirty-boundary",
                    test_rse_bspstore_write_preserves_dirty_boundary);
    g_test_add_func("/ia64-exec-smoke/rse-loadrs-dirty-partition-bspstore-switch",
                    test_rse_loadrs_dirty_partition_survives_bspstore_switch);
    g_test_add_func("/ia64-exec-smoke/rse-loadrs-preserves-rfi-frame",
                    test_rse_loadrs_preserves_dirty_frame_uncovered_by_rfi);
    g_test_add_func("/ia64-exec-smoke/rse-loadrs-reads-clean-prefix-only",
                    test_rse_loadrs_reads_clean_prefix_only);
    g_test_add_func("/ia64-exec-smoke/rse-reconstructs-clean-partition-after-load",
                    test_rse_reconstructs_clean_partition_after_load);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-ip-and-nop",
                    test_i_unit_mov_ip_and_nop);
    g_test_add_func("/ia64-exec-smoke/i-unit-break-delivers-interruption-state",
                    test_i_unit_break_delivers_interruption_state);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-from-predicate",
                    test_i_unit_mov_from_predicate);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-to-predicate-mask",
                    test_i_unit_mov_to_predicate_mask);
    g_test_add_func("/ia64-exec-smoke/i-unit-mov-to-branch",
                    test_i_unit_mov_to_branch);
    g_test_add_func("/ia64-exec-smoke/application-register-moves",
                    test_application_register_moves);
    g_test_add_func("/ia64-exec-smoke/m-unit-system-memory-management",
                    test_m_unit_system_memory_management);
    g_test_add_func("/ia64-exec-smoke/interrupt-control-registers",
                    test_interrupt_control_registers);
    g_test_add_func("/ia64-exec-smoke/interrupt-unmask-pending",
                    test_interrupt_unmask_exposes_pending_external_interrupt);
    g_test_add_func("/ia64-exec-smoke/lx-movl-reconstructs-immediate",
                    test_lx_movl_reconstructs_immediate);
    g_test_add_func("/ia64-exec-smoke/lx-nop-hint-pair",
                    test_lx_nop_hint_pair);
    g_test_add_func("/ia64-exec-smoke/alu-add-register-form",
                    test_alu_add_register_form);
    g_test_add_func("/ia64-exec-smoke/alu-sub-register-form",
                    test_alu_sub_register_form);
    g_test_add_func("/ia64-exec-smoke/alu-logic-addp4-and-shladd",
                    test_alu_logic_addp4_and_shladd);
    g_test_add_func("/ia64-exec-smoke/i-unit-mux-permutations",
                    test_i_unit_mux_permutations);
    g_test_add_func("/ia64-exec-smoke/i-unit-packed-i2-frontier-mix4r",
                    test_i_unit_packed_i2_frontier_mix4r);
    g_test_add_func("/ia64-exec-smoke/i-unit-packed-i2-operations",
                    test_i_unit_packed_i2_operations);
    g_test_add_func("/ia64-exec-smoke/i-unit-variable-shifts",
                    test_i_unit_variable_shifts);
    g_test_add_func("/ia64-exec-smoke/i-unit-bit-count",
                    test_i_unit_bit_count);
    g_test_add_func("/ia64-exec-smoke/addl-immediate-form",
                    test_addl_immediate_form);
    g_test_add_func("/ia64-exec-smoke/m-unit-setf-significand",
                    test_m_unit_setf_significand);
    g_test_add_func("/ia64-exec-smoke/m-unit-getf-significand",
                    test_m_unit_getf_significand);
    g_test_add_func("/ia64-exec-smoke/floating-spill-format-constants",
                    test_floating_spill_format_constants);
    g_test_add_func("/ia64-exec-smoke/extract-zero-extends-bitfield",
                    test_extract_zero_extends_bitfield);
    g_test_add_func("/ia64-exec-smoke/deposit-zero-elilo-frontier",
                    test_deposit_zero_from_elilo_frontier);
    g_test_add_func("/ia64-exec-smoke/deposit-immediate-masks-field",
                    test_deposit_immediate_masks_inserted_field);
    g_test_add_func("/ia64-exec-smoke/shift-right-pair-elilo-frontier",
                    test_shift_right_pair_from_elilo_frontier);
    g_test_add_func("/ia64-exec-smoke/integer-extend-zero-extends-byte",
                    test_integer_extend_zero_extends_byte);
    g_test_add_func("/ia64-exec-smoke/f-unit-xma-low",
                    test_f_unit_xma_low);
    g_test_add_func("/ia64-exec-smoke/f-unit-multiply-add-operand-order",
                    test_f_unit_multiply_add_uses_ia64_operand_order);
    g_test_add_func("/ia64-exec-smoke/f-unit-reciprocal-approx",
                    test_f_unit_reciprocal_approx_sets_predicate);
    g_test_add_func("/ia64-exec-smoke/f-unit-misc-unsigned-trunc-conversion",
                    test_f_unit_misc_unsigned_trunc_conversion);
    g_test_add_func("/ia64-exec-smoke/f-unit-misc-noop",
                    test_f_unit_misc_noop);
    g_test_add_func("/ia64-exec-smoke/ldst-immediate-decode",
                    test_ldst_immediate_decode);
    g_test_add_func("/ia64-exec-smoke/m-unit-atomic-decode",
                    test_m_unit_atomic_decode);
    g_test_add_func("/ia64-exec-smoke/floating-memory-decode",
                    test_floating_memory_decode);
    g_test_add_func("/ia64-exec-smoke/compare-immediate-predicate-write",
                    test_compare_immediate_updates_predicates);
    g_test_add_func("/ia64-exec-smoke/compare-parallel-predicate-write",
                    test_compare_parallel_predicate_completers);
    g_test_add_func("/ia64-exec-smoke/unc-compare-false-predicate-clear",
                    test_unc_compare_clears_targets_when_false_predicated);
    g_test_add_func("/ia64-exec-smoke/unc-predicate-test-false-predicate-clear",
                    test_unc_predicate_test_clears_targets_when_false_predicated);
    g_test_add_func("/ia64-exec-smoke/predicate-test-bit",
                    test_predicate_test_bit_updates_predicates);
    g_test_add_func("/ia64-exec-smoke/rotating-predicate-access",
                    test_rotating_predicate_access_maps_through_rrb);
    g_test_add_func("/ia64-exec-smoke/b-unit-relative-call",
                    test_b_unit_relative_call_updates_link_and_frame);
    g_test_add_func("/ia64-exec-smoke/b-unit-relative-branch",
                    test_b_unit_relative_branch);
    g_test_add_func("/ia64-exec-smoke/counted-store-loop-decode",
                    test_counted_store_loop_decode_from_decompressor);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-return",
                    test_b_unit_indirect_return);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-return-wrap",
                    test_b_unit_indirect_return_wraps_frame_base);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-return-clean-bsp",
                    test_b_unit_indirect_return_retreats_clean_bsp);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-return-clean-boundary",
                    test_b_unit_indirect_return_clamps_clean_boundary);
    g_test_add_func("/ia64-exec-smoke/b-unit-rfi",
                    test_b_unit_return_from_interruption);
    g_test_add_func("/ia64-exec-smoke/rfi-staged-control-registers",
                    test_rfi_staged_control_registers);
    g_test_add_func("/ia64-exec-smoke/rfi-valid-ifs-uncovers-frame",
                    test_rfi_uncovers_valid_interruption_frame);
    g_test_add_func("/ia64-exec-smoke/rfi-valid-ifs-clamps-clean-boundary",
                    test_rfi_uncovers_valid_frame_clamps_clean_boundary);
    g_test_add_func("/ia64-exec-smoke/rfi-invalid-ifs",
                    test_rfi_ignores_invalid_ifs);
    g_test_add_func("/ia64-exec-smoke/b-unit-system-branch-extensions",
                    test_b_unit_system_branch_extensions);
    g_test_add_func("/ia64-exec-smoke/cover-ifs-psr-ic",
                    test_cover_sets_ifs_only_when_interruption_collection_off);
    g_test_add_func("/ia64-exec-smoke/b-unit-indirect-call",
                    test_b_unit_indirect_call_updates_link_and_frame);
    g_test_add_func("/ia64-exec-smoke/b-unit-predict-or-nop",
                    test_b_unit_predict_or_nop);
    g_test_add_func("/ia64-exec-smoke/reserved-template-message",
                    test_reserved_template_message);
    g_test_add_func("/ia64-exec-smoke/physical-region-alias-translation",
                    test_physical_region_alias_translation);

    return g_test_run();
}
