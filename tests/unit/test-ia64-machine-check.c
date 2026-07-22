/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "target/ia64/insn.h"
#include "target/ia64/machine-check.h"

#define TEST_STATIC_NAT (UINT64_C(1) << 3)
#define TEST_BANK0_NAT (UINT64_C(1) << 19)
#define TEST_BANK1_NAT (UINT64_C(1) << 27)

static void seed_static_state(CPUIA64State *env, bool bank_one, bool ic)
{
    uint64_t psr = (bank_one ? IA64_PSR_BN_BIT : 0) |
                   (ic ? IA64_PSR_IC_BIT : 0);

    ia64_cpu_reset_synthetic_itanium2(env);
    ia64_env_replace_psr(env, psr);
    for (unsigned reg = 1; reg <= 31; reg++) {
        env->gr[reg] = UINT64_C(0x1000000000000000) + reg;
    }
    for (unsigned reg = 0; reg < 16; reg++) {
        env->banked_gr[reg] = UINT64_C(0x2000000000000010) + reg;
    }
    env->nat.gr_nat[0] = TEST_STATIC_NAT |
        (bank_one ? TEST_BANK1_NAT : TEST_BANK0_NAT);
    env->nat.gr_nat[1] = bank_one ? TEST_BANK0_NAT : TEST_BANK1_NAT;
    env->pr = UINT64_C(0x8000000000000021);
    env->br[0] = UINT64_C(0x1111222233334440);
    env->br[1] = UINT64_C(0x5555666677778880);
    env->rse.rsc = UINT64_C(0x0000000000010018);
    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ip = UINT64_C(0x123450);
    ia64_set_cfm(env, ia64_make_cfm(24, 8, 2));
}

static void assert_common_image(const CPUIA64State *env,
                                const uint64_t *image)
{
    g_assert_cmphex(image[IA64_MIN_STATE_NAT], ==,
                    TEST_STATIC_NAT | TEST_BANK0_NAT |
                    (TEST_BANK1_NAT << 16));
    for (unsigned reg = 1; reg <= 15; reg++) {
        g_assert_cmphex(image[IA64_MIN_STATE_GR1 + reg - 1], ==,
                        UINT64_C(0x1000000000000000) + reg);
    }
    for (unsigned reg = 0; reg < 16; reg++) {
        g_assert_cmphex(image[IA64_MIN_STATE_BANK0_GR16 + reg], ==,
                        UINT64_C(0x1000000000000010) + reg);
        g_assert_cmphex(image[IA64_MIN_STATE_BANK1_GR16 + reg], ==,
                        UINT64_C(0x2000000000000010) + reg);
    }
    g_assert_cmphex(image[IA64_MIN_STATE_PR], ==, env->pr);
    g_assert_cmphex(image[IA64_MIN_STATE_BR0], ==, env->br[0]);
    g_assert_cmphex(image[IA64_MIN_STATE_BR1], ==, env->br[1]);
    g_assert_cmphex(image[IA64_MIN_STATE_RSC], ==, env->rse.rsc);
    g_assert_cmphex(image[IA64_MIN_STATE_IIP], ==, env->ip);
    g_assert_cmphex(image[IA64_MIN_STATE_IPSR], ==, ia64_env_psr(
                        (CPUIA64State *)env));
    g_assert_cmphex(image[IA64_MIN_STATE_IFS], ==,
                    env->cfm | IA64_IFS_VALID_BIT);
}

static void test_min_state_bank_layout(void)
{
    CPUIA64State env;

    for (unsigned bank_one = 0; bank_one < 2; bank_one++) {
        const uint64_t *image;

        seed_static_state(&env, bank_one, true);
        g_assert_true(ia64_machine_check_register_min_state(&env, 0x4000,
                                                            0));
        g_assert_true(ia64_machine_check_capture(
            &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
        image = ia64_machine_check_pending_image(&env);
        g_assert_nonnull(image);
        assert_common_image(&env, image);
        g_assert_cmphex(image[IA64_MIN_STATE_XIP], ==, env.ip);
        g_assert_cmphex(image[IA64_MIN_STATE_XPSR], ==,
                        ia64_env_psr(&env));
        g_assert_cmphex(image[IA64_MIN_STATE_XFS], ==,
                        env.cfm | IA64_IFS_VALID_BIT);
    }
}

static void test_uncollected_two_level_resources(void)
{
    CPUIA64State env;
    const uint64_t prior_iip = UINT64_C(0xabcdef0);
    const uint64_t prior_ipsr = IA64_PSR_IC_BIT | UINT64_C(0x20000);
    const uint64_t prior_ifs = ia64_make_cfm(8, 4, 1);
    uint64_t saved_image[IA64_MIN_STATE_WORDS];
    const uint64_t *image;

    seed_static_state(&env, false, false);
    env.cr[IA64_CR_IIP] = prior_iip;
    env.cr[IA64_CR_IPSR] = prior_ipsr;
    env.cr[IA64_CR_IFS] = prior_ifs;
    g_assert_true(ia64_machine_check_capture(
        &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
    image = ia64_machine_check_pending_image(&env);
    assert_common_image(&env, image);
    g_assert_cmphex(image[IA64_MIN_STATE_XIP], ==, prior_iip);
    g_assert_cmphex(image[IA64_MIN_STATE_XPSR], ==, prior_ipsr);
    g_assert_cmphex(image[IA64_MIN_STATE_XFS], ==, prior_ifs);

    memcpy(saved_image, image, sizeof(saved_image));
    ia64_machine_check_mark_delivered(&env);
    g_assert_true(ia64_machine_check_resume(&env, saved_image, false,
                                             false));
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, prior_iip);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, prior_ipsr);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, prior_ifs);
}

static void test_registration_and_deferred_capture(void)
{
    CPUIA64State env;
    uint64_t first_iip;

    seed_static_state(&env, false, true);
    g_assert_false(ia64_machine_check_register_min_state(&env, 0x4100, 0));
    g_assert_false(ia64_machine_check_register_min_state(&env, 0x4000, 8));
    g_assert_true(ia64_machine_check_register_min_state(&env, 0x4000, 4));
    ia64_env_replace_psr(&env, ia64_env_psr(&env) | IA64_PSR_MC_BIT);
    g_assert_true(ia64_machine_check_capture(
        &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
    g_assert_false(ia64_machine_check_delivery_ready(&env));
    first_iip = env.machine_check.min_state[IA64_MIN_STATE_IIP];
    env.ip += 0x1000;
    g_assert_false(ia64_machine_check_capture(
        &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
    g_assert_cmphex(env.machine_check.min_state[IA64_MIN_STATE_IIP], ==,
                    first_iip);
    g_assert_true((env.machine_check.processor_state_parameter &
                   (UINT64_C(1) << 4)) != 0);
    ia64_env_replace_psr(&env, ia64_env_psr(&env) & ~IA64_PSR_MC_BIT);
    g_assert_true(ia64_machine_check_delivery_ready(&env));
}

static void test_resume_restores_min_state(void)
{
    CPUIA64State env;
    uint64_t image[IA64_MIN_STATE_WORDS];
    uint64_t expected_psr;
    uint64_t expected_cfm;

    seed_static_state(&env, true, true);
    expected_psr = ia64_env_psr(&env);
    expected_cfm = env.cfm;
    g_assert_true(ia64_machine_check_capture(
        &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
    memcpy(image, env.machine_check.min_state, sizeof(image));
    ia64_machine_check_mark_delivered(&env);
    g_assert_true(env.machine_check.active);

    memset(env.gr, 0xa5, sizeof(env.gr));
    memset(env.banked_gr, 0x5a, sizeof(env.banked_gr));
    env.nat.gr_nat[0] = UINT64_MAX;
    env.nat.gr_nat[1] = UINT64_MAX;
    env.pr = 1;
    env.br[0] = 0;
    env.br[1] = 0;
    env.ip = 0;
    env.cr[IA64_CR_CMCV] = UINT64_C(0x40);
    g_assert_true(ia64_machine_check_resume(&env, image, false, true));

    g_assert_cmphex(ia64_env_psr(&env), ==, expected_psr);
    g_assert_cmphex(env.cfm, ==, expected_cfm);
    g_assert_cmphex(env.ip, ==, image[IA64_MIN_STATE_IIP]);
    g_assert_cmphex(env.gr[1], ==, image[IA64_MIN_STATE_GR1]);
    g_assert_cmphex(env.gr[31], ==,
                    image[IA64_MIN_STATE_BANK0_GR16 + 15]);
    g_assert_cmphex(env.banked_gr[15], ==,
                    image[IA64_MIN_STATE_BANK1_GR16 + 15]);
    g_assert_cmphex(env.nat.gr_nat[0], ==,
                    TEST_STATIC_NAT | TEST_BANK1_NAT);
    g_assert_cmphex(env.nat.gr_nat[1], ==, TEST_BANK0_NAT);
    g_assert_cmphex(env.cr[IA64_CR_IRR1] & UINT64_C(1), ==, 1);
    g_assert_false(env.machine_check.active);
    g_assert_false(env.machine_check.cmci_pending);
}

static void test_state_canonicality(void)
{
    CPUIA64State env;

    seed_static_state(&env, false, true);
    g_assert_true(ia64_machine_check_state_is_canonical(&env.machine_check));
    env.machine_check.min_state_address = 1;
    g_assert_false(ia64_machine_check_state_is_canonical(
        &env.machine_check));
    env.machine_check.min_state_address = 0;
    g_assert_true(ia64_machine_check_capture(
        &env, IA64_MACHINE_CHECK_TRANSLATION_OVERLAP));
    g_assert_true(ia64_machine_check_state_is_canonical(&env.machine_check));
    env.machine_check.cause = 0xff;
    g_assert_false(ia64_machine_check_state_is_canonical(
        &env.machine_check));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ia64-machine-check/min-state-bank-layout",
                    test_min_state_bank_layout);
    g_test_add_func("/ia64-machine-check/uncollected-two-level-resources",
                    test_uncollected_two_level_resources);
    g_test_add_func("/ia64-machine-check/registration-and-deferred-capture",
                    test_registration_and_deferred_capture);
    g_test_add_func("/ia64-machine-check/resume-restores-min-state",
                    test_resume_restores_min_state);
    g_test_add_func("/ia64-machine-check/state-canonicality",
                    test_state_canonicality);
    return g_test_run();
}
