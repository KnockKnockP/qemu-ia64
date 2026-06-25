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
    g_test_add_func("/ia64-exec-smoke/reserved-template-message",
                    test_reserved_template_message);

    return g_test_run();
}
