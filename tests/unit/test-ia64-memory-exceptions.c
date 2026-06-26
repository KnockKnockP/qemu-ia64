/*
 * IA-64 memory and exception skeleton tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "exec/page-protection.h"
#include "target/ia64/exception.h"
#include "target/ia64/exec-smoke.h"
#include "target/ia64/mem.h"

static void test_identity_debug_memory_path(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    char text[192];

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_translate_address(&env, 0x12345000,
                                         MMU_DATA_LOAD, 0, true,
                                         &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_OK);
    g_assert_cmphex(result.paddr, ==, 0x12345000);
    g_assert_cmpint(result.prot, ==, PAGE_READ | PAGE_WRITE | PAGE_EXEC);
    g_assert_cmpint(result.region, ==, 0);
    g_assert_true(result.debug);
    g_assert_true(result.identity);
    g_assert_cmphex(env.memory.last_vaddr, ==, 0x12345000);
    g_assert_cmphex(env.memory.last_paddr, ==, 0x12345000);

    ia64_format_translate_result(&result, text, sizeof(text));
    g_assert_nonnull(strstr(text, "status=ok"));
    g_assert_nonnull(strstr(text, "identity=yes"));
}

static void test_physical_region_alias_path(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr alias = 0xe000000000001000ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);

    g_assert_true(ia64_translate_address(&env, alias, MMU_DATA_LOAD, 0,
                                         false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_OK);
    g_assert_cmpint(result.region, ==, 7);
    g_assert_cmphex(result.paddr, ==, 0x1000);
    g_assert_nonnull(strstr(result.message, "physical mode region-bit strip"));
    g_assert_cmphex(env.memory.last_vaddr, ==, alias);
    g_assert_cmpint(env.memory.last_status, ==, IA64_TRANSLATE_OK);
}

static void test_translated_address_misses_without_entry(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0xa000000100002c00ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= UINT64_C(0x0000001000000000);

    g_assert_false(ia64_translate_address(&env, address, MMU_INST_FETCH, 2,
                                          false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);
    g_assert_cmpint(result.region, ==, 5);
    g_assert_nonnull(strstr(result.message, "instruction TLB miss"));
}

static void test_instruction_translation_register_lookup(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t translation = 0x0010000004000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= UINT64_C(0x0000001000000000);

    g_assert_true(ia64_install_translation(&env, true, true, 2, base,
                                           translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH, 2,
                                         false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_OK);
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);
    g_assert_cmpuint(result.page_size, ==, 26);
    g_assert_nonnull(strstr(result.message, "instruction translation"));
}

static void test_translation_cache_preserves_pinned_register(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t tr_translation = 0x0010000004000661ULL;
    uint64_t tc_translation = 0x0010000008000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= UINT64_C(0x0000001000000000);

    g_assert_true(ia64_install_translation(&env, true, true, 2, base,
                                           tr_translation, itir));
    g_assert_true(ia64_install_translation(&env, true, false, 0, base,
                                           tc_translation, itir));

    g_assert_true(env.memory.itr[2].valid);
    g_assert_true(env.memory.itc[0].valid);
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH, 2,
                                         false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_OK);
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);
}

static void test_exception_reporting(void)
{
    CPUIA64State env;
    char text[256];

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x4000;

    ia64_record_exception(&env, IA64_EXCEPTION_ILLEGAL_OPERATION, 0,
                          MMU_INST_FETCH, "phase6 illegal-op placeholder");
    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_ILLEGAL_OPERATION);
    g_assert_cmphex(env.exception.vector, ==, 0x5400);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, 0x4000);
    g_assert_nonnull(strstr((const char *)env.exception.message,
                           "phase6 illegal-op placeholder"));

    ia64_record_exception(&env, IA64_EXCEPTION_PAGE_FAULT,
                          0xe000000000001000ULL, MMU_DATA_LOAD,
                          "phase6 page-fault placeholder");
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.exception.vector, ==, 0x5000);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, 0xe000000000001000ULL);

    ia64_format_exception(&env.exception, text, sizeof(text));
    g_assert_nonnull(strstr(text, "kind=page-fault"));
    g_assert_nonnull(strstr(text, "pending=yes"));

    ia64_record_exception(&env, IA64_EXCEPTION_GENERAL_EXCEPTION, 0,
                          MMU_DATA_LOAD, "general placeholder");
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_GENERAL_EXCEPTION);

    ia64_record_exception(&env, IA64_EXCEPTION_BREAK, 0,
                          MMU_INST_FETCH, "break placeholder");
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_BREAK);

    ia64_record_exception(&env, IA64_EXCEPTION_EXTERNAL_INTERRUPT, 0,
                          MMU_DATA_LOAD, "external interrupt placeholder");
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_EXTERNAL_INTERRUPT);

    ia64_clear_exception(&env);
    g_assert_false(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_NONE);
}

static void test_tlb_miss_delivery_vectors_to_iva(void)
{
    CPUIA64State env;
    uint64_t psr = UINT64_C(0x0000100300006000);
    vaddr miss = 0xa000000100002c00ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = miss;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;

    ia64_deliver_exception(&env, IA64_EXCEPTION_INSTRUCTION_TLB_MISS,
                           miss, MMU_INST_FETCH, "test itlb miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==,
                    IA64_EXCEPTION_INSTRUCTION_TLB_MISS);
    g_assert_cmphex(env.exception.vector, ==, 0x0400);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, miss);
    g_assert_cmphex(env.ip, ==, 0x100400);
    g_assert_cmphex(env.psr & UINT64_C(0x0000100300006000), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-memory/identity-debug-path",
                    test_identity_debug_memory_path);
    g_test_add_func("/ia64-memory/physical-region-alias",
                    test_physical_region_alias_path);
    g_test_add_func("/ia64-memory/translated-miss",
                    test_translated_address_misses_without_entry);
    g_test_add_func("/ia64-memory/instruction-translation-register",
                    test_instruction_translation_register_lookup);
    g_test_add_func("/ia64-memory/tc-preserves-pinned-tr",
                    test_translation_cache_preserves_pinned_register);
    g_test_add_func("/ia64-exception/reporting", test_exception_reporting);
    g_test_add_func("/ia64-exception/tlb-miss-delivery",
                    test_tlb_miss_delivery_vectors_to_iva);

    return g_test_run();
}
