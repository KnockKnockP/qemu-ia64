/*
 * IA-64 memory and exception skeleton tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "exec/page-protection.h"
#include "target/ia64/exception.h"
#include "target/ia64/insn.h"
#include "target/ia64/mem.h"

#define IA64_PSR_IC_BIT   UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT    UINT64_C(0x0000000000004000)
#define IA64_PSR_BN_BIT   UINT64_C(0x0000100000000000)
#define IA64_PSR_ED_BIT   UINT64_C(0x0000080000000000)
#define IA64_PSR_RT_BIT   UINT64_C(0x0000000008000000)
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_DCR_DM_BIT   UINT64_C(0x0000000000000100)
#define IA64_PTE_P_BIT    UINT64_C(0x0000000000000001)
#define IA64_PTE_A_BIT    UINT64_C(0x0000000000000020)
#define IA64_PSR_DELIVERY_CLEARED_MASK \
    (IA64_PSR_I_BIT | IA64_PSR_IC_BIT | IA64_PSR_RI_MASK | \
     IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK)
#define IA64_PSR_DELIVERY_PRESERVED_MASK \
    (IA64_TB_PSR_DT_BIT | IA64_PSR_RT_BIT | IA64_TB_PSR_IT_BIT)

static void assert_delivery_psr(CPUIA64State *env, uint64_t preserved)
{
    g_assert_cmphex((env->psr & IA64_PSR_DELIVERY_CLEARED_MASK), ==, 0);
    g_assert_cmphex((env->psr & IA64_PSR_DELIVERY_PRESERVED_MASK),
                    ==, preserved);
}

static uint64_t test_rr(uint32_t rid, uint8_t page_size, bool vhpt)
{
    return ((uint64_t)rid << 8) | ((uint64_t)page_size << 2) |
           (vhpt ? 1 : 0);
}

static uint64_t test_ldst_load(uint8_t memory_class, uint8_t width_code,
                               uint8_t target, uint8_t base)
{
    uint8_t x6 = (memory_class << 2) | width_code;

    return (UINT64_C(4) << 37) | ((uint64_t)x6 << 30) |
           ((uint64_t)base << 20) | ((uint64_t)target << 6);
}

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

static void test_instruction_translation_reports_exception_deferral(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0x4000;
    uint64_t itir = test_rr(0x11, 12, false);
    uint64_t pte = IA64_PTE_P_BIT | IA64_PTE_A_BIT |
                   (3ULL << 9) | (1ULL << 52) | 0x200000;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_TB_PSR_IT_BIT;
    env.rr[0] = test_rr(0x11, 12, false);

    g_assert_true(ia64_install_translation(&env, true, false, 0, address,
                                           pte, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                         IA64_MMU_INST_CPL0, true,
                                         &result));
    g_assert_true(result.exception_deferral);

    env.psr = 0;
    g_assert_true(ia64_translate_address(&env, 0x1000, MMU_DATA_LOAD,
                                         0, true, &result));
    g_assert_false(result.exception_deferral);
}

static void test_speculative_load_exception_records_isr_sp_ed(void)
{
    CPUIA64State env;
    vaddr ip = 0x4000;
    vaddr miss = 0x6000;
    uint64_t psr = ia64_psr_with_ri(IA64_PSR_IC_BIT |
                                    IA64_TB_PSR_IT_BIT |
                                    IA64_TB_PSR_DT_BIT, 0);
    uint64_t itir = test_rr(0x22, 12, false);
    uint64_t code_pte_ed = IA64_PTE_P_BIT | IA64_PTE_A_BIT |
                           (7ULL << 9) | (1ULL << 52);
    uint64_t code_pte_no_ed = IA64_PTE_P_BIT | IA64_PTE_A_BIT |
                              (7ULL << 9);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[0] = test_rr(0x22, 12, false);
    g_assert_true(ia64_install_translation(&env, true, false, 0, ip,
                                           code_pte_ed, itir));
    env.current_slot_valid = true;
    env.current_slot_ip = ip;
    env.current_slot_ri = ia64_psr_ri(psr);
    env.current_slot_type = IA64_SLOT_TYPE_M;
    env.current_slot_raw = test_ldst_load(1, 3, 21, 20);

    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_TLB_MISS, miss,
                           MMU_DATA_LOAD, "speculative-load");

    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, UINT64_C(1) << IA64_ISR_R_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_SP_BIT),
                    ==, UINT64_C(1) << IA64_ISR_SP_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_ED_BIT),
                    ==, UINT64_C(1) << IA64_ISR_ED_BIT);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[0] = test_rr(0x22, 12, false);
    g_assert_true(ia64_install_translation(&env, true, false, 0, ip,
                                           code_pte_no_ed, itir));
    env.current_slot_valid = true;
    env.current_slot_ip = ip;
    env.current_slot_ri = ia64_psr_ri(psr);
    env.current_slot_type = IA64_SLOT_TYPE_M;
    env.current_slot_raw = test_ldst_load(1, 3, 21, 20);

    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_TLB_MISS, miss,
                           MMU_DATA_LOAD, "speculative-load");

    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_SP_BIT),
                    ==, UINT64_C(1) << IA64_ISR_SP_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_ED_BIT),
                    ==, 0);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[0] = test_rr(0x22, 12, false);
    g_assert_true(ia64_install_translation(&env, true, false, 0, ip,
                                           code_pte_ed, itir));
    env.current_slot_valid = true;
    env.current_slot_ip = ip;
    env.current_slot_ri = ia64_psr_ri(psr);
    env.current_slot_type = IA64_SLOT_TYPE_M;
    env.current_slot_raw = test_ldst_load(0, 3, 21, 20);

    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_TLB_MISS, miss,
                           MMU_DATA_LOAD, "normal-load");

    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_SP_BIT),
                    ==, 0);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_ED_BIT),
                    ==, 0);
}

static void test_control_speculative_load_deferral_policy(void)
{
    CPUIA64State env;
    vaddr ip = 0x4000;
    vaddr miss = 0x6000;
    uint64_t itir = test_rr(0x33, 12, false);
    uint64_t code_pte_ed = IA64_PTE_P_BIT | IA64_PTE_A_BIT |
                           (7ULL << 9) | (1ULL << 52);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_ED_BIT;
    g_assert_true(ia64_control_speculative_load_defer(&env, 1, false,
                                                      miss, NULL));
    g_assert_cmphex(env.psr & IA64_PSR_ED_BIT, ==, 0);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = IA64_PSR_IC_BIT | IA64_TB_PSR_IT_BIT | IA64_TB_PSR_DT_BIT;
    env.cr[IA64_CR_DCR] = IA64_DCR_DM_BIT;
    env.rr[0] = test_rr(0x33, 12, false);
    g_assert_true(ia64_install_translation(&env, true, false, 0, ip,
                                           code_pte_ed, itir));
    g_assert_true(ia64_control_speculative_load_defer(&env, 1, false,
                                                      miss, NULL));

    env.cr[IA64_CR_DCR] = 0;
    g_assert_false(ia64_control_speculative_load_defer(&env, 1, false,
                                                       miss, NULL));
    g_assert_false(ia64_control_speculative_load_defer(&env, 0, false,
                                                       miss, NULL));
}

static void test_tcg_tb_flags_and_mmu_indexes_include_cpl(void)
{
    uint64_t cpl0 = IA64_TB_PSR_DT_BIT | IA64_TB_PSR_IT_BIT;
    uint64_t cpl3 = cpl0 | IA64_TB_PSR_CPL_MASK;
    uint64_t banked_ri2 = cpl0 | IA64_TB_PSR_BN_BIT |
                          (2ULL << IA64_PSR_RI_SHIFT);
    uint32_t cpl0_flags = ia64_tcg_tb_flags_from_psr(cpl0);
    uint32_t cpl3_flags = ia64_tcg_tb_flags_from_psr(cpl3);
    uint32_t banked_ri2_flags = ia64_tcg_tb_flags_from_psr(banked_ri2);

    g_assert_cmpuint(ia64_tcg_psr_cpl(cpl0), ==, 0);
    g_assert_cmpuint(ia64_tcg_psr_cpl(cpl3), ==, 3);
    g_assert_cmphex(cpl0_flags & IA64_TB_FLAG_DT, ==, IA64_TB_FLAG_DT);
    g_assert_cmphex(cpl0_flags & IA64_TB_FLAG_IT, ==, IA64_TB_FLAG_IT);
    g_assert_cmpuint(ia64_tcg_tb_flags_cpl(cpl3_flags), ==, 3);
    g_assert_cmphex(banked_ri2_flags & IA64_TB_FLAG_BN, ==,
                    IA64_TB_FLAG_BN);
    g_assert_cmpuint(ia64_tcg_tb_flags_ri(banked_ri2_flags), ==, 2);
    g_assert_cmphex(cpl0_flags, !=, cpl3_flags);

    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(0, false), ==,
                    IA64_MMU_PHYSICAL);
    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(IA64_TB_PSR_DT_BIT, false),
                    ==, IA64_MMU_DATA_CPL0);
    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(
                        IA64_TB_PSR_DT_BIT | IA64_TB_PSR_CPL_MASK, false),
                    ==, IA64_MMU_DATA_CPL3);
    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(
                        IA64_TB_PSR_IT_BIT | IA64_TB_PSR_CPL_MASK, true),
                    ==, IA64_MMU_INST_CPL3);
    g_assert_cmpint(ia64_tcg_data_mmu_index_for_tb_flags(cpl0_flags), ==,
                    IA64_MMU_DATA_CPL0);
    g_assert_cmpint(ia64_tcg_data_mmu_index_for_tb_flags(cpl3_flags), ==,
                    IA64_MMU_DATA_CPL3);
    g_assert_cmphex(IA64_MMU_ALL_IDXMAP,
                    ==, (1u << IA64_MMU_INDEX_COUNT) - 1u);
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
    g_assert_false(result.vhpt_enabled);
    g_assert_nonnull(strstr(result.message, "instruction alternate TLB miss"));
}

static void test_translated_address_vhpt_miss_reports_region_mode(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0xa000000100002c00ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= UINT64_C(0x0000001000000000);
    env.rr[5] |= 1;

    g_assert_false(ia64_translate_address(&env, address, MMU_INST_FETCH, 2,
                                          false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);
    g_assert_cmpint(result.region, ==, 5);
    g_assert_true(result.vhpt_enabled);
    g_assert_nonnull(strstr(result.message, "instruction VHPT TLB miss"));
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

static void test_translation_lookup_cache_refreshes_after_install(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t large_translation = 0x0010000004000661ULL;
    uint64_t small_translation = 0x0010000008000661ULL;
    uint64_t large_itir = 0x68;
    uint64_t small_itir = 0x40;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_DT_BIT;
    env.rr[5] = test_rr(0x90, 26, false);

    g_assert_true(ia64_install_translation(&env, false, true, 2, base,
                                           large_translation, large_itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                         IA64_MMU_DATA_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);

    g_assert_true(ia64_install_translation(&env, false, false, 0, address,
                                           small_translation, small_itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                         IA64_MMU_DATA_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000008002c00ULL);
    g_assert_cmpuint(result.page_size, ==, 16);
}

static void test_region_register_change_selects_new_rid(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t rid1_translation = 0x0010000004000661ULL;
    uint64_t rid2_translation = 0x0010000008000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_IT_BIT;
    env.rr[5] = test_rr(0x100, 26, false);

    g_assert_true(ia64_install_translation(&env, true, false, 0, base,
                                           rid1_translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                         IA64_MMU_INST_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);

    env.rr[5] = test_rr(0x200, 26, false);
    g_assert_false(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                          IA64_MMU_INST_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);

    g_assert_true(ia64_install_translation(&env, true, false, 0, base,
                                           rid2_translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                         IA64_MMU_INST_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000008002c00ULL);
}

static void test_firmware_identity_tlb_assist_installs_data_tc(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0x00000000020005d0ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_DT_BIT;

    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                          IA64_MMU_DATA_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);

    ia64_firmware_identity_tlb_set(&env, true);
    g_assert_true(ia64_firmware_identity_tlb_fill(
        &env, address, MMU_DATA_LOAD, IA64_MMU_DATA_CPL0, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_OK);
    g_assert_cmphex(result.paddr, ==, address);
    g_assert_cmpuint(result.page_size, ==, 22);
    g_assert_true(env.memory.dtc[0].valid);
    g_assert_cmphex(env.memory.dtc[0].vaddr_base, ==, 0x0000000002000000ULL);
    g_assert_cmphex(env.memory.dtc[0].paddr_base, ==, 0x0000000002000000ULL);
    g_assert_cmpuint(env.memory.next_dtc, ==, 1);
}

static void test_cr_iva_write_masks_base_and_disables_firmware_assist(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0x00000000020005d0ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_DT_BIT;
    ia64_firmware_identity_tlb_set(&env, true);

    ia64_write_control_register(&env, IA64_CR_IVA, 0x00000000001f9234ULL);
    g_assert_cmphex(env.cr[IA64_CR_IVA], ==, 0x00000000001f8000ULL);
    g_assert_false(ia64_firmware_identity_tlb_fill(
        &env, address, MMU_DATA_LOAD, IA64_MMU_DATA_CPL0, &result));
}

static void test_translation_cache_purge_and_same_va_remap(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t first_translation = 0x0010000004000661ULL;
    uint64_t second_translation = 0x0010000008000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_DT_BIT;
    env.rr[5] = test_rr(0x300, 26, false);

    g_assert_true(ia64_install_translation(&env, false, false, 0, base,
                                           first_translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                         IA64_MMU_DATA_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);

    ia64_purge_translation_cache(&env, address, 26, false);
    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                          IA64_MMU_DATA_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);

    g_assert_true(ia64_install_translation(&env, false, false, 0, base,
                                           second_translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                         IA64_MMU_DATA_CPL0, false,
                                         &result));
    g_assert_cmphex(result.paddr, ==, 0x0000000008002c00ULL);
}

static void test_host_tlb_flush_span_for_ia64_page(void)
{
    const uint8_t min_page_bits = 12;
    vaddr start = 0;
    uint64_t len = 0;

    g_assert_true(ia64_host_tlb_flush_span(0x60000fffffc05e48ULL, 16,
                                           &start, &len));
    g_assert_cmphex(start, ==, 0x60000fffffc00000ULL);
    g_assert_cmphex(len, ==, 0x10000ULL);

    g_assert_true(ia64_host_tlb_flush_span(0x60000fffffc05e48ULL,
                                           min_page_bits, &start, &len));
    g_assert_cmphex(start, ==,
                    0x60000fffffc05e48ULL & ~((1ULL << min_page_bits) - 1));
    g_assert_cmphex(len, ==, 1ULL << min_page_bits);

    g_assert_false(ia64_host_tlb_flush_span(0x60000fffffc05e48ULL,
                                            min_page_bits - 1,
                                            &start, &len));
    g_assert_false(ia64_host_tlb_flush_span(0x60000fffffc05e48ULL, 40,
                                            &start, &len));
}

static void test_translation_register_purge_removes_pinned_entry(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t translation = 0x0010000004000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr |= IA64_TB_PSR_IT_BIT;
    env.rr[5] = test_rr(0x400, 26, false);

    g_assert_true(ia64_install_translation(&env, true, true, 2, base,
                                           translation, itir));
    g_assert_true(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                         IA64_MMU_INST_CPL0, false,
                                         &result));

    ia64_purge_translation_register(&env, true, address, 26);
    g_assert_false(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                          IA64_MMU_INST_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);
}

static void test_demand_data_page_fault_delivery(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    vaddr ip = 0xa00000010015fcf0ULL;
    uint64_t not_present_translation = 0x0010000004000660ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                               IA64_TB_PSR_DT_BIT, 1);
    env.ip = ip;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[5] = test_rr(0x500, 26, false);

    g_assert_true(ia64_install_translation(&env, false, false, 0, base,
                                           not_present_translation, itir));
    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_LOAD,
                                          IA64_MMU_DATA_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_NOT_PRESENT);
    g_assert_nonnull(strstr(result.message, "data translation not present"));

    ia64_deliver_exception(&env, IA64_EXCEPTION_PAGE_FAULT, address,
                           MMU_DATA_LOAD, result.message);

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.exception.vector, ==, 0x5000);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, ip);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, address);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==,
                    ia64_default_itir(&env, address));
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 1);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, UINT64_C(1) << IA64_ISR_R_BIT);
    g_assert_nonnull(strstr((const char *)env.exception.message,
                            "data translation not present"));
    g_assert_cmphex(env.ip, ==, 0x105000);
}

static void test_user_store_protection_page_fault_preserves_slot(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    vaddr ip = 0xa00000010015fcf0ULL;
    uint64_t kernel_translation = 0x0010000004000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                               IA64_TB_PSR_DT_BIT |
                               IA64_TB_PSR_CPL_MASK, 2);
    env.ip = ip;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[5] = test_rr(0x501, 26, false);

    g_assert_true(ia64_install_translation(&env, false, false, 0, base,
                                           kernel_translation, itir));
    g_assert_false(ia64_translate_address(&env, address, MMU_DATA_STORE,
                                          IA64_MMU_DATA_CPL3, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_ACCESS_DENIED);
    g_assert_nonnull(strstr(result.message, "data translation access denied"));
    g_assert_nonnull(strstr(result.message, "cpl=3"));

    ia64_deliver_exception(&env, IA64_EXCEPTION_PAGE_FAULT, address,
                           MMU_DATA_STORE, result.message);

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, ip);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, address);
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 2);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_W_BIT),
                    ==, UINT64_C(1) << IA64_ISR_W_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, 0);
    g_assert_nonnull(strstr((const char *)env.exception.message, "cpl=3"));
    assert_delivery_psr(&env, IA64_TB_PSR_DT_BIT);
}

static void test_instruction_fetch_page_fault_sets_fault_ip(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c08ULL;
    uint64_t not_present_translation = 0x0010000004000660ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_PSR_I_BIT | IA64_TB_PSR_IT_BIT;
    env.ip = 0xa00000010000ffe0ULL;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.rr[5] = test_rr(0x502, 26, false);

    g_assert_true(ia64_install_translation(&env, true, false, 0, base,
                                           not_present_translation, itir));
    g_assert_false(ia64_translate_address(&env, address, MMU_INST_FETCH,
                                          IA64_MMU_INST_CPL0, false,
                                          &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_NOT_PRESENT);
    g_assert_nonnull(strstr(result.message,
                            "instruction translation not present"));

    ia64_deliver_exception(&env, IA64_EXCEPTION_PAGE_FAULT, address,
                           MMU_INST_FETCH, result.message);

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, address & ~0xfULL);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, address);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_X_BIT),
                    ==, UINT64_C(1) << IA64_ISR_X_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, 0);
    g_assert_cmphex(env.ip, ==, 0x105000);
}

static void test_no_detail_translation_keeps_status_without_message(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr base = 0xa000000100000000ULL;
    vaddr address = 0xa000000100002c00ULL;
    uint64_t kernel_translation = 0x0010000004000661ULL;
    uint64_t itir = 0x68;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_TB_PSR_DT_BIT | IA64_TB_PSR_CPL_MASK;
    env.rr[5] = test_rr(0x503, 26, false);

    g_assert_false(ia64_translate_address_no_detail(
                       &env, address, MMU_DATA_LOAD, IA64_MMU_DATA_CPL3,
                       false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_TLB_MISS);
    g_assert_cmpstr(result.message, ==, "");
    g_assert_cmphex(env.memory.last_vaddr, ==, address);
    g_assert_cmpint(env.memory.last_status, ==, IA64_TRANSLATE_TLB_MISS);

    g_assert_true(ia64_install_translation(&env, false, false, 0, base,
                                           kernel_translation, itir));
    g_assert_false(ia64_translate_address_no_detail(
                       &env, address, MMU_DATA_STORE, IA64_MMU_DATA_CPL3,
                       false, &result));
    g_assert_cmpint(result.status, ==, IA64_TRANSLATE_ACCESS_DENIED);
    g_assert_cmpstr(result.message, ==, "");
    g_assert_cmphex(result.paddr, ==, 0x0000000004002c00ULL);
}

static void test_fast_exception_delivery_keeps_state_without_message(void)
{
    CPUIA64State env;
    uint64_t psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                                    IA64_TB_PSR_DT_BIT, 2);
    vaddr ip = 0xa00000010015fcf0ULL;
    vaddr address = 0xa000000100002c00ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = psr;
    env.ip = ip;
    env.cr[IA64_CR_IVA] = 0x100000;

    ia64_deliver_exception_fast(&env, IA64_EXCEPTION_PAGE_FAULT, address,
                                MMU_DATA_STORE, "unused fast detail");

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.exception.vector, ==, 0x5000);
    if (g_getenv("VIBTANIUM_EXCEPTION_TRACE") ||
        g_getenv("VIBTANIUM_USER_EXCEPTION_TRACE")) {
        g_assert_nonnull(strstr((const char *)env.exception.message,
                                "unused fast detail"));
    } else {
        g_assert_cmpstr((const char *)env.exception.message, ==, "");
    }
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, ip);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, address);
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 2);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_W_BIT),
                    ==, UINT64_C(1) << IA64_ISR_W_BIT);
}

static void test_translation_fault_vectors(void)
{
    CPUIA64State env;
    IA64TranslateResult result;
    vaddr address = 0x2000000000211a38ULL;

    memset(&result, 0, sizeof(result));
    result.vaddr = address;
    result.status = IA64_TRANSLATE_DIRTY_BIT;
    result.access_type = MMU_DATA_STORE;
    g_assert_cmpint(ia64_exception_for_translate_result(&result), ==,
                    IA64_EXCEPTION_DIRTY_BIT);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_TB_PSR_DT_BIT, 2);
    env.ip = 0x2000000000118400ULL;
    env.cr[IA64_CR_IVA] = 0x100000;
    ia64_deliver_exception(&env, IA64_EXCEPTION_DIRTY_BIT, address,
                           MMU_DATA_STORE, "dirty");
    g_assert_cmphex(env.exception.vector, ==, 0x2000);
    g_assert_cmphex(env.ip, ==, 0x102000);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==,
                    ia64_default_itir(&env, address));
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 2);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_W_BIT),
                    ==, UINT64_C(1) << IA64_ISR_W_BIT);

    result.status = IA64_TRANSLATE_ACCESS_BIT;
    result.access_type = MMU_INST_FETCH;
    g_assert_cmpint(ia64_exception_for_translate_result(&result), ==,
                    IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_TB_PSR_IT_BIT;
    env.ip = 0x2000000000118400ULL;
    env.cr[IA64_CR_IVA] = 0x100000;
    ia64_deliver_exception(&env, IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT,
                           address, MMU_INST_FETCH, "iaccess");
    g_assert_cmphex(env.exception.vector, ==, 0x2400);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, address & ~0xfULL);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_X_BIT),
                    ==, UINT64_C(1) << IA64_ISR_X_BIT);

    result.status = IA64_TRANSLATE_ACCESS_BIT;
    result.access_type = MMU_DATA_LOAD;
    g_assert_cmpint(ia64_exception_for_translate_result(&result), ==,
                    IA64_EXCEPTION_DATA_ACCESS_BIT);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_TB_PSR_DT_BIT;
    env.ip = 0x2000000000118400ULL;
    env.cr[IA64_CR_IVA] = 0x100000;
    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_ACCESS_BIT, address,
                           MMU_DATA_LOAD, "daccess");
    g_assert_cmphex(env.exception.vector, ==, 0x2800);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, env.exception.ip);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, UINT64_C(1) << IA64_ISR_R_BIT);

    result.status = IA64_TRANSLATE_ACCESS_DENIED;
    result.access_type = MMU_DATA_STORE;
    g_assert_cmpint(ia64_exception_for_translate_result(&result), ==,
                    IA64_EXCEPTION_DATA_ACCESS_RIGHTS);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.psr = IA64_PSR_IC_BIT | IA64_TB_PSR_DT_BIT;
    env.ip = 0x2000000000118400ULL;
    env.cr[IA64_CR_IVA] = 0x100000;
    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_ACCESS_RIGHTS, address,
                           MMU_DATA_STORE, "rights");
    g_assert_cmphex(env.exception.vector, ==, 0x5300);
    g_assert_cmphex(env.ip, ==, 0x105300);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_W_BIT),
                    ==, UINT64_C(1) << IA64_ISR_W_BIT);
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
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, UINT64_C(1) << IA64_ISR_R_BIT);

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

static void test_interruption_delivery_preserves_translation_bits(void)
{
    CPUIA64State env;
    uint64_t preserved = IA64_TB_PSR_DT_BIT | IA64_TB_PSR_IT_BIT |
                         IA64_PSR_RT_BIT;
    uint64_t psr = ia64_psr_with_ri(IA64_PSR_IC_BIT | IA64_PSR_I_BIT |
                                    IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK |
                                    preserved, 2);

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0xe0000000049acc10ULL;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0xe000000004400000ULL;

    ia64_deliver_exception(&env, IA64_EXCEPTION_EXTERNAL_INTERRUPT, env.ip,
                           MMU_DATA_LOAD, "external interrupt");

    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_EXTERNAL_INTERRUPT);
    g_assert_cmphex(env.exception.vector, ==, 0x3000);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.ip, ==, 0xe000000004403000ULL);
    assert_delivery_psr(&env, preserved);
    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(env.psr, true), ==,
                    IA64_MMU_INST_CPL0);
    g_assert_cmpint(ia64_tcg_mmu_index_for_psr(env.psr, false), ==,
                    IA64_MMU_DATA_CPL0);
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
    env.cr[IA64_CR_IFS] = 0x8000000000003333ULL;

    ia64_deliver_exception(&env, IA64_EXCEPTION_INSTRUCTION_TLB_MISS,
                           miss, MMU_INST_FETCH, "test itlb miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==,
                    IA64_EXCEPTION_INSTRUCTION_TLB_MISS);
    g_assert_cmphex(env.exception.vector, ==, 0x0400);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, 0);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, ia64_default_itir(&env, miss));
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==,
                    ia64_vhpt_hash_address(&env, miss));
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_X_BIT),
                    ==, UINT64_C(1) << IA64_ISR_X_BIT);
    g_assert_cmphex(env.ip, ==, 0x100400);
    assert_delivery_psr(&env, 0);
}

static void test_vhpt_translation_vectors_to_iva(void)
{
    CPUIA64State env;
    uint64_t psr = UINT64_C(0x0000100300006000);
    vaddr miss = 0xa000000100002c00ULL;
    uint64_t expected_iha;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0xa000000100001470ULL;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.cr[IA64_CR_PTA] = (20ULL << 2) | (1ULL << 15) | 1ULL;
    expected_iha = ia64_vhpt_hash_address(&env, miss);

    ia64_deliver_exception(&env, IA64_EXCEPTION_VHPT_TRANSLATION,
                           miss, MMU_DATA_LOAD, "test vhpt translation");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_VHPT_TRANSLATION);
    g_assert_cmphex(env.exception.vector, ==, 0x0000);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, 0xa000000100001470ULL);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, expected_iha);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==,
                    ia64_default_itir(&env, expected_iha));
    g_assert_cmphex(env.ip, ==, 0x100000);
    assert_delivery_psr(&env, 0);
}

static void test_alternate_tlb_miss_delivery_vectors_to_iva(void)
{
    CPUIA64State env;
    uint64_t psr = UINT64_C(0x0000100300006000);
    vaddr miss = 0xa000000100002c00ULL;
    uint64_t saved_iha = 0x12345678;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = miss;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.cr[IA64_CR_IHA] = saved_iha;

    ia64_deliver_exception(&env,
                           IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS,
                           miss, MMU_INST_FETCH, "test alt itlb miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==,
                    IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS);
    g_assert_cmphex(env.exception.vector, ==, 0x0c00);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, miss);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, ia64_default_itir(&env, miss));
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, saved_iha);
    g_assert_cmphex(env.ip, ==, 0x100c00);
}

static void test_data_tlb_miss_records_slot_and_access(void)
{
    CPUIA64State env;
    uint64_t psr = ia64_psr_with_ri(UINT64_C(0x0000100300006000), 2);
    vaddr ip = 0xa00000010015fcf0ULL;
    vaddr miss = 0xa0007fffffc88c98ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;

    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_TLB_MISS, miss,
                           MMU_DATA_STORE, "test dtlb store miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_DATA_TLB_MISS);
    g_assert_cmphex(env.exception.vector, ==, 0x0800);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmpuint(ia64_psr_ri(env.cr[IA64_CR_IPSR]), ==, 2);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, ip);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, miss);
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 2);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_W_BIT),
                    ==, UINT64_C(1) << IA64_ISR_W_BIT);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, 0);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_X_BIT),
                    ==, 0);
    g_assert_cmphex(env.ip, ==, 0x100800);
    assert_delivery_psr(&env, 0);
}

static void test_register_nat_consumption_delivery_vectors_to_iva(void)
{
    CPUIA64State env;
    uint64_t psr = ia64_psr_with_ri(UINT64_C(0x0000100300006000), 1);
    vaddr ip = 0xa00000010015fcf0ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = ip;
    env.psr = psr;
    env.cr[IA64_CR_IVA] = 0x100000;

    ia64_deliver_exception(&env, IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION,
                           ip, MMU_DATA_LOAD, "register NaT");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==,
                    IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION);
    g_assert_cmphex(env.exception.vector, ==, 0x5600);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, psr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, ip);
    g_assert_cmphex((env.cr[IA64_CR_ISR] & IA64_ISR_EI_MASK) >>
                    IA64_ISR_EI_SHIFT, ==, 1);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & IA64_ISR_CODE_MASK,
                    ==, IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION);
    g_assert_cmphex(env.cr[IA64_CR_ISR] & (UINT64_C(1) << IA64_ISR_R_BIT),
                    ==, UINT64_C(1) << IA64_ISR_R_BIT);
    g_assert_cmphex(env.ip, ==, 0x105600);
    assert_delivery_psr(&env, 0);
}

static void test_non_nested_exception_with_ic_clear_preserves_collection_state(void)
{
    CPUIA64State env;
    uint64_t saved_ipsr = 0x1111;
    uint64_t saved_iip = 0xcafe0;
    uint64_t saved_iipa = 0x2222;
    uint64_t saved_ifs = 0x3333;
    uint64_t saved_ifa = 0x5555;
    uint64_t saved_itir = 0x6666;
    uint64_t saved_iha = 0x7777;
    uint64_t saved_iim = 0x8888;
    uint64_t expected_isr = (UINT64_C(2) << IA64_ISR_EI_SHIFT) |
                            (UINT64_C(1) << IA64_ISR_W_BIT) |
                            (UINT64_C(1) << IA64_ISR_NI_BIT);
    vaddr fault_ip = 0xa00000010015fcf0ULL;
    vaddr fault_addr = 0xa0007fffffc88c98ULL;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = fault_ip;
    env.psr = ia64_psr_with_ri(IA64_PSR_I_BIT | IA64_PSR_BN_BIT |
                               IA64_PSR_CPL_MASK, 2);
    env.cr[IA64_CR_IVA] = 0x100000;
    env.cr[IA64_CR_IPSR] = saved_ipsr;
    env.cr[IA64_CR_IIP] = saved_iip;
    env.cr[IA64_CR_IIPA] = saved_iipa;
    env.cr[IA64_CR_IFS] = saved_ifs;
    env.cr[IA64_CR_IFA] = saved_ifa;
    env.cr[IA64_CR_ITIR] = saved_itir;
    env.cr[IA64_CR_IHA] = saved_iha;
    env.cr[IA64_CR_IIM] = saved_iim;

    ia64_deliver_exception(&env, IA64_EXCEPTION_PAGE_FAULT, fault_addr,
                           MMU_DATA_STORE, "page fault with ic clear");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_PAGE_FAULT);
    g_assert_cmphex(env.exception.vector, ==, 0x5000);
    g_assert_cmphex(env.ip, ==, 0x105000);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, saved_ipsr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, saved_iip);
    g_assert_cmphex(env.cr[IA64_CR_IIPA], ==, saved_iipa);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, saved_ifa);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, saved_itir);
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, saved_iha);
    g_assert_cmphex(env.cr[IA64_CR_IIM], ==, saved_iim);
    g_assert_cmphex(env.cr[IA64_CR_ISR], ==, expected_isr);
    assert_delivery_psr(&env, 0);
}

static void test_data_tlb_miss_with_ic_clear_vectors_to_nested(void)
{
    CPUIA64State env;
    uint64_t saved_ipsr = 0x1111;
    uint64_t saved_iip = 0xcafe0;
    uint64_t saved_iipa = 0x2222;
    uint64_t saved_ifs = 0x3333;
    uint64_t saved_isr = 0x4444;
    uint64_t saved_ifa = 0x5555;
    uint64_t saved_itir = 0x6666;
    uint64_t saved_iha = 0x7777;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x12340;
    env.psr = IA64_PSR_I_BIT | IA64_PSR_RI_MASK |
              IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.cr[IA64_CR_IPSR] = saved_ipsr;
    env.cr[IA64_CR_IIP] = saved_iip;
    env.cr[IA64_CR_IIPA] = saved_iipa;
    env.cr[IA64_CR_IFS] = saved_ifs;
    env.cr[IA64_CR_ISR] = saved_isr;
    env.cr[IA64_CR_IFA] = saved_ifa;
    env.cr[IA64_CR_ITIR] = saved_itir;
    env.cr[IA64_CR_IHA] = saved_iha;

    ia64_deliver_exception(&env, IA64_EXCEPTION_DATA_TLB_MISS, 0x70,
                           MMU_DATA_LOAD, "nested data miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_DATA_NESTED_TLB);
    g_assert_cmphex(env.exception.vector, ==, 0x1400);
    g_assert_cmphex(env.ip, ==, 0x101400);
    g_assert_cmphex(env.cr[IA64_CR_IPSR], ==, saved_ipsr);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, saved_iip);
    g_assert_cmphex(env.cr[IA64_CR_IIPA], ==, saved_iipa);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, saved_ifs);
    g_assert_cmphex(env.cr[IA64_CR_ISR], ==, saved_isr);
    g_assert_cmphex(env.cr[IA64_CR_IFA], ==, saved_ifa);
    g_assert_cmphex(env.cr[IA64_CR_ITIR], ==, saved_itir);
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, saved_iha);
    assert_delivery_psr(&env, 0);
}

static void test_alternate_data_tlb_miss_with_ic_clear_vectors_to_nested(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.ip = 0x12340;
    env.psr = IA64_PSR_I_BIT | IA64_PSR_RI_MASK |
              IA64_PSR_BN_BIT | IA64_PSR_CPL_MASK;
    env.cr[IA64_CR_IVA] = 0x100000;
    env.cr[IA64_CR_IPSR] = 0x1111;
    env.cr[IA64_CR_IIP] = 0xcafe0;
    env.cr[IA64_CR_IHA] = 0x7777;

    ia64_deliver_exception(&env, IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS,
                           0x70, MMU_DATA_LOAD, "nested alt data miss");

    g_assert_true(env.exception.pending);
    g_assert_cmpint(env.exception.kind, ==, IA64_EXCEPTION_DATA_NESTED_TLB);
    g_assert_cmphex(env.exception.vector, ==, 0x1400);
    g_assert_cmphex(env.ip, ==, 0x101400);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, 0xcafe0);
    g_assert_cmphex(env.cr[IA64_CR_IHA], ==, 0x7777);
    assert_delivery_psr(&env, 0);
}

static void test_restore_ri_prefers_dirty_slot(void)
{
    CPUIA64State env;

    ia64_cpu_reset_synthetic_itanium2(&env);

    /* Without a helper-published slot, insn_start data wins. */
    ia64_env_set_psr(&env, ia64_psr_with_ri(IA64_PSR_IC_BIT, 0));
    g_assert_cmpuint(ia64_env_restore_ri(&env, 1), ==, 1);

    /* A slot helper (interpreter loop, fast load/store) is more precise. */
    ia64_env_set_ri(&env, 2);
    g_assert_cmpuint(ia64_env_restore_ri(&env, 0), ==, 2);

    /* Bundle retirement publishes PSR.ri and re-arms insn_start data. */
    ia64_env_set_psr(&env, ia64_psr_with_ri(ia64_env_psr(&env), 0));
    g_assert_cmpuint(ia64_env_restore_ri(&env, 1), ==, 1);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-memory/identity-debug-path",
                    test_identity_debug_memory_path);
    g_test_add_func("/ia64-memory/physical-region-alias",
                    test_physical_region_alias_path);
    g_test_add_func("/ia64-memory/instruction-exception-deferral",
                    test_instruction_translation_reports_exception_deferral);
    g_test_add_func("/ia64-exception/speculative-load-isr-sp-ed",
                    test_speculative_load_exception_records_isr_sp_ed);
    g_test_add_func("/ia64-memory/control-speculative-load-deferral-policy",
                    test_control_speculative_load_deferral_policy);
    g_test_add_func("/ia64-memory/tcg-tb-flags-mmu-index-cpl",
                    test_tcg_tb_flags_and_mmu_indexes_include_cpl);
    g_test_add_func("/ia64-memory/translated-miss",
                    test_translated_address_misses_without_entry);
    g_test_add_func("/ia64-memory/translated-vhpt-miss",
                    test_translated_address_vhpt_miss_reports_region_mode);
    g_test_add_func("/ia64-memory/instruction-translation-register",
                    test_instruction_translation_register_lookup);
    g_test_add_func("/ia64-memory/tc-preserves-pinned-tr",
                    test_translation_cache_preserves_pinned_register);
    g_test_add_func("/ia64-memory/lookup-cache-refreshes-after-install",
                    test_translation_lookup_cache_refreshes_after_install);
    g_test_add_func("/ia64-memory/region-register-rid-change",
                    test_region_register_change_selects_new_rid);
    g_test_add_func("/ia64-memory/firmware-identity-tlb-assist-data",
                    test_firmware_identity_tlb_assist_installs_data_tc);
    g_test_add_func("/ia64-memory/cr-iva-write-disables-firmware-assist",
                    test_cr_iva_write_masks_base_and_disables_firmware_assist);
    g_test_add_func("/ia64-memory/tc-purge-same-va-remap",
                    test_translation_cache_purge_and_same_va_remap);
    g_test_add_func("/ia64-memory/host-tlb-flush-span",
                    test_host_tlb_flush_span_for_ia64_page);
    g_test_add_func("/ia64-memory/tr-purge-pinned-entry",
                    test_translation_register_purge_removes_pinned_entry);
    g_test_add_func("/ia64-memory/demand-data-page-fault",
                    test_demand_data_page_fault_delivery);
    g_test_add_func("/ia64-memory/user-store-protection-page-fault",
                    test_user_store_protection_page_fault_preserves_slot);
    g_test_add_func("/ia64-memory/instruction-fetch-page-fault",
                    test_instruction_fetch_page_fault_sets_fault_ip);
    g_test_add_func("/ia64-memory/no-detail-translation",
                    test_no_detail_translation_keeps_status_without_message);
    g_test_add_func("/ia64-exception/fast-delivery",
                    test_fast_exception_delivery_keeps_state_without_message);
    g_test_add_func("/ia64-exception/translation-fault-vectors",
                    test_translation_fault_vectors);
    g_test_add_func("/ia64-exception/reporting", test_exception_reporting);
    g_test_add_func("/ia64-exception/delivery-preserves-translation-bits",
                    test_interruption_delivery_preserves_translation_bits);
    g_test_add_func("/ia64-exception/tlb-miss-delivery",
                    test_tlb_miss_delivery_vectors_to_iva);
    g_test_add_func("/ia64-exception/vhpt-translation-delivery",
                    test_vhpt_translation_vectors_to_iva);
    g_test_add_func("/ia64-exception/alternate-tlb-miss-delivery",
                    test_alternate_tlb_miss_delivery_vectors_to_iva);
    g_test_add_func("/ia64-exception/data-tlb-miss-slot-and-access",
                    test_data_tlb_miss_records_slot_and_access);
    g_test_add_func("/ia64-exception/register-nat-consumption-delivery",
                    test_register_nat_consumption_delivery_vectors_to_iva);
    g_test_add_func("/ia64-exception/ic-clear-preserves-collection-state",
                    test_non_nested_exception_with_ic_clear_preserves_collection_state);
    g_test_add_func("/ia64-exception/data-nested-tlb-delivery",
                    test_data_tlb_miss_with_ic_clear_vectors_to_nested);
    g_test_add_func("/ia64-exception/alternate-data-nested-tlb-delivery",
                    test_alternate_data_tlb_miss_with_ic_clear_vectors_to_nested);
    g_test_add_func("/ia64-exception/restore-ri-prefers-dirty-slot",
                    test_restore_ri_prefers_dirty_slot);

    return g_test_run();
}
