/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_MEM_H
#define IA64_MEM_H

#include "cpu.h"

typedef enum IA64TranslateStatus {
    IA64_TRANSLATE_OK,
    IA64_TRANSLATE_BAD_ADDRESS,
    IA64_TRANSLATE_UNIMPLEMENTED,
    IA64_TRANSLATE_TLB_MISS,
    IA64_TRANSLATE_NOT_PRESENT,
    IA64_TRANSLATE_ACCESS_DENIED,
} IA64TranslateStatus;

typedef struct IA64TranslateResult {
    IA64TranslateStatus status;
    vaddr vaddr;
    hwaddr paddr;
    uint8_t region;
    int prot;
    int mmu_idx;
    MMUAccessType access_type;
    uint8_t page_size;
    bool debug;
    bool identity;
    bool vhpt_enabled;
    char message[160];
} IA64TranslateResult;

const char *ia64_translate_status_name(IA64TranslateStatus status);
uint8_t ia64_va_region(vaddr address);
uint32_t ia64_region_id(uint64_t rr);
bool ia64_region_vhpt_enabled(uint64_t rr);
bool ia64_page_size_supported(uint8_t page_size);
uint8_t ia64_region_page_size(uint64_t rr);
uint64_t ia64_default_itir(CPUIA64State *env, vaddr address);
uint64_t ia64_vhpt_hash_address(CPUIA64State *env, vaddr address);
uint64_t ia64_vhpt_tag(CPUIA64State *env, vaddr address);
bool ia64_install_translation(CPUIA64State *env, bool instruction,
                              bool pinned, uint8_t slot,
                              vaddr virtual_address,
                              uint64_t translation_format,
                              uint64_t itir);
void ia64_purge_translation_cache(CPUIA64State *env, vaddr address,
                                  uint8_t page_size);
void ia64_purge_translation_register(CPUIA64State *env, bool instruction,
                                     vaddr address, uint8_t page_size);
void ia64_purge_all_translation_cache(CPUIA64State *env);
bool ia64_translate_data_non_access(CPUIA64State *env, vaddr address,
                                    hwaddr *paddr);
bool ia64_translate_address(CPUIA64State *env, vaddr address,
                            MMUAccessType access_type, int mmu_idx,
                            bool debug, IA64TranslateResult *result);
void ia64_format_translate_result(const IA64TranslateResult *result,
                                  char *buf, size_t buflen);

#endif
