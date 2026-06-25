/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_MEM_H
#define IA64_MEM_H

#include "cpu.h"

typedef enum IA64TranslateStatus {
    IA64_TRANSLATE_OK,
    IA64_TRANSLATE_BAD_ADDRESS,
    IA64_TRANSLATE_UNIMPLEMENTED,
} IA64TranslateStatus;

typedef struct IA64TranslateResult {
    IA64TranslateStatus status;
    vaddr vaddr;
    hwaddr paddr;
    uint8_t region;
    int prot;
    int mmu_idx;
    MMUAccessType access_type;
    bool debug;
    bool identity;
    char message[160];
} IA64TranslateResult;

const char *ia64_translate_status_name(IA64TranslateStatus status);
uint8_t ia64_va_region(vaddr address);
bool ia64_translate_address(CPUIA64State *env, vaddr address,
                            MMUAccessType access_type, int mmu_idx,
                            bool debug, IA64TranslateResult *result);
void ia64_format_translate_result(const IA64TranslateResult *result,
                                  char *buf, size_t buflen);

#endif
