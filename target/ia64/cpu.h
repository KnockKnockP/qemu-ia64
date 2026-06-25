/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_CPU_H
#define IA64_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"

typedef struct CPUArchState {
    uint64_t gr[128];
    uint64_t br[8];
    uint64_t ip;
    uint64_t psr;
    uint64_t cfm;
    uint64_t pr;

    struct {} end_reset_fields;
} CPUIA64State;

struct ArchCPU {
    CPUState parent_obj;

    CPUIA64State env;
};

#define CPU_RESOLVING_TYPE TYPE_IA64_CPU

void ia64_translate_init(void);
void ia64_translate_code(CPUState *cs, TranslationBlock *tb, int *max_insns,
                         vaddr pc, void *host_pc);

void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags);
hwaddr ia64_cpu_get_phys_addr_debug(CPUState *cs, vaddr addr);
bool ia64_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr);
int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n);
int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n);

#endif
