/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_EXCEPTION_H
#define IA64_EXCEPTION_H

#include "cpu.h"

typedef struct IA64TranslateResult IA64TranslateResult;

/* IA64ExceptionRecord.access_type for interruptions with no memory access. */
#define IA64_EXCEPTION_ACCESS_NONE (-1)
/* Semaphore references are architecturally both reads and writes. */
#define IA64_EXCEPTION_ACCESS_SEMAPHORE (-2)
/*
 * A NaT'ed address operand is consumed before a memory transaction occurs.
 * Such Register NaT Consumption faults retain the operation's R/W class but
 * additionally report the architected non-access bit in ISR.na.
 */
#define IA64_EXCEPTION_ACCESS_READ_NON_ACCESS (-3)
#define IA64_EXCEPTION_ACCESS_WRITE_NON_ACCESS (-4)
#define IA64_EXCEPTION_ACCESS_SEMAPHORE_NON_ACCESS (-5)
/*
 * Architecturally identified read/non-access instructions.  Unlike the
 * generic descriptor above, these also supply ISR.code{3:0} from Table 5-1:
 * fc/fc.i use code 1 and lfetch.fault uses code 4.
 */
#define IA64_EXCEPTION_ACCESS_FC_READ_NON_ACCESS (-6)
#define IA64_EXCEPTION_ACCESS_LFETCH_FAULT_READ_NON_ACCESS (-7)

const char *ia64_exception_name(IA64ExceptionKind kind);
bool ia64_interruption_collection_enabled(uint64_t psr);
bool ia64_interruption_sets_ni(uint64_t psr, bool psr_ic_inflight);
bool ia64_data_tlb_miss_is_nested(uint64_t psr, bool psr_ic_inflight,
                                  IA64ExceptionKind kind,
                                  MMUAccessType access_type);
IA64ExceptionKind
ia64_exception_for_translate_result(const IA64TranslateResult *result);
void ia64_clear_exception(CPUIA64State *env);
void ia64_record_exception(CPUIA64State *env, IA64ExceptionKind kind,
                           vaddr address, int32_t access_type,
                           const char *detail);
void ia64_deliver_exception(CPUIA64State *env, IA64ExceptionKind kind,
                            vaddr address, int32_t access_type,
                            const char *detail);
void ia64_deliver_exception_fast(CPUIA64State *env, IA64ExceptionKind kind,
                                 vaddr address, int32_t access_type,
                                 const char *detail);
G_NORETURN void ia64_raise_data_plane_exception(
    CPUIA64State *env, IA64ExceptionKind kind, vaddr address,
    int32_t access_type);
G_NORETURN void ia64_raise_arch_register_nat_consumption(
    CPUIA64State *env, MMUAccessType access_type, const char *detail);
G_NORETURN void ia64_raise_arch_unaligned_data_reference(
    CPUIA64State *env, vaddr address, MMUAccessType access_type);
G_NORETURN void ia64_raise_arch_translation_fault(
    CPUIA64State *env, const IA64TranslateResult *result);
void ia64_deliver_illegal_operation_fast(CPUIA64State *env);
/* Deliver a post-branch trap after env already contains the branch target. */
void ia64_deliver_branch_trap(CPUIA64State *env, IA64ExceptionKind kind);
void ia64_format_exception(const IA64ExceptionRecord *record,
                           char *buf, size_t buflen);

#endif
