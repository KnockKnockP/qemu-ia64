/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_EXCEPTION_H
#define IA64_EXCEPTION_H

#include "cpu.h"

typedef struct IA64TranslateResult IA64TranslateResult;

/* IA64ExceptionRecord.access_type for interruptions with no memory access. */
#define IA64_EXCEPTION_ACCESS_NONE (-1)

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
                           vaddr address, MMUAccessType access_type,
                           const char *detail);
void ia64_deliver_exception(CPUIA64State *env, IA64ExceptionKind kind,
                            vaddr address, MMUAccessType access_type,
                            const char *detail);
void ia64_deliver_exception_fast(CPUIA64State *env, IA64ExceptionKind kind,
                                 vaddr address, MMUAccessType access_type,
                                 const char *detail);
void ia64_deliver_illegal_operation_fast(CPUIA64State *env);
/* Deliver a post-branch trap after env already contains the branch target. */
void ia64_deliver_branch_trap(CPUIA64State *env, IA64ExceptionKind kind);
void ia64_format_exception(const IA64ExceptionRecord *record,
                           char *buf, size_t buflen);

#endif
