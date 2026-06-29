/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_EXCEPTION_H
#define IA64_EXCEPTION_H

#include "cpu.h"

typedef struct IA64TranslateResult IA64TranslateResult;

const char *ia64_exception_name(IA64ExceptionKind kind);
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
void ia64_format_exception(const IA64ExceptionRecord *record,
                           char *buf, size_t buflen);

#endif
