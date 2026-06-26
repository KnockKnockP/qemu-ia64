/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"
#include "trace-target_ia64.h"

#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT  UINT64_C(0x0000000000004000)
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PSR_RI_MASK  UINT64_C(0x0000060000000000)
#define IA64_PSR_BN_BIT   UINT64_C(0x0000100000000000)

static bool ia64_exception_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EXCEPTION_TRACE") != NULL;
    }
    return enabled != 0;
}

const char *ia64_exception_name(IA64ExceptionKind kind)
{
    switch (kind) {
    case IA64_EXCEPTION_NONE:
        return "none";
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
        return "instruction-tlb-miss";
    case IA64_EXCEPTION_DATA_TLB_MISS:
        return "data-tlb-miss";
    case IA64_EXCEPTION_ILLEGAL_OPERATION:
        return "illegal-operation";
    case IA64_EXCEPTION_PAGE_FAULT:
        return "page-fault";
    case IA64_EXCEPTION_GENERAL_EXCEPTION:
        return "general-exception";
    case IA64_EXCEPTION_BREAK:
        return "break";
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        return "external-interrupt";
    default:
        return "unknown";
    }
}

void ia64_clear_exception(CPUIA64State *env)
{
    memset(&env->exception, 0, sizeof(env->exception));
}

void ia64_record_exception(CPUIA64State *env, IA64ExceptionKind kind,
                           vaddr address, MMUAccessType access_type,
                           const char *detail)
{
    IA64ExceptionRecord *record = &env->exception;

    memset(record, 0, sizeof(*record));
    record->kind = kind;
    record->ip = env->ip;
    record->address = address;
    record->access_type = access_type;
    record->pending = kind != IA64_EXCEPTION_NONE;

    switch (kind) {
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
        record->vector = 0x0400;
        break;
    case IA64_EXCEPTION_DATA_TLB_MISS:
        record->vector = 0x0800;
        break;
    case IA64_EXCEPTION_ILLEGAL_OPERATION:
        record->vector = 0x5400;
        break;
    case IA64_EXCEPTION_PAGE_FAULT:
        record->vector = 0x5000;
        break;
    case IA64_EXCEPTION_GENERAL_EXCEPTION:
        record->vector = 0x5400;
        break;
    case IA64_EXCEPTION_BREAK:
        record->vector = 0x2c00;
        break;
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        record->vector = 0x3000;
        break;
    case IA64_EXCEPTION_NONE:
    default:
        record->vector = 0;
        break;
    }

    snprintf((char *)record->message, sizeof(record->message),
             "%s at ip=0x%016" VADDR_PRIx " address=0x%016" VADDR_PRIx
             " access=%d%s%s",
             ia64_exception_name(kind), record->ip, record->address,
             access_type, detail ? " " : "", detail ? detail : "");

    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_IIPA] = address;
    env->cr[IA64_CR_ISR] = access_type;
}

void ia64_deliver_exception(CPUIA64State *env, IA64ExceptionKind kind,
                            vaddr address, MMUAccessType access_type,
                            const char *detail)
{
    uint64_t source_ip = env->ip;

    ia64_record_exception(env, kind, address, access_type, detail);

    env->cr[IA64_CR_IPSR] = env->psr;
    env->cr[IA64_CR_IIP] = access_type == MMU_INST_FETCH ?
                           (address & ~0xfULL) : env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_ISR] = access_type;

    env->psr &= ~(IA64_PSR_I_BIT | IA64_PSR_IC_BIT |
                  IA64_PSR_BN_BIT | IA64_PSR_RI_MASK |
                  IA64_PSR_CPL_MASK);
    env->ip = env->cr[IA64_CR_IVA] + env->exception.vector;
    env->cr[IA64_CR_IIP] &= ~0xfULL;

    trace_ia64_exception_deliver(ia64_exception_name(kind), source_ip,
                                 address, env->exception.vector, env->ip,
                                 env->cr[IA64_CR_IPSR],
                                 env->cr[IA64_CR_IIP],
                                 env->cr[IA64_CR_IFA],
                                 env->cr[IA64_CR_ISR], env->psr);
    if (ia64_exception_trace_enabled()) {
        fprintf(stderr,
                "[ia64-exception] kind=%s ip=0x%016" PRIx64
                " address=0x%016" PRIx64 " vector=0x%04" PRIx64
                " target=0x%016" PRIx64 " ipsr=0x%016" PRIx64
                " iip=0x%016" PRIx64 " ifa=0x%016" PRIx64
                " isr=0x%016" PRIx64 " psr=0x%016" PRIx64 "\n",
                ia64_exception_name(kind), source_ip, address,
                env->exception.vector, env->ip, env->cr[IA64_CR_IPSR],
                env->cr[IA64_CR_IIP], env->cr[IA64_CR_IFA],
                env->cr[IA64_CR_ISR], env->psr);
    }
}

void ia64_format_exception(const IA64ExceptionRecord *record,
                           char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "kind=%s vector=0x%02" PRIx64 " ip=0x%016" VADDR_PRIx
             " address=0x%016" VADDR_PRIx " access=%d pending=%s"
             " message=\"%s\"",
             ia64_exception_name(record->kind), record->vector,
             record->ip, record->address, record->access_type,
             record->pending ? "yes" : "no",
             (const char *)record->message);
}
