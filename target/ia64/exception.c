/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"

const char *ia64_exception_name(IA64ExceptionKind kind)
{
    switch (kind) {
    case IA64_EXCEPTION_NONE:
        return "none";
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
    case IA64_EXCEPTION_ILLEGAL_OPERATION:
        record->vector = 0x24;
        break;
    case IA64_EXCEPTION_PAGE_FAULT:
        record->vector = 0x14;
        break;
    case IA64_EXCEPTION_GENERAL_EXCEPTION:
        record->vector = 0x28;
        break;
    case IA64_EXCEPTION_BREAK:
        record->vector = 0x2c;
        break;
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        record->vector = 0x30;
        break;
    case IA64_EXCEPTION_NONE:
    default:
        record->vector = 0;
        break;
    }

    snprintf(record->message, sizeof(record->message),
             "%s at ip=0x%016" VADDR_PRIx " address=0x%016" VADDR_PRIx
             " access=%d%s%s",
             ia64_exception_name(kind), record->ip, record->address,
             access_type, detail ? " " : "", detail ? detail : "");

    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_IIPA] = address;
    env->cr[IA64_CR_ISR] = access_type;
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
             record->pending ? "yes" : "no", record->message);
}
