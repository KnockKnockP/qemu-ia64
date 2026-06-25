/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "mem.h"
#include "exec/page-protection.h"

const char *ia64_translate_status_name(IA64TranslateStatus status)
{
    switch (status) {
    case IA64_TRANSLATE_OK:
        return "ok";
    case IA64_TRANSLATE_BAD_ADDRESS:
        return "bad-address";
    case IA64_TRANSLATE_UNIMPLEMENTED:
        return "unimplemented";
    default:
        return "unknown";
    }
}

uint8_t ia64_va_region(vaddr address)
{
    return address >> 61;
}

bool ia64_translate_address(CPUIA64State *env, vaddr address,
                            MMUAccessType access_type, int mmu_idx,
                            bool debug, IA64TranslateResult *result)
{
    memset(result, 0, sizeof(*result));
    result->vaddr = address;
    result->region = ia64_va_region(address);
    result->access_type = access_type;
    result->mmu_idx = mmu_idx;
    result->debug = debug;

    if (result->region != 0) {
        result->status = IA64_TRANSLATE_BAD_ADDRESS;
        snprintf(result->message, sizeof(result->message),
                 "region %u translation is not implemented for "
                 "address=0x%016" VADDR_PRIx,
                 result->region, address);
    } else {
        result->status = IA64_TRANSLATE_OK;
        result->paddr = address;
        result->prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        result->identity = true;
        snprintf(result->message, sizeof(result->message),
                 "phase6 identity translation address=0x%016" VADDR_PRIx,
                 address);
    }

    env->memory.last_vaddr = result->vaddr;
    env->memory.last_paddr = result->paddr;
    env->memory.last_region = result->region;
    env->memory.last_status = result->status;
    env->memory.identity_region0_only = true;

    return result->status == IA64_TRANSLATE_OK;
}

void ia64_format_translate_result(const IA64TranslateResult *result,
                                  char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "status=%s vaddr=0x%016" VADDR_PRIx
             " paddr=0x%016" HWADDR_PRIx " region=%u prot=0x%x"
             " access=%d mmu=%d debug=%s identity=%s message=\"%s\"",
             ia64_translate_status_name(result->status), result->vaddr,
             result->paddr, result->region, result->prot,
             result->access_type, result->mmu_idx,
             result->debug ? "yes" : "no",
             result->identity ? "yes" : "no", result->message);
}
