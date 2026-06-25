/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exec-smoke.h"

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env)
{
    memset(env, 0, offsetof(CPUIA64State, end_reset_fields));

    /*
     * Synthetic reset: enough for a stable placeholder CPU, not yet validated
     * against PAL/SAL-visible Itanium 2 reset state.
     */
    env->pr = 1;
    env->gr[0] = 0;
    env->ip = 0;
    env->psr = 0;
    env->cfm = 0;

    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
    env->ar[IA64_AR_UNAT] = env->nat.unat;
    env->ar[IA64_AR_PFS] = 0;
    env->ar[IA64_AR_FPSR] = 0;

    env->cr[IA64_CR_IPSR] = env->psr;
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFS] = env->cfm;
}

const char *ia64_exec_smoke_status_name(IA64ExecSmokeStatus status)
{
    switch (status) {
    case IA64_EXEC_SMOKE_OK:
        return "ok";
    case IA64_EXEC_SMOKE_RESERVED_TEMPLATE:
        return "reserved-template";
    case IA64_EXEC_SMOKE_UNSUPPORTED_SLOT:
        return "unsupported-slot";
    default:
        return "unknown";
    }
}

bool ia64_exec_smoke_slot_supported(IA64SlotType type, uint64_t raw)
{
    switch (type) {
    case IA64_SLOT_TYPE_M:
    case IA64_SLOT_TYPE_I:
        return raw == IA64_SMOKE_NOP_RAW;
    default:
        return false;
    }
}

static void ia64_exec_smoke_set_message(IA64ExecSmokeReport *report,
                                        const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

static void ia64_exec_smoke_set_message(IA64ExecSmokeReport *report,
                                        const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(report->message, sizeof(report->message), fmt, ap);
    va_end(ap);
}

IA64ExecSmokeStatus
ia64_exec_smoke_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64ExecSmokeReport *report)
{
    memset(report, 0, sizeof(*report));
    report->failed_slot = -1;
    report->ip_before = env->ip;
    report->ip_after = env->ip;

    ia64_decode_bundle(bundle, &report->bundle);

    if (!report->bundle.valid) {
        report->status = IA64_EXEC_SMOKE_RESERVED_TEMPLATE;
        ia64_exec_smoke_set_message(
            report,
            "reserved IA-64 template 0x%02x at ip=0x%016" PRIx64,
            report->bundle.tmpl, report->ip_before);
        return report->status;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = report->bundle.info->slot_type[slot];
        uint64_t raw = report->bundle.slot[slot];

        if (!ia64_exec_smoke_slot_supported(type, raw)) {
            report->status = IA64_EXEC_SMOKE_UNSUPPORTED_SLOT;
            report->failed_slot = slot;
            ia64_exec_smoke_set_message(
                report,
                "unsupported IA-64 smoke instruction at ip=0x%016" PRIx64
                " slot=%d type=%s raw=0x%011" PRIx64
                " template=0x%02x %s",
                report->ip_before, slot, ia64_slot_type_name(type), raw,
                report->bundle.tmpl, report->bundle.info->name);
            return report->status;
        }
    }

    env->ip += IA64_BUNDLE_SIZE;
    report->status = IA64_EXEC_SMOKE_OK;
    report->ip_after = env->ip;
    ia64_exec_smoke_set_message(
        report,
        "executed IA-64 smoke NOP bundle at ip=0x%016" PRIx64
        " next=0x%016" PRIx64,
        report->ip_before, report->ip_after);

    return report->status;
}
