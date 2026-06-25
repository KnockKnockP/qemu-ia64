/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_EXEC_SMOKE_H
#define IA64_EXEC_SMOKE_H

#include "cpu.h"
#include "bundle.h"

#define IA64_SMOKE_NOP_RAW 0x08000000ULL

typedef enum IA64ExecSmokeStatus {
    IA64_EXEC_SMOKE_OK,
    IA64_EXEC_SMOKE_RESERVED_TEMPLATE,
    IA64_EXEC_SMOKE_UNSUPPORTED_SLOT,
} IA64ExecSmokeStatus;

typedef struct IA64ExecSmokeReport {
    IA64ExecSmokeStatus status;
    IA64DecodedBundle bundle;
    uint64_t ip_before;
    uint64_t ip_after;
    int failed_slot;
    char message[160];
} IA64ExecSmokeReport;

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env);

const char *ia64_exec_smoke_status_name(IA64ExecSmokeStatus status);
bool ia64_exec_smoke_slot_supported(IA64SlotType type, uint64_t raw);
IA64ExecSmokeStatus
ia64_exec_smoke_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64ExecSmokeReport *report);

#endif
