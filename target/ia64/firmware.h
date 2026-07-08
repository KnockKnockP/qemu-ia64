/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_FIRMWARE_H
#define IA64_FIRMWARE_H

#include "cpu.h"

#define IA64_FIRMWARE_EFI_CALL_GATE_BASE UINT64_C(0x00085000)
#define IA64_FIRMWARE_EFI_START_IMAGE_RETURN_GATE UINT64_C(0x00085600)
#define IA64_FIRMWARE_EFI_PAL_PROC       UINT64_C(0x00086500)
#define IA64_FIRMWARE_EFI_SAL_PROC       UINT64_C(0x00086510)

#define IA64_FIRMWARE_EFI_BOOT_SERVICE_COUNT 43
#define IA64_FIRMWARE_EFI_RUNTIME_SERVICE_COUNT 11
#define IA64_FIRMWARE_EFI_CON_OUT_SERVICE_COUNT 9
#define IA64_FIRMWARE_EFI_CON_IN_SERVICE_COUNT 2
#define IA64_FIRMWARE_EFI_BLOCK_IO_SERVICE_COUNT 4
#define IA64_FIRMWARE_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT 1
#define IA64_FIRMWARE_EFI_FILE_SERVICE_COUNT 10
#define IA64_FIRMWARE_EFI_GOP_SERVICE_COUNT 3

#define IA64_FIRMWARE_EFI_CLASSIFY_SERVICE_COUNT \
    (IA64_FIRMWARE_EFI_BOOT_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_RUNTIME_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_CON_OUT_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_CON_IN_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_BLOCK_IO_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_FILE_SERVICE_COUNT + \
     IA64_FIRMWARE_EFI_GOP_SERVICE_COUNT)

typedef bool (*IA64FirmwareDispatchFn)(CPUIA64State *env, uint64_t gate_ip);
typedef bool (*IA64FirmwareCmdlinePendingFn)(void);
typedef void (*IA64FirmwareCmdlineApplyFn)(CPUIA64State *env);
typedef void (*IA64FirmwareRecoverPostLoadFn)(uint64_t ip);
typedef struct PCIBus PCIBus;

void ia64_firmware_set_dispatch(IA64FirmwareDispatchFn dispatch);
bool ia64_firmware_dispatch_gate(CPUIA64State *env, uint64_t gate_ip);

void ia64_firmware_set_cmdline_append_hooks(
    IA64FirmwareCmdlinePendingFn pending,
    IA64FirmwareCmdlineApplyFn apply);
bool ia64_firmware_linux_cmdline_append_pending(void);
void ia64_firmware_maybe_apply_linux_cmdline_append(CPUIA64State *env);

void ia64_firmware_set_recover_post_load(
    IA64FirmwareRecoverPostLoadFn recover);
void ia64_firmware_recover_post_load(uint64_t ip);

void ia64_firmware_set_pci_bus(PCIBus *bus);

#endif
