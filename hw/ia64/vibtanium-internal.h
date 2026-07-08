/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBTANIUM_INTERNAL_H
#define HW_IA64_VIBTANIUM_INTERNAL_H

#include "hw/ia64/efi-storage.h"
#include "hw/ia64/efi-vars.h"
#include "hw/ia64/vibtanium.h"
#include "system/memory.h"

typedef struct BlockBackend BlockBackend;

#define VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT "timeout"

bool vibtanium_efi_boot_manager_policy_valid(const char *value);
bool vibtanium_start_efi_boot_manager(VibtaniumMachineState *vms,
                                      MachineState *machine);
void vibtanium_efi_boot_manager_destroy(VibtaniumMachineState *vms);

void vibtanium_sparse_io_init(VibtaniumMachineState *vms,
                              MemoryRegion *sysmem);

bool vibtanium_blk_media_device(BlockBackend *blk,
                                VibtaniumEfiBlockDevice *dev);
void vibtanium_blk_media_device_cleanup(VibtaniumEfiBlockDevice *dev);

bool vibtanium_load_explicit_efi_app(VibtaniumMachineState *vms,
                                     MachineState *machine);
bool vibtanium_builtin_bit_available(void);
bool vibtanium_load_builtin_bit(VibtaniumMachineState *vms,
                                MachineState *machine);
bool vibtanium_try_media_efi_app(VibtaniumMachineState *vms,
                                 MachineState *machine,
                                 VibtaniumEfiBlockDevice *dev,
                                 const char *path,
                                 const VibtaniumEfiBootEntry *entry);
bool vibtanium_try_boot_entry_on_media(VibtaniumMachineState *vms,
                                       MachineState *machine,
                                       const VibtaniumEfiBootEntry *entry);

#endif
