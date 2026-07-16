/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBTANIUM_INTERNAL_H
#define HW_IA64_VIBTANIUM_INTERNAL_H

#include "hw/ia64/vibtanium.h"
#include "system/memory.h"

void vibtanium_sparse_io_init(VibtaniumMachineState *vms,
                              MemoryRegion *sysmem);

#endif
