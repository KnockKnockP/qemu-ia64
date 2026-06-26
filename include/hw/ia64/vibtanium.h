/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBTANIUM_H
#define HW_IA64_VIBTANIUM_H

#include "hw/core/boards.h"
#include "hw/core/irq.h"
#include "qemu/units.h"
#include "target/ia64/cpu-qom.h"

#define TYPE_VIBTANIUM_MACHINE MACHINE_TYPE_NAME("vibtanium")
OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumMachineState, VIBTANIUM_MACHINE)

#define VIBTANIUM_RAM_BASE      UINT64_C(0x00000000)
#define VIBTANIUM_KERNEL_ALIAS_BASE UINT64_C(0x100000000)
#define VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET UINT64_C(0x04000000)
#define VIBTANIUM_UART_BASE     UINT64_C(0xff000000)
#define VIBTANIUM_NVRAM_BASE    UINT64_C(0xffe00000)
#define VIBTANIUM_FIRMWARE_BASE UINT64_C(0xfff00000)

#define VIBTANIUM_UART_SLOT_SIZE UINT64_C(0x100)
#define VIBTANIUM_NVRAM_SIZE     (64 * KiB)
#define VIBTANIUM_FIRMWARE_SIZE  (1 * MiB)
#define VIBTANIUM_RAM_LIMIT      VIBTANIUM_UART_BASE

struct VibtaniumMachineState {
    MachineState parent_obj;

    IA64CPU *cpu;
    IRQState uart_irq;
    MemoryRegion kernel_alias;
    MemoryRegion nvram;
    MemoryRegion firmware;
};

#endif
