/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBATNIUM_H
#define HW_IA64_VIBATNIUM_H

#include "hw/core/boards.h"
#include "hw/core/irq.h"
#include "qemu/units.h"
#include "target/ia64/cpu-qom.h"

#define TYPE_VIBATNIUM_MACHINE MACHINE_TYPE_NAME("vibatnium")
OBJECT_DECLARE_SIMPLE_TYPE(VibatniumMachineState, VIBATNIUM_MACHINE)

#define VIBATNIUM_RAM_BASE      UINT64_C(0x00000000)
#define VIBATNIUM_UART_BASE     UINT64_C(0xff000000)
#define VIBATNIUM_NVRAM_BASE    UINT64_C(0xffe00000)
#define VIBATNIUM_FIRMWARE_BASE UINT64_C(0xfff00000)

#define VIBATNIUM_UART_SLOT_SIZE UINT64_C(0x100)
#define VIBATNIUM_NVRAM_SIZE     (64 * KiB)
#define VIBATNIUM_FIRMWARE_SIZE  (1 * MiB)
#define VIBATNIUM_RAM_LIMIT      VIBATNIUM_UART_BASE

struct VibatniumMachineState {
    MachineState parent_obj;

    IA64CPU *cpu;
    IRQState uart_irq;
    MemoryRegion nvram;
    MemoryRegion firmware;
};

#endif
