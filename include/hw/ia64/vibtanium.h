/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBTANIUM_H
#define HW_IA64_VIBTANIUM_H

#include "hw/core/boards.h"
#include "hw/core/irq.h"
#include "qemu/units.h"
#include "target/ia64/cpu-qom.h"

#define TYPE_VIBTANIUM_MACHINE MACHINE_TYPE_NAME("vibtanium")
OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumMachineState, VIBTANIUM_MACHINE)

typedef struct SerialMM SerialMM;

#define VIBTANIUM_RAM_BASE      UINT64_C(0x00000000)
#define VIBTANIUM_KERNEL_ALIAS_BASE UINT64_C(0x100000000)
#define VIBTANIUM_KERNEL_ALIAS_RAM_OFFSET UINT64_C(0x04000000)
#define VIBTANIUM_IO_PORT_BASE UINT64_C(0x0000000200000000)
#define VIBTANIUM_LOCAL_SAPIC_IPI_BASE UINT64_C(0xfee00000)
#define VIBTANIUM_IOSAPIC_BASE UINT64_C(0xfec00000)
#define VIBTANIUM_UART_BASE     UINT64_C(0xff000000)
#define VIBTANIUM_FRAMEBUFFER_BASE UINT64_C(0xff100000)
#define VIBTANIUM_NVRAM_BASE    UINT64_C(0xffe00000)
#define VIBTANIUM_FIRMWARE_BASE UINT64_C(0xfff00000)

#define VIBTANIUM_LEGACY_COM1_BASE 0x3f8
#define VIBTANIUM_LEGACY_COM1_SIZE 8
#define VIBTANIUM_IO_PORT_SIZE  (64 * MiB)
#define VIBTANIUM_LOCAL_SAPIC_IPI_SIZE (1 * MiB)
#define VIBTANIUM_IOSAPIC_SIZE  UINT64_C(0x100)
#define VIBTANIUM_IOSAPIC_REDIRECTION_COUNT 24
#define VIBTANIUM_UART_SLOT_SIZE UINT64_C(0x100)
#define VIBTANIUM_FRAMEBUFFER_WIDTH  640
#define VIBTANIUM_FRAMEBUFFER_HEIGHT 400
#define VIBTANIUM_FRAMEBUFFER_STRIDE (VIBTANIUM_FRAMEBUFFER_WIDTH * 4)
#define VIBTANIUM_FRAMEBUFFER_SIZE \
    (VIBTANIUM_FRAMEBUFFER_STRIDE * VIBTANIUM_FRAMEBUFFER_HEIGHT)
#define VIBTANIUM_NVRAM_SIZE     (64 * KiB)
#define VIBTANIUM_FIRMWARE_SIZE  (1 * MiB)
#define VIBTANIUM_RAM_LIMIT      VIBTANIUM_UART_BASE

struct VibtaniumMachineState {
    MachineState parent_obj;

    IA64CPU *cpu;
    SerialMM *uart;
    IRQState uart_irq;
    MemoryRegion kernel_alias;
    MemoryRegion io_port_space;
    MemoryRegion local_sapic_ipi;
    MemoryRegion iosapic;
    MemoryRegion framebuffer;
    MemoryRegion nvram;
    MemoryRegion firmware;
    bool efi_auto_enter;
    uint32_t iosapic_select;
    uint32_t iosapic_rte_low[VIBTANIUM_IOSAPIC_REDIRECTION_COUNT];
    uint32_t iosapic_rte_high[VIBTANIUM_IOSAPIC_REDIRECTION_COUNT];
};

#endif
