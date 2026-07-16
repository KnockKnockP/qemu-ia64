/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_VIBTANIUM_H
#define HW_IA64_VIBTANIUM_H

#include "hw/core/boards.h"
#include "hw/core/irq.h"
#include "hw/acpi/acpi.h"
#include "qemu/units.h"
#include "target/ia64/cpu-qom.h"

#define TYPE_VIBTANIUM_MACHINE MACHINE_TYPE_NAME("vibtanium")
OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumMachineState, VIBTANIUM_MACHINE)

typedef struct DeviceState DeviceState;
typedef struct ISABus ISABus;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct SerialMM SerialMM;
typedef struct VibtaniumEfiBootManagerState VibtaniumEfiBootManagerState;

#define VIBTANIUM_RAM_BASE      UINT64_C(0x00000000)
#define VIBTANIUM_MIN_RAM_SIZE  (128 * MiB)
#define VIBTANIUM_LOW_RAM_LIMIT UINT64_C(0x80000000)
#define VIBTANIUM_HIGH_RAM_BASE UINT64_C(0x80200000)
#define VIBTANIUM_FIRMWARE_ADDRESS_SPACE_BASE UINT64_C(0xff000000)
#define VIBTANIUM_FIRMWARE_ADDRESS_SPACE_SIZE (16 * MiB)
#define VIBTANIUM_HIGH_RAM_AFTER_FIRMWARE_BASE \
    (VIBTANIUM_FIRMWARE_ADDRESS_SPACE_BASE + \
     VIBTANIUM_FIRMWARE_ADDRESS_SPACE_SIZE)
#define VIBTANIUM_IO_PORT_BASE UINT64_C(0x0000000200000000)
#define VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_BASE UINT64_C(0xfee00000)
#define VIBTANIUM_LOCAL_SAPIC_IPI_BASE VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_BASE
#define VIBTANIUM_IOSAPIC_BASE   UINT64_C(0xfec00000)
#define VIBTANIUM_UART_BASE     UINT64_C(0xff000000)
#define VIBTANIUM_NVRAM_BASE    UINT64_C(0xffe00000)
#define VIBTANIUM_NVRAM_SIZE    (64 * KiB)
#define VIBTANIUM_FIRMWARE_BASE UINT64_C(0xfff00000)
#define VIBTANIUM_FIRMWARE_SIZE (1 * MiB)

/* Rewritten PCI host windows retained by the Vibtanium firmware frontend. */
#define VIBTANIUM_GUEST_PCI_CONFIG_BASE UINT64_C(0x0000007ff0000000)
#define VIBTANIUM_GUEST_PCI_CONFIG_SIZE UINT64_C(0x10000000)
#define VIBTANIUM_GUEST_PCI_MMIO_BASE UINT64_C(0xc1000000)
#define VIBTANIUM_GUEST_PCI_MMIO_SIZE UINT64_C(0x10000000)
#define VIBTANIUM_PCI_MMIO_BASE VIBTANIUM_GUEST_PCI_MMIO_BASE
#define VIBTANIUM_PCI_MMIO_SIZE VIBTANIUM_GUEST_PCI_MMIO_SIZE

#define VIBTANIUM_VGA_LEGACY_BASE UINT64_C(0x000a0000)
#define VIBTANIUM_VGA_LEGACY_SIZE UINT64_C(0x00020000)
#define VIBTANIUM_VGA_TEXT_BASE   UINT64_C(0x000b8000)
#define VIBTANIUM_VGA_TEXT_OFFSET \
    (VIBTANIUM_VGA_TEXT_BASE - VIBTANIUM_VGA_LEGACY_BASE)
#define VIBTANIUM_VGA_TEXT_SIZE   UINT64_C(0x00008000)
#define VIBTANIUM_VGA_TEXT_COLUMNS 80
#define VIBTANIUM_VGA_TEXT_ROWS 25
#define VIBTANIUM_LEGACY_COM1_BASE 0x3f8
#define VIBTANIUM_LEGACY_COM1_SIZE 8
#define VIBTANIUM_LEGACY_COM1_IRQ 4
#define VIBTANIUM_ACPI_SCI_IRQ 9
#define VIBTANIUM_ACPI_PM_BASE 0x400
#define VIBTANIUM_ACPI_PM_SIZE 12
#define VIBTANIUM_ACPI_RESET_PORT (VIBTANIUM_ACPI_PM_BASE + 12)
#define VIBTANIUM_ACPI_RESET_VALUE 1
#define VIBTANIUM_LEGACY_ISA_IRQS 16
#define VIBTANIUM_PCI_INTX_IRQ_BASE 16
#define VIBTANIUM_PCI_INTX_IRQS 4
#define VIBTANIUM_PCI_IO_BASE    0x0000
#define VIBTANIUM_PCI_IO_SIZE    0x1000000
#define VIBTANIUM_PCI_IO_SPARSE_SIZE (64 * MiB)
#define VIBTANIUM_IDE_PRIMARY_CMD_BASE 0x1f0
#define VIBTANIUM_IDE_PRIMARY_CTL_BAR_BASE 0x3f4
#define VIBTANIUM_IDE_SECONDARY_CMD_BASE 0x170
#define VIBTANIUM_IDE_SECONDARY_CTL_BAR_BASE 0x374
#define VIBTANIUM_IDE_BMDMA_BASE 0xc000
#define VIBTANIUM_UHCI_IO_BASE 0xc120
#define VIBTANIUM_OHCI_MMIO_BASE \
    (VIBTANIUM_GUEST_PCI_MMIO_BASE + UINT64_C(0x00010000))
#define VIBTANIUM_ISA_VGA_LFB_BASE UINT64_C(0xe0000000)
#define VIBTANIUM_ISA_VGA_LFB_SIZE (8 * MiB)
#define VIBTANIUM_FRAMEBUFFER_BASE VIBTANIUM_ISA_VGA_LFB_BASE
#define VIBTANIUM_LEGACY_I8042_DATA_PORT 0x60
#define VIBTANIUM_LEGACY_I8042_COMMAND_PORT 0x64
#define VIBTANIUM_LEGACY_I8042_KEYBOARD_IRQ 1
#define VIBTANIUM_LEGACY_I8042_MOUSE_IRQ 12
#define VIBTANIUM_I8042_MMIO_COMMAND_OFFSET 4
#define VIBTANIUM_LEGACY_VGA_CRTC_INDEX_COLOR 0x3d4
#define VIBTANIUM_LEGACY_VGA_CRTC_DATA_COLOR 0x3d5
#define VIBTANIUM_LEGACY_VGA_CRTC_INDEX_MONO 0x3b4
#define VIBTANIUM_LEGACY_VGA_CRTC_DATA_MONO 0x3b5
#define VIBTANIUM_VGA_CRTC_REGISTER_COUNT 0x19
#define VIBTANIUM_IO_PORT_SIZE  VIBTANIUM_PCI_IO_SPARSE_SIZE
#define VIBTANIUM_LOCAL_SAPIC_IPI_SIZE (1 * MiB)
#define VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_SIZE (2 * MiB)
#define VIBTANIUM_IOSAPIC_SIZE  UINT64_C(0x100)
#define VIBTANIUM_IOSAPIC_REDIRECTION_COUNT 24
#define VIBTANIUM_UART_SLOT_SIZE UINT64_C(0x100)
#define VIBTANIUM_FRAMEBUFFER_WIDTH  640
#define VIBTANIUM_FRAMEBUFFER_HEIGHT 400
#define VIBTANIUM_FRAMEBUFFER_STRIDE (VIBTANIUM_FRAMEBUFFER_WIDTH * 4)
#define VIBTANIUM_FRAMEBUFFER_SIZE \
    (VIBTANIUM_FRAMEBUFFER_STRIDE * VIBTANIUM_FRAMEBUFFER_HEIGHT)
struct VibtaniumMachineState {
    MachineState parent_obj;

    IA64CPU *cpu;
    DeviceState *iosapic;
    ISABus *isa_bus;
    qemu_irq isa_irqs[VIBTANIUM_LEGACY_ISA_IRQS];
    qemu_irq acpi_sci;
    ACPIREGS acpi_regs;
    MemoryRegion acpi_io;
    MemoryRegion acpi_reset;
    Notifier acpi_powerdown_notifier;
    DeviceState *pci_host;
    PCIBus *pci_bus;
    PCIDevice *pci_ide;
    PCIDevice *pci_ohci;
    PCIDevice *pci_uhci;
    qemu_irq pci_irqs[VIBTANIUM_PCI_INTX_IRQS];
    SerialMM *uart;
    DeviceState *i8042;
    MemoryRegion *i8042_mmio;
    MemoryRegion low_ram;
    MemoryRegion high_ram_below_pci;
    MemoryRegion high_ram_above_pci;
    MemoryRegion high_ram_above_vga;
    MemoryRegion high_ram_above_4g;
    MemoryRegion pci_mmio;
    MemoryRegion pci_mmio_window;
    MemoryRegion pci_io;
    AddressSpace pci_io_as;
    MemoryRegion io_port_space;
    MemoryRegion local_sapic_pib;
    MemoryRegion nvram;
    MemoryRegion firmware;
    uint8_t local_sapic_xtpr;
    char *nvram_path;
    char *efi_boot_manager;
    VibtaniumEfiBootManagerState *boot_manager;
    bool built_in_test;
    bool efi_auto_enter;
    bool hcdp_serial_console;
    bool debug_prompt_autocontinue;
};

#endif
