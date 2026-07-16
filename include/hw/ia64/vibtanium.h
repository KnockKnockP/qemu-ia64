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
#define VIBTANIUM_UART_BASE     UINT64_C(0xff000000)
#define VIBTANIUM_NVRAM_BASE    UINT64_C(0xffe00000)
#define VIBTANIUM_NVRAM_SIZE     (64 * KiB)

/*
 * Guest-firmware platform ABI.  These addresses are consumed by the
 * guest-executed IA-64 PAL/SAL/EFI image from the rewrite reference.  QEMU
 * locates the default image through its normal firmware data path; the
 * generic -bios option may override the image name or path.
 */
#define VIBTANIUM_DEFAULT_FIRMWARE "ia64-firmware.bin"
#define VIBTANIUM_GUEST_FIRMWARE_BASE UINT64_C(0x00100000)
#define VIBTANIUM_GUEST_FIRMWARE_MAX_SIZE (1 * MiB)
#define VIBTANIUM_GUEST_FIRMWARE_HANDOFF UINT64_C(0x000ff000)
#define VIBTANIUM_GUEST_FIRMWARE_HANDOFF_MAGIC \
    UINT64_C(0x4d41523436414951) /* "QIA64RAM" */
#define VIBTANIUM_GUEST_FIRMWARE_HANDOFF_VERSION UINT64_C(7)
#define VIBTANIUM_GUEST_UART_BASE UINT64_C(0x00000047f0000000)
#define VIBTANIUM_GUEST_IOSAPIC_BASE UINT64_C(0x0000000080110000)
#define VIBTANIUM_GUEST_IO_PORT_BASE UINT64_C(0x000000800010000000)
#define VIBTANIUM_GUEST_PCI_CONFIG_BASE UINT64_C(0x0000007ff0000000)
#define VIBTANIUM_GUEST_PCI_CONFIG_SIZE UINT64_C(0x10000000)
#define VIBTANIUM_GUEST_PCI_MMIO_BASE UINT64_C(0xc1000000)
#define VIBTANIUM_GUEST_PCI_MMIO_SIZE UINT64_C(0x10000000)
#define VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE UINT64_C(0xc4000000)
#define VIBTANIUM_GUEST_VGA_FRAMEBUFFER_MAX_SIZE UINT64_C(0x04000000)
#define VIBTANIUM_GUEST_ACPI_PM_BASE UINT64_C(0x2000)
#define VIBTANIUM_GUEST_ACPI_RESET_OFFSET UINT64_C(0x0c)
#define VIBTANIUM_GUEST_ACPI_RESET_VALUE UINT64_C(0x01)
#define VIBTANIUM_GUEST_RTC_BASE UINT64_C(0xffef0000)
#define VIBTANIUM_GUEST_RTC_SIZE UINT64_C(0x2000)
#define VIBTANIUM_GUEST_NVRAM_BASE UINT64_C(0xfff00000)
#define VIBTANIUM_GUEST_NVRAM_COMMIT_OFFSET \
    (VIBTANIUM_NVRAM_SIZE - sizeof(uint64_t))
#define VIBTANIUM_GUEST_NVRAM_COMMIT_MAGIC \
    UINT64_C(0x54494d4d4f43564e) /* "NVCOMMIT" */
/*
 * The reference image used the Linux syscall break value at its PAL portal.
 * The loader rewrites that one bundle to this platform-private transaction,
 * so an OS `break 0x100000` remains an ordinary architectural syscall.
 */
#define VIBTANIUM_GUEST_PAL_SOURCE_BREAK UINT64_C(0x100000)
#define VIBTANIUM_GUEST_PAL_BREAK UINT64_C(0x1fffff)

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
#define VIBTANIUM_AHCI_IDP_IO_BASE 0xc100
#define VIBTANIUM_UHCI_IO_BASE 0xc120
#define VIBTANIUM_LSI_IO_BASE 0xc200
#define VIBTANIUM_VGA_IO_BASE 0xc300
#define VIBTANIUM_OHCI_MMIO_BASE \
    (VIBTANIUM_GUEST_PCI_MMIO_BASE + UINT64_C(0x00010000))
#define VIBTANIUM_AHCI_MMIO_BASE \
    (VIBTANIUM_GUEST_PCI_MMIO_BASE + UINT64_C(0x00020000))
#define VIBTANIUM_LSI_MMIO_BASE \
    (VIBTANIUM_GUEST_PCI_MMIO_BASE + UINT64_C(0x00030000))
#define VIBTANIUM_LSI_RAM_BASE \
    (VIBTANIUM_GUEST_PCI_MMIO_BASE + UINT64_C(0x00032000))
#define VIBTANIUM_VGA_MMIO_BASE UINT64_C(0xc8000000)
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
    Notifier acpi_powerdown_notifier;
    DeviceState *pci_host;
    PCIBus *pci_bus;
    PCIDevice *pci_ide;
    PCIDevice *pci_ahci;
    PCIDevice *pci_ohci;
    PCIDevice *pci_uhci;
    PCIDevice *pci_lsi;
    PCIDevice *pci_vga;
    qemu_irq pci_irqs[VIBTANIUM_PCI_INTX_IRQS];
    SerialMM *uart;
    DeviceState *i8042;
    MemoryRegion *i8042_mmio;
    MemoryRegion low_ram;
    MemoryRegion high_ram_below_pci;
    MemoryRegion high_ram_above_pci;
    MemoryRegion high_ram_above_4g;
    MemoryRegion pci_mmio;
    MemoryRegion pci_mmio_window;
    MemoryRegion pci_io;
    AddressSpace pci_io_as;
    MemoryRegion io_port_space;
    MemoryRegion guest_io_port_space;
    MemoryRegion local_sapic_pib;
    MemoryRegion guest_uart_alias;
    MemoryRegion guest_iosapic_alias;
    MemoryRegion guest_acpi_io_alias;
    MemoryRegion guest_acpi_reset;
    MemoryRegion guest_vga_framebuffer_alias;
    MemoryRegion guest_vga_mmio_alias;
    MemoryRegion guest_vga_legacy_alias;
    MemoryRegion guest_nvram_alias;
    MemoryRegion guest_nvram_commit;
    MemoryRegion guest_rtc;
    uint8_t local_sapic_xtpr;
    MemoryRegion nvram;
    char *nvram_path;
    char *guest_nvram_resolved_path;
    bool hcdp_serial_console;
    bool guest_nvram_write_warning;
};

#endif
