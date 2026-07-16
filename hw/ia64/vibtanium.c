/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/datadir.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/acpi/acpi.h"
#include "hw/char/serial-mm.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "hw/core/sysbus.h"
#include "hw/ide/ahci-pci.h"
#include "hw/ia64/firmware.h"
#include "hw/ia64/vibtanium.h"
#include "hw/intc/ia64-iosapic.h"
#include "hw/input/i8042.h"
#include "hw/isa/isa.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pci_bus.h"
#include "hw/usb/hcd-uhci.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/rtc.h"
#include "system/runstate.h"
#include "system/system.h"
#include "target/ia64/bundle.h"
#include "target/ia64/insn.h"
#include "target/ia64/mem.h"
#include "vibtanium-internal.h"

#define TYPE_VIBTANIUM_PCI_HOST "vibtanium-pci-host"
#define VIBTANIUM_PIB_INTA_OFFSET UINT64_C(0x1e0000)
#define VIBTANIUM_PIB_XTPR_OFFSET UINT64_C(0x1e0008)

typedef struct VibtaniumPciHostState {
    PCIHostState parent_obj;
    MemoryRegion guest_config;
} VibtaniumPciHostState;

typedef struct VibtaniumPciBarAllocator {
    uint64_t io_next;
    uint64_t mem_next;
    uint64_t mem_limit;
} VibtaniumPciBarAllocator;

OBJECT_DECLARE_SIMPLE_TYPE(VibtaniumPciHostState, VIBTANIUM_PCI_HOST)

static GlobalProperty vibtanium_compat_defaults[] = {
    /*
     * Windows Server 2003's IA-64 USB hub driver performs an
     * alignment-requiring 32-bit load from offset 10 of Microsoft OS
     * extended-property descriptors.  The offset is packed by definition,
     * so do not expose the optional selective-suspend property on HID input
     * devices.
     */
    { "usb-kbd", "msos-desc", "off" },
    { "usb-mouse", "msos-desc", "off" },
    { "usb-tablet", "msos-desc", "off" },
};

static bool vibtanium_handle_guest_pal_break(CPUIA64State *env,
                                              uint64_t immediate)
{
    return immediate == VIBTANIUM_GUEST_PAL_BREAK &&
           vibtanium_firmware_dispatch_pal_break(env);
}

static void vibtanium_acpi_update_sci(ACPIREGS *regs)
{
    VibtaniumMachineState *vms =
        container_of(regs, VibtaniumMachineState, acpi_regs);

    acpi_update_sci(regs, vms->acpi_sci);
}

static void vibtanium_acpi_reset(void *opaque)
{
    VibtaniumMachineState *vms = opaque;

    acpi_pm1_evt_reset(&vms->acpi_regs);
    acpi_pm1_cnt_reset(&vms->acpi_regs);
    acpi_pm_tmr_reset(&vms->acpi_regs);
    acpi_gpe_reset(&vms->acpi_regs);
    vibtanium_acpi_update_sci(&vms->acpi_regs);
}

static int vibtanium_acpi_post_load(void *opaque, int version_id)
{
    VibtaniumMachineState *vms = opaque;

    vibtanium_acpi_update_sci(&vms->acpi_regs);
    return 0;
}

static const VMStateDescription vmstate_vibtanium_acpi = {
    .name = "vibtanium-acpi",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = vibtanium_acpi_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT16(acpi_regs.pm1.evt.sts, VibtaniumMachineState),
        VMSTATE_UINT16(acpi_regs.pm1.evt.en, VibtaniumMachineState),
        VMSTATE_UINT16(acpi_regs.pm1.cnt.cnt, VibtaniumMachineState),
        VMSTATE_TIMER_PTR(acpi_regs.tmr.timer, VibtaniumMachineState),
        VMSTATE_INT64(acpi_regs.tmr.overflow_time, VibtaniumMachineState),
        VMSTATE_END_OF_LIST()
    },
};

static void vibtanium_acpi_powerdown_req(Notifier *notifier, void *opaque)
{
    VibtaniumMachineState *vms =
        container_of(notifier, VibtaniumMachineState,
                     acpi_powerdown_notifier);

    acpi_pm1_evt_power_down(&vms->acpi_regs);
}

static void vibtanium_acpi_init(VibtaniumMachineState *vms)
{
    memory_region_init(&vms->acpi_io, OBJECT(vms), "vibtanium-acpi-pm",
                       VIBTANIUM_ACPI_PM_SIZE);
    acpi_pm1_evt_init(&vms->acpi_regs, vibtanium_acpi_update_sci,
                      &vms->acpi_io);
    acpi_pm1_cnt_init(&vms->acpi_regs, &vms->acpi_io,
                      true, true, 0, true);
    acpi_pm_tmr_init(&vms->acpi_regs, vibtanium_acpi_update_sci,
                     &vms->acpi_io);
    acpi_gpe_init(&vms->acpi_regs, 2);
    memory_region_add_subregion(&vms->pci_io, VIBTANIUM_ACPI_PM_BASE,
                                &vms->acpi_io);

    vms->acpi_powerdown_notifier.notify = vibtanium_acpi_powerdown_req;
    qemu_register_powerdown_notifier(&vms->acpi_powerdown_notifier);
    qemu_register_reset(vibtanium_acpi_reset, vms);
    vmstate_register(NULL, 0, &vmstate_vibtanium_acpi, vms);
    vibtanium_acpi_reset(vms);
}

static void vibtanium_isa_init(VibtaniumMachineState *vms)
{
    vms->isa_bus = isa_bus_new(NULL, get_system_memory(), &vms->pci_io,
                               &error_fatal);
    for (int i = 0; i < VIBTANIUM_LEGACY_ISA_IRQS; i++) {
        vms->isa_irqs[i] = qdev_get_gpio_in(vms->iosapic, i);
    }
    isa_bus_register_input_irqs(vms->isa_bus, vms->isa_irqs);
}

static void vibtanium_pci_set_irq(void *opaque, int irq_num, int level)
{
    VibtaniumMachineState *vms = opaque;

    if (irq_num < 0 || irq_num >= VIBTANIUM_PCI_INTX_IRQS) {
        return;
    }

    qemu_set_irq(vms->pci_irqs[irq_num], level);
}

static PCIDevice *vibtanium_pci_config_device(VibtaniumPciHostState *host,
                                               hwaddr address,
                                               uint32_t *reg)
{
    PCIBus *bus = PCI_HOST_BRIDGE(host)->bus;
    uint8_t bus_num = extract64(address, 20, 8);
    uint8_t slot = extract64(address, 15, 5);
    uint8_t function = extract64(address, 12, 3);

    *reg = address & 0xfff;
    return pci_find_device(bus, bus_num, PCI_DEVFN(slot, function));
}

static uint64_t vibtanium_pci_config_read(void *opaque, hwaddr address,
                                          unsigned size)
{
    VibtaniumPciHostState *host = opaque;
    PCIDevice *dev;
    uint32_t reg;

    if (address >= VIBTANIUM_GUEST_PCI_CONFIG_SIZE || size > 4 ||
        address + size > VIBTANIUM_GUEST_PCI_CONFIG_SIZE) {
        return UINT64_MAX;
    }
    dev = vibtanium_pci_config_device(host, address, &reg);
    if (!dev) {
        return UINT64_MAX;
    }
    return pci_host_config_read_common(dev, reg, pci_config_size(dev), size);
}

static void vibtanium_pci_config_write(void *opaque, hwaddr address,
                                       uint64_t value, unsigned size)
{
    VibtaniumPciHostState *host = opaque;
    PCIDevice *dev;
    uint32_t reg;

    if (address >= VIBTANIUM_GUEST_PCI_CONFIG_SIZE || size > 4 ||
        address + size > VIBTANIUM_GUEST_PCI_CONFIG_SIZE) {
        return;
    }
    dev = vibtanium_pci_config_device(host, address, &reg);
    if (dev) {
        pci_host_config_write_common(dev, reg, pci_config_size(dev), value,
                                     size);
    }
}

static const MemoryRegionOps vibtanium_pci_config_ops = {
    .read = vibtanium_pci_config_read,
    .write = vibtanium_pci_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t vibtanium_align_pci_base(uint64_t base, uint64_t size)
{
    if (base > UINT64_MAX - (size - 1)) {
        error_report("vibtanium PCI region allocation overflow");
        exit(1);
    }

    return (base + size - 1) & ~(size - 1);
}

static uint64_t vibtanium_alloc_pci_region(const char *kind,
                                           uint64_t *next,
                                           uint64_t limit,
                                           uint64_t size,
                                           const PCIDevice *dev,
                                           int region_num)
{
    uint64_t base = vibtanium_align_pci_base(*next, size);

    if (base > limit || size > limit - base) {
        error_report("vibtanium PCI %s BAR allocation failed for %s "
                     "region %d size=0x%" PRIx64,
                     kind, dev->name, region_num, size);
        exit(1);
    }

    *next = base + size;
    return base;
}

static void vibtanium_assign_pci_device_bars(PCIBus *bus,
                                             PCIDevice *dev,
                                             void *opaque)
{
    VibtaniumPciBarAllocator *alloc = opaque;
    uint16_t command = pci_get_word(dev->config + PCI_COMMAND);
    bool assigned = false;

    if (dev->config[PCI_INTERRUPT_PIN] >= 1 &&
        dev->config[PCI_INTERRUPT_PIN] <= PCI_NUM_PINS) {
        unsigned output = (PCI_SLOT(dev->devfn) +
                           dev->config[PCI_INTERRUPT_PIN] - 1) %
                          VIBTANIUM_PCI_INTX_IRQS;

        pci_default_write_config(dev, PCI_INTERRUPT_LINE,
                                 VIBTANIUM_PCI_INTX_IRQ_BASE + output, 1);
    }

    for (int i = 0; i < PCI_NUM_REGIONS; i++) {
        PCIIORegion *region = &dev->io_regions[i];
        uint64_t addr;
        uint32_t config_addr;

        if (i == PCI_ROM_SLOT || !region->size ||
            pci_get_bar_addr(dev, i) != PCI_BAR_UNMAPPED) {
            continue;
        }

        config_addr = pci_bar(dev, i);
        if (region->type & PCI_BASE_ADDRESS_SPACE_IO) {
            addr = vibtanium_alloc_pci_region(
                "I/O", &alloc->io_next,
                VIBTANIUM_PCI_IO_BASE + VIBTANIUM_PCI_IO_SIZE,
                region->size, dev, i);
            pci_default_write_config(
                dev, config_addr,
                addr | (region->type & ~PCI_BASE_ADDRESS_IO_MASK), 4);
            command |= PCI_COMMAND_IO;
        } else {
            uint64_t flags = region->type & ~PCI_BASE_ADDRESS_MEM_MASK;

            addr = vibtanium_alloc_pci_region(
                "MMIO", &alloc->mem_next, alloc->mem_limit,
                region->size, dev, i);
            pci_default_write_config(dev, config_addr,
                                     (uint32_t)(addr | flags), 4);
            if (region->type & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                pci_default_write_config(dev, config_addr + 4,
                                         (uint32_t)(addr >> 32), 4);
            }
            command |= PCI_COMMAND_MEMORY;
        }
        assigned = true;
    }

    if (assigned) {
        pci_default_write_config(dev, PCI_COMMAND,
                                 command | PCI_COMMAND_MASTER, 2);
    }
}

static void vibtanium_assign_pci_bars(VibtaniumMachineState *vms)
{
    VibtaniumPciBarAllocator alloc = {
        .io_next = UINT64_C(0xc400),
        .mem_next = UINT64_C(0xc9000000),
        .mem_limit = VIBTANIUM_GUEST_PCI_MMIO_BASE +
                     VIBTANIUM_GUEST_PCI_MMIO_SIZE,
    };

    if (!vms->pci_bus) {
        return;
    }

    pci_for_each_device(vms->pci_bus, 0, vibtanium_assign_pci_device_bars,
                        &alloc);
}

static void vibtanium_configure_firmware_pci(VibtaniumMachineState *vms)
{
    vms->pci_ide = pci_find_device(vms->pci_bus, 0, PCI_DEVFN(0, 0));
    if (vms->pci_ide &&
        pci_get_word(vms->pci_ide->config + PCI_VENDOR_ID) ==
            PCI_VENDOR_ID_CMD &&
        pci_get_word(vms->pci_ide->config + PCI_DEVICE_ID) ==
            PCI_DEVICE_ID_CMD_646) {
        /* Optional CMD646 controller at the EFI firmware's fixed IDE path. */
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_0,
                                 VIBTANIUM_IDE_PRIMARY_CMD_BASE, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_1,
                                 VIBTANIUM_IDE_PRIMARY_CTL_BAR_BASE, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_2,
                                 VIBTANIUM_IDE_SECONDARY_CMD_BASE, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_3,
                                 VIBTANIUM_IDE_SECONDARY_CTL_BAR_BASE, 4);
        pci_default_write_config(vms->pci_ide, PCI_BASE_ADDRESS_4,
                                 VIBTANIUM_IDE_BMDMA_BASE, 4);
        pci_default_write_config(vms->pci_ide, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MASTER, 2);
    } else {
        vms->pci_ide = NULL;
    }

    if (vms->pci_ahci) {
        pci_default_write_config(vms->pci_ahci, PCI_BASE_ADDRESS_4,
                                 VIBTANIUM_AHCI_IDP_IO_BASE, 4);
        pci_default_write_config(vms->pci_ahci, PCI_BASE_ADDRESS_5,
                                 VIBTANIUM_AHCI_MMIO_BASE, 4);
        pci_default_write_config(vms->pci_ahci, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                                 PCI_COMMAND_MASTER, 2);
    }

    if (vms->pci_ohci) {
        pci_default_write_config(vms->pci_ohci, PCI_BASE_ADDRESS_0,
                                 VIBTANIUM_OHCI_MMIO_BASE, 4);
        pci_default_write_config(vms->pci_ohci, PCI_COMMAND,
                                 PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER, 2);
    }

    if (vms->pci_uhci) {
        pci_default_write_config(vms->pci_uhci, PCI_BASE_ADDRESS_4,
                                 VIBTANIUM_UHCI_IO_BASE, 4);
        pci_default_write_config(vms->pci_uhci, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MASTER, 2);
    }

    if (vms->pci_lsi) {
        pci_default_write_config(vms->pci_lsi, PCI_BASE_ADDRESS_0,
                                 VIBTANIUM_LSI_IO_BASE, 4);
        pci_default_write_config(vms->pci_lsi, PCI_BASE_ADDRESS_1,
                                 VIBTANIUM_LSI_MMIO_BASE, 4);
        pci_default_write_config(vms->pci_lsi, PCI_BASE_ADDRESS_2,
                                 VIBTANIUM_LSI_RAM_BASE, 4);
        pci_default_write_config(vms->pci_lsi, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                                 PCI_COMMAND_MASTER, 2);
    }

    if (vms->pci_vga) {
        pci_default_write_config(vms->pci_vga, PCI_BASE_ADDRESS_0,
                                 VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE, 4);
        pci_default_write_config(vms->pci_vga, PCI_BASE_ADDRESS_1,
                                 VIBTANIUM_VGA_IO_BASE, 4);
        pci_default_write_config(vms->pci_vga, PCI_BASE_ADDRESS_2,
                                 VIBTANIUM_VGA_MMIO_BASE, 4);
        pci_default_write_config(vms->pci_vga, PCI_COMMAND,
                                 PCI_COMMAND_IO | PCI_COMMAND_MEMORY, 2);
    }

    /* Allocate user-added BARs after the fixed firmware-visible windows. */
    vibtanium_assign_pci_bars(vms);
}

static void vibtanium_guest_firmware_write_handoff(
    VibtaniumMachineState *vms)
{
    uint8_t handoff[64] = { 0 };
    MachineState *machine = MACHINE(vms);
    MemTxResult result;

    stq_le_p(handoff, VIBTANIUM_GUEST_FIRMWARE_HANDOFF_MAGIC);
    stq_le_p(handoff + 8, VIBTANIUM_GUEST_FIRMWARE_HANDOFF_VERSION);
    stq_le_p(handoff + 16, machine->ram_size);
    stq_le_p(handoff + 24,
             vms->hcdp_serial_console ? 0 : 1); /* serial : VGA */
    stq_le_p(handoff + 32, 1); /* IDE bus-master DMA enabled */
    stq_le_p(handoff + 40, 0); /* no separate debug UART */
    stq_le_p(handoff + 48, 0);
    stq_le_p(handoff + 56, 1); /* i8042 present */
    result = address_space_write(&address_space_memory,
                                 VIBTANIUM_GUEST_FIRMWARE_HANDOFF,
                                 MEMTXATTRS_UNSPECIFIED,
                                 handoff, sizeof(handoff));
    if (result != MEMTX_OK) {
        error_report("could not write IA-64 guest firmware handoff");
        exit(1);
    }
}

static void vibtanium_guest_firmware_reset_cpu(VibtaniumMachineState *vms)
{
    CPUIA64State *env = &vms->cpu->env;

    ia64_env_replace_psr(env, 0);
    env->ip = VIBTANIUM_GUEST_FIRMWARE_BASE;
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IVA] = UINT64_C(0x10000);
    env->cr[IA64_CR_PTA] = 0;
    env->cr[IA64_CR_DCR] = UINT64_C(0x300); /* DCR.dm | DCR.dp */
    env->br[0] = env->ip;
    env->gr[1] = VIBTANIUM_GUEST_FIRMWARE_BASE;
    env->gr[12] = UINT64_C(0x200000);
    env->ar[IA64_AR_KR0] = VIBTANIUM_GUEST_FIRMWARE_BASE;
    env->rse.rsc = IA64_RSC_MODE_MASK;
    env->rse.bsp = UINT64_C(0x80000);
    env->rse.bspstore = UINT64_C(0x80000);
    env->rse.bsp_load = UINT64_C(0x80000);
    env->rse.rnat = 0;
    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = 0;
    env->cfm = 0;
    ia64_firmware_identity_tlb_set(env, true);
    ia64_env_begin_source_visibility_epoch(env);
}

static void vibtanium_reset(MachineState *machine, ResetType type)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(machine);

    qemu_devices_reset(type);
    vibtanium_configure_firmware_pci(vms);
    vibtanium_guest_firmware_write_handoff(vms);
    /*
     * The generic loader installs its reset PC during qemu_devices_reset().
     * A normal IA-64 CPU reset leaves IP zero; preserve any nonzero entry
     * point supplied by -device loader for no-OS and kernel fixtures.
     */
    if (vms->cpu->env.ip == 0) {
        vibtanium_guest_firmware_reset_cpu(vms);
    }
}

static void vibtanium_pci_init(VibtaniumMachineState *vms)
{
    MachineState *machine = MACHINE(vms);
    PCIHostState *host;
    VibtaniumPciHostState *vhost;

    vms->pci_host = qdev_new(TYPE_VIBTANIUM_PCI_HOST);
    host = PCI_HOST_BRIDGE(vms->pci_host);
    vhost = VIBTANIUM_PCI_HOST(vms->pci_host);

    for (int i = 0; i < VIBTANIUM_PCI_INTX_IRQS; i++) {
        vms->pci_irqs[i] = qdev_get_gpio_in(vms->iosapic,
                                            VIBTANIUM_PCI_INTX_IRQ_BASE + i);
    }
    vms->pci_bus = pci_register_root_bus(
        vms->pci_host, "pci", vibtanium_pci_set_irq, pci_swizzle_map_irq_fn,
        vms, &vms->pci_mmio, &vms->pci_io, 0,
        VIBTANIUM_PCI_INTX_IRQS,
        TYPE_PCI_BUS);
    host->bus = vms->pci_bus;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(vms->pci_host), &error_fatal);

    memory_region_init_io(&vhost->guest_config, OBJECT(vms->pci_host),
                          &vibtanium_pci_config_ops, vhost,
                          "vibtanium.guest-firmware-pci-ecam",
                          VIBTANIUM_GUEST_PCI_CONFIG_SIZE);
    memory_region_add_subregion(get_system_memory(),
                                VIBTANIUM_GUEST_PCI_CONFIG_BASE,
                                &vhost->guest_config);

    /*
     * The EFI firmware publishes device paths for these exact slots.  Keep
     * slot zero
     * empty by default, but release it after board creation so an explicit
     * -device cmd646-ide,bus=pci,addr=0 can occupy the optional IDE path.
     */
    pci_bus_set_slot_reserved_mask(vms->pci_bus, 1U << 0);

    vms->pci_ahci = pci_new(PCI_DEVFN(1, 0), TYPE_ICH9_AHCI);
    pci_realize_and_unref(vms->pci_ahci, vms->pci_bus, &error_fatal);

    machine->usb |= defaults_enabled() && !machine->usb_disabled;
    if (machine_usb(machine)) {
        vms->pci_ohci = pci_new(PCI_DEVFN(2, 0), "pci-ohci");
        pci_realize_and_unref(vms->pci_ohci, vms->pci_bus, &error_fatal);

        vms->pci_uhci = pci_new(PCI_DEVFN(3, 0), TYPE_PIIX3_USB_UHCI);
        pci_realize_and_unref(vms->pci_uhci, vms->pci_bus, &error_fatal);
    }

    vms->pci_lsi = pci_new(PCI_DEVFN(4, 0), "lsi53c895a");
    qdev_prop_set_bit(DEVICE(vms->pci_lsi),
                      "disconnect-on-data-wait", false);
    pci_realize_and_unref(vms->pci_lsi, vms->pci_bus, &error_fatal);
    lsi53c8xx_handle_legacy_cmdline(DEVICE(vms->pci_lsi));

    vms->pci_vga = pci_vga_init(vms->pci_bus);

    vibtanium_configure_firmware_pci(vms);
    pci_bus_clear_slot_reserved_mask(vms->pci_bus, 1U << 0);
}

static void vibtanium_i8042_init(VibtaniumMachineState *vms)
{
    DeviceState *dev = qdev_new(TYPE_I8042_MMIO);

    qdev_prop_set_uint64(dev, "mask", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET);
    qdev_prop_set_uint32(dev, "size", VIBTANIUM_I8042_MMIO_COMMAND_OFFSET + 1);

    qdev_connect_gpio_out(dev, I8042_KBD_IRQ,
                          qdev_get_gpio_in(
                              vms->iosapic,
                              VIBTANIUM_LEGACY_I8042_KEYBOARD_IRQ));
    qdev_connect_gpio_out(dev, I8042_MOUSE_IRQ,
                          qdev_get_gpio_in(
                              vms->iosapic,
                              VIBTANIUM_LEGACY_I8042_MOUSE_IRQ));

    if (!sysbus_realize(SYS_BUS_DEVICE(dev), &error_fatal)) {
        return;
    }
    vms->i8042 = dev;
    vms->i8042_mmio = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    object_unref(OBJECT(dev));
}

static uint64_t vibtanium_guest_rtc_read(void *opaque, hwaddr address,
                                         unsigned size)
{
    struct tm tm;

    (void)opaque;
    if (address != 0 || size != sizeof(uint64_t)) {
        return 0;
    }
    qemu_get_timedate(&tm, 0);
    return mktimegm(&tm);
}

static const MemoryRegionOps vibtanium_guest_rtc_ops = {
    .read = vibtanium_guest_rtc_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
};

static uint64_t vibtanium_guest_acpi_reset_read(void *opaque,
                                                hwaddr address,
                                                unsigned size)
{
    (void)opaque;
    (void)address;
    (void)size;
    return 0;
}

static void vibtanium_guest_acpi_reset_write(void *opaque, hwaddr address,
                                             uint64_t value, unsigned size)
{
    (void)opaque;
    if (address == 0 && size == 1 &&
        (value & UINT8_MAX) == VIBTANIUM_GUEST_ACPI_RESET_VALUE) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static const MemoryRegionOps vibtanium_guest_acpi_reset_ops = {
    .read = vibtanium_guest_acpi_reset_read,
    .write = vibtanium_guest_acpi_reset_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static uint8_t *vibtanium_guest_nvram_data(VibtaniumMachineState *vms)
{
    return memory_region_get_ram_ptr(&vms->nvram);
}

static uint64_t vibtanium_guest_nvram_commit_read(void *opaque,
                                                   hwaddr address,
                                                   unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    uint8_t *data = vibtanium_guest_nvram_data(vms) +
                    VIBTANIUM_GUEST_NVRAM_COMMIT_OFFSET + address;
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size; i++) {
        value |= (uint64_t)data[i] << (i * 8);
    }
    return value;
}

static void vibtanium_guest_nvram_persist(VibtaniumMachineState *vms)
{
    g_autoptr(GError) err = NULL;

    if (!vms->guest_nvram_resolved_path) {
        return;
    }
    if (!g_file_set_contents(vms->guest_nvram_resolved_path,
                             (const char *)vibtanium_guest_nvram_data(vms),
                             VIBTANIUM_NVRAM_SIZE, &err) &&
        !vms->guest_nvram_write_warning) {
        warn_report("failed to save IA-64 guest NVRAM '%s': %s",
                    vms->guest_nvram_resolved_path,
                    err ? err->message : "unknown error");
        vms->guest_nvram_write_warning = true;
    }
}

static void vibtanium_guest_nvram_commit_write(void *opaque,
                                                hwaddr address,
                                                uint64_t value,
                                                unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    uint8_t *data;
    unsigned i;

    if (address == 0 && size == sizeof(uint64_t) &&
        value == VIBTANIUM_GUEST_NVRAM_COMMIT_MAGIC) {
        vibtanium_guest_nvram_persist(vms);
        return;
    }

    data = vibtanium_guest_nvram_data(vms) +
           VIBTANIUM_GUEST_NVRAM_COMMIT_OFFSET + address;
    for (i = 0; i < size; i++) {
        data[i] = value >> (i * 8);
    }
}

static const MemoryRegionOps vibtanium_guest_nvram_commit_ops = {
    .read = vibtanium_guest_nvram_commit_read,
    .write = vibtanium_guest_nvram_commit_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
};

static void vibtanium_guest_nvram_load(VibtaniumMachineState *vms,
                                        const char *firmware_path)
{
    g_autofree char *directory = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    gsize length = 0;

    memset(vibtanium_guest_nvram_data(vms), 0, VIBTANIUM_NVRAM_SIZE);
    g_clear_pointer(&vms->guest_nvram_resolved_path, g_free);
    vms->guest_nvram_write_warning = false;

    if (g_strcmp0(vms->nvram_path, "none") == 0) {
        return;
    }
    if (vms->nvram_path && g_strcmp0(vms->nvram_path, "auto") != 0) {
        vms->guest_nvram_resolved_path = g_strdup(vms->nvram_path);
    } else {
        directory = g_path_get_dirname(firmware_path);
        vms->guest_nvram_resolved_path =
            g_build_filename(directory, "nvram", NULL);
    }

    if (g_file_get_contents(vms->guest_nvram_resolved_path, &contents,
                            &length, &err)) {
        if (length == VIBTANIUM_NVRAM_SIZE) {
            memcpy(vibtanium_guest_nvram_data(vms), contents, length);
        } else {
            warn_report("ignoring IA-64 guest NVRAM '%s': expected %u "
                        "bytes, found %zu",
                        vms->guest_nvram_resolved_path,
                        (unsigned)VIBTANIUM_NVRAM_SIZE, (size_t)length);
        }
    } else if (err && !g_error_matches(err, G_FILE_ERROR,
                                       G_FILE_ERROR_NOENT)) {
        warn_report("failed to load IA-64 guest NVRAM '%s': %s",
                    vms->guest_nvram_resolved_path, err->message);
    }
}

static void vibtanium_guest_firmware_init_platform(
    VibtaniumMachineState *vms)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *framebuffer = vms->pci_vga ?
        vms->pci_vga->io_regions[0].memory : NULL;
    MemoryRegion *vga_mmio = vms->pci_vga ?
        vms->pci_vga->io_regions[2].memory : NULL;
    MemoryRegion *uart = sysbus_mmio_get_region(SYS_BUS_DEVICE(vms->uart), 0);
    MemoryRegion *iosapic =
        sysbus_mmio_get_region(SYS_BUS_DEVICE(vms->iosapic), 0);
    uint64_t framebuffer_size;

    memory_region_init_alias(&vms->guest_uart_alias, OBJECT(vms),
                             "vibtanium.guest-firmware-uart", uart, 0,
                             memory_region_size(uart));
    memory_region_add_subregion(sysmem, VIBTANIUM_GUEST_UART_BASE,
                                &vms->guest_uart_alias);

    memory_region_init_alias(&vms->guest_iosapic_alias, OBJECT(vms),
                             "vibtanium.guest-firmware-iosapic", iosapic, 0,
                             memory_region_size(iosapic));
    memory_region_add_subregion(sysmem, VIBTANIUM_GUEST_IOSAPIC_BASE,
                                &vms->guest_iosapic_alias);

    memory_region_init_alias(&vms->guest_acpi_io_alias, OBJECT(vms),
                             "vibtanium.guest-firmware-acpi-pm",
                             &vms->acpi_io, 0,
                             memory_region_size(&vms->acpi_io));
    memory_region_add_subregion(&vms->pci_io,
                                VIBTANIUM_GUEST_ACPI_PM_BASE,
                                &vms->guest_acpi_io_alias);
    memory_region_init_io(&vms->guest_acpi_reset, OBJECT(vms),
                          &vibtanium_guest_acpi_reset_ops, vms,
                          "vibtanium.guest-firmware-acpi-reset", 1);
    memory_region_add_subregion(
        &vms->pci_io,
        VIBTANIUM_GUEST_ACPI_PM_BASE +
            VIBTANIUM_GUEST_ACPI_RESET_OFFSET,
        &vms->guest_acpi_reset);

    if (framebuffer && memory_region_size(framebuffer)) {
        framebuffer_size = MIN(memory_region_size(framebuffer),
                               VIBTANIUM_GUEST_VGA_FRAMEBUFFER_MAX_SIZE);
        memory_region_init_alias(&vms->guest_vga_framebuffer_alias,
                                 OBJECT(vms),
                                 "vibtanium.guest-firmware-vga-framebuffer",
                                 framebuffer, 0, framebuffer_size);
        memory_region_add_subregion_overlap(
            &vms->pci_mmio, VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE,
            &vms->guest_vga_framebuffer_alias, 1);
    } else {
        warn_report("IA-64 guest firmware VGA framebuffer is unavailable");
    }
    if (vga_mmio && memory_region_size(vga_mmio)) {
        memory_region_init_alias(&vms->guest_vga_mmio_alias,
                                 OBJECT(vms),
                                 "vibtanium.guest-firmware-vga-mmio",
                                 vga_mmio, 0,
                                 memory_region_size(vga_mmio));
        memory_region_add_subregion_overlap(
            &vms->pci_mmio, VIBTANIUM_VGA_MMIO_BASE,
            &vms->guest_vga_mmio_alias, 1);
    }
    if (vms->pci_vga) {
        memory_region_init_alias(&vms->guest_vga_legacy_alias,
                                 OBJECT(vms),
                                 "vibtanium.guest-firmware-vga-legacy",
                                 &vms->pci_mmio,
                                 VIBTANIUM_VGA_LEGACY_BASE,
                                 VIBTANIUM_VGA_LEGACY_SIZE);
        memory_region_add_subregion_overlap(
            sysmem, VIBTANIUM_VGA_LEGACY_BASE,
            &vms->guest_vga_legacy_alias, 1);
    }

    memory_region_init_alias(&vms->guest_nvram_alias, OBJECT(vms),
                             "vibtanium.guest-firmware-nvram",
                             &vms->nvram, 0, VIBTANIUM_NVRAM_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_GUEST_NVRAM_BASE,
                                &vms->guest_nvram_alias);
    memory_region_init_io(&vms->guest_nvram_commit, OBJECT(vms),
                          &vibtanium_guest_nvram_commit_ops, vms,
                          "vibtanium.guest-firmware-nvram-commit",
                          sizeof(uint64_t));
    memory_region_add_subregion_overlap(
        sysmem,
        VIBTANIUM_GUEST_NVRAM_BASE +
            VIBTANIUM_GUEST_NVRAM_COMMIT_OFFSET,
        &vms->guest_nvram_commit, 1);

    memory_region_init_io(&vms->guest_rtc, OBJECT(vms),
                          &vibtanium_guest_rtc_ops, vms,
                          "vibtanium.guest-firmware-rtc",
                          VIBTANIUM_GUEST_RTC_SIZE);
    memory_region_add_subregion(sysmem, VIBTANIUM_GUEST_RTC_BASE,
                                &vms->guest_rtc);
}

static bool vibtanium_patch_guest_pal_portal(uint8_t *image, size_t size)
{
    const size_t portal_offset = 0x60;
    const uint64_t slot_mask = (UINT64_C(1) << 41) - 1;
    const uint64_t immediate_mask =
        (UINT64_C(1) << 36) | (((UINT64_C(1) << 20) - 1) << 6);
    uint8_t *bundle;
    uint64_t low;
    uint64_t raw;
    uint64_t immediate;

    if (size < portal_offset + IA64_BUNDLE_SIZE) {
        return false;
    }
    bundle = image + portal_offset;
    low = ldq_le_p(bundle);

    /* The linked PAL portal is an M_MI bundle with break.m in slot zero. */
    if ((low & 0x1f) != 0x0a) {
        return false;
    }
    raw = (low >> 5) & slot_mask;
    if ((raw >> 37) != 0 || ((raw >> 33) & 7) != 0 ||
        ((raw >> 31) & 3) != 0 || ((raw >> 27) & 15) != 0) {
        return false;
    }
    immediate = (((raw >> 36) & 1) << 20) |
                ((raw >> 6) & 0xfffff);
    if (immediate == VIBTANIUM_GUEST_PAL_BREAK) {
        return true;
    }
    if (immediate != VIBTANIUM_GUEST_PAL_SOURCE_BREAK) {
        return false;
    }

    raw &= ~immediate_mask;
    raw |= ((VIBTANIUM_GUEST_PAL_BREAK >> 20) & 1) << 36;
    raw |= (VIBTANIUM_GUEST_PAL_BREAK & 0xfffff) << 6;
    low &= ~(slot_mask << 5);
    low |= raw << 5;
    stq_le_p(bundle, low);
    return true;
}

static void vibtanium_load_guest_firmware(VibtaniumMachineState *vms,
                                           MachineState *machine)
{
    const char *firmware = machine->firmware ?: VIBTANIUM_DEFAULT_FIRMWARE;
    g_autofree char *resolved =
        qemu_find_file(QEMU_FILE_TYPE_BIOS, firmware);
    g_autofree uint8_t *image = NULL;
    const char *filename = resolved ?: firmware;
    int64_t size = get_image_size(filename, NULL);

    if (size < 0) {
        error_report("could not open IA-64 guest firmware '%s'",
                     firmware);
        exit(1);
    }
    if (size == 0 || size > VIBTANIUM_GUEST_FIRMWARE_MAX_SIZE) {
        error_report("IA-64 guest firmware '%s' has invalid size 0x%" PRIx64
                     " (maximum 0x%" PRIx64 ")",
                     firmware, (uint64_t)size,
                     (uint64_t)VIBTANIUM_GUEST_FIRMWARE_MAX_SIZE);
        exit(1);
    }
    image = g_malloc(size);
    if (load_image_size(filename, image, size) != size) {
        error_report("could not load IA-64 guest firmware '%s'",
                     firmware);
        exit(1);
    }
    if (!vibtanium_patch_guest_pal_portal(image, size)) {
        error_report("IA-64 guest firmware '%s' has no supported PAL portal "
                     "at offset 0x60", firmware);
        exit(1);
    }
    rom_add_blob_fixed_as(filename, image, size,
                          VIBTANIUM_GUEST_FIRMWARE_BASE,
                          &address_space_memory);

    vibtanium_guest_nvram_load(vms, filename);
    vibtanium_guest_firmware_init_platform(vms);
    vibtanium_guest_firmware_write_handoff(vms);
    vibtanium_guest_firmware_reset_cpu(vms);
}

static uint64_t vibtanium_local_sapic_ipi_read(void *opaque, hwaddr offset,
                                               unsigned size)
{
    /*
     * The upper half of the architectural Processor Interrupt Block exposes
     * one-byte INTA and XTPR locations. Vibtanium has no 8259A-compatible
     * ExtINT source, so INTA currently supplies vector zero.
     */
    if (offset == VIBTANIUM_PIB_INTA_OFFSET && size == 1) {
        return 0;
    }

    return 0;
}

static void vibtanium_local_sapic_ipi_write(void *opaque, hwaddr offset,
                                            uint64_t value, unsigned size)
{
    VibtaniumMachineState *vms = opaque;
    CPUIA64State *env = &vms->cpu->env;
    uint64_t delivery_mode = (value >> 8) & 0x7;
    uint64_t vector = value & 0xff;

    if (offset == VIBTANIUM_PIB_XTPR_OFFSET && size == 1) {
        vms->local_sapic_xtpr = value;
        return;
    }

    if (offset >= VIBTANIUM_LOCAL_SAPIC_IPI_SIZE ||
        size != 8 || (offset & 7) != 0) {
        return;
    }

    if (delivery_mode != 0) {
        return;
    }

    if (ia64_queue_external_interrupt(env, vector)) {
        cpu_interrupt(CPU(vms->cpu), CPU_INTERRUPT_HARD);
    }
}

static const MemoryRegionOps vibtanium_local_sapic_ipi_ops = {
    .read = vibtanium_local_sapic_ipi_read,
    .write = vibtanium_local_sapic_ipi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static uint64_t vibtanium_map_ram_alias(VibtaniumMachineState *vms,
                                        MachineState *machine,
                                        MemoryRegion *alias,
                                        hwaddr guest_base,
                                        uint64_t backing_offset,
                                        uint64_t remaining,
                                        uint64_t capacity,
                                        const char *name)
{
    uint64_t size = MIN(remaining, capacity);

    if (size == 0) {
        return 0;
    }

    memory_region_init_alias(alias, OBJECT(vms), name, machine->ram,
                             backing_offset, size);
    memory_region_add_subregion(get_system_memory(), guest_base, alias);
    return size;
}

static void vibtanium_map_ram(VibtaniumMachineState *vms,
                              MachineState *machine)
{
    uint64_t remaining = machine->ram_size;
    uint64_t offset = 0;
    uint64_t size;

    /*
     * Keep the RAM backing dense while reproducing the physical holes that
     * the guest EFI firmware publishes in its memory map.  Displaced RAM
     * resumes
     * after each aperture and, once below-4-GiB space is exhausted, at 4 GiB.
     */
    size = vibtanium_map_ram_alias(vms, machine, &vms->low_ram,
                                   VIBTANIUM_RAM_BASE, offset, remaining,
                                   VIBTANIUM_LOW_RAM_LIMIT,
                                   "vibtanium.low-ram");
    offset += size;
    remaining -= size;

    size = vibtanium_map_ram_alias(
        vms, machine, &vms->high_ram_below_pci,
        VIBTANIUM_HIGH_RAM_BASE, offset, remaining,
        VIBTANIUM_GUEST_PCI_MMIO_BASE - VIBTANIUM_HIGH_RAM_BASE,
        "vibtanium.high-ram-below-pci");
    offset += size;
    remaining -= size;

    size = vibtanium_map_ram_alias(
        vms, machine, &vms->high_ram_above_pci,
        VIBTANIUM_GUEST_PCI_MMIO_BASE + VIBTANIUM_GUEST_PCI_MMIO_SIZE,
        offset, remaining,
        VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_BASE -
            (VIBTANIUM_GUEST_PCI_MMIO_BASE +
             VIBTANIUM_GUEST_PCI_MMIO_SIZE),
        "vibtanium.high-ram-above-pci");
    offset += size;
    remaining -= size;

    if (remaining > UINT64_MAX - VIBTANIUM_HIGH_RAM_AFTER_FIRMWARE_BASE) {
        error_report("vibtanium RAM does not fit in the guest physical "
                     "address space");
        exit(1);
    }
    vibtanium_map_ram_alias(vms, machine, &vms->high_ram_above_4g,
                            VIBTANIUM_HIGH_RAM_AFTER_FIRMWARE_BASE,
                            offset, remaining, remaining,
                            "vibtanium.high-ram-above-4g");
}

static void vibtanium_init(MachineState *machine)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();

    if (machine->ram_size < VIBTANIUM_MIN_RAM_SIZE) {
        g_autofree char *minimum = size_to_str(VIBTANIUM_MIN_RAM_SIZE);

        error_report("vibtanium RAM must be at least %s", minimum);
        exit(1);
    }

    vibtanium_map_ram(vms, machine);
    memory_region_init(&vms->pci_mmio, OBJECT(vms), "vibtanium.pci-mmio",
                       VIBTANIUM_GUEST_PCI_MMIO_BASE +
                       VIBTANIUM_GUEST_PCI_MMIO_SIZE);
    memory_region_init_alias(&vms->pci_mmio_window, OBJECT(vms),
                             "vibtanium.pci-mmio-window",
                             &vms->pci_mmio,
                             VIBTANIUM_GUEST_PCI_MMIO_BASE,
                             VIBTANIUM_GUEST_PCI_MMIO_SIZE);
    memory_region_add_subregion_overlap(
        sysmem, VIBTANIUM_GUEST_PCI_MMIO_BASE,
        &vms->pci_mmio_window, 1);
    memory_region_init(&vms->pci_io, OBJECT(vms), "vibtanium.pci-io",
                       VIBTANIUM_PCI_IO_SIZE);
    address_space_init(&vms->pci_io_as, &vms->pci_io,
                       "vibtanium-pci-io");

    vms->cpu = IA64_CPU(cpu_create(machine->cpu_type));
    vms->cpu->env.platform_break_handler = vibtanium_handle_guest_pal_break;
    vms->iosapic = qdev_new(TYPE_IA64_IOSAPIC);
    ia64_iosapic_set_cpu(IA64_IOSAPIC(vms->iosapic), vms->cpu);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(vms->iosapic), &error_fatal);

    memory_region_init_io(&vms->local_sapic_pib, OBJECT(machine),
                          &vibtanium_local_sapic_ipi_ops, vms,
                          "vibtanium.local-sapic-pib",
                          VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_SIZE);
    memory_region_add_subregion(sysmem,
                                VIBTANIUM_PROCESSOR_INTERRUPT_BLOCK_BASE,
                                &vms->local_sapic_pib);

    vms->uart = serial_mm_init(
        sysmem, VIBTANIUM_UART_BASE, 0,
        qdev_get_gpio_in(vms->iosapic, VIBTANIUM_LEGACY_COM1_IRQ),
        115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);
    vibtanium_i8042_init(vms);

    vibtanium_sparse_io_init(vms, sysmem);
    vibtanium_isa_init(vms);
    vms->acpi_sci = qdev_get_gpio_in(vms->iosapic, VIBTANIUM_ACPI_SCI_IRQ);
    vibtanium_acpi_init(vms);
    vibtanium_pci_init(vms);

    memory_region_init_ram(&vms->nvram, NULL, "vibtanium.nvram",
                           VIBTANIUM_NVRAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, VIBTANIUM_NVRAM_BASE, &vms->nvram);

    vibtanium_load_guest_firmware(vms, machine);
}

static bool vibtanium_get_hcdp_serial_console(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return vms->hcdp_serial_console;
}

static void vibtanium_set_hcdp_serial_console(Object *obj, bool value,
                                              Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    vms->hcdp_serial_console = value;
}

static char *vibtanium_get_nvram(Object *obj, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    return g_strdup(vms->nvram_path ? vms->nvram_path : "auto");
}

static void vibtanium_set_nvram(Object *obj, const char *value, Error **errp)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    g_free(vms->nvram_path);
    vms->nvram_path = g_strdup(value && *value ? value : NULL);
}

static void vibtanium_machine_finalize(Object *obj)
{
    VibtaniumMachineState *vms = VIBTANIUM_MACHINE(obj);

    g_free(vms->guest_nvram_resolved_path);
    g_free(vms->nvram_path);
}

static void vibtanium_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Vibtanium IA-64 machine with guest-executed firmware";
    mc->init = vibtanium_init;
    mc->max_cpus = 1;
    mc->reset = vibtanium_reset;
    mc->default_cpu_type = TYPE_ITANIUM2_CPU;
    mc->default_ram_size = 2 * GiB;
    mc->default_ram_id = "vibtanium.ram";
    mc->default_display = "ati";
    mc->block_default_type = IF_SCSI;
    mc->no_cdrom = 1;
    mc->no_floppy = 1;
    mc->no_parallel = 1;
    compat_props_add(mc->compat_props, vibtanium_compat_defaults,
                     G_N_ELEMENTS(vibtanium_compat_defaults));

    object_class_property_add_bool(oc, "hcdp-serial-console",
                                   vibtanium_get_hcdp_serial_console,
                                   vibtanium_set_hcdp_serial_console);
    object_class_property_set_description(oc, "hcdp-serial-console",
        "Expose the IA-64 HCDP UART as the firmware-selected primary console");

    object_class_property_add_str(oc, "nvram",
                                  vibtanium_get_nvram,
                                  vibtanium_set_nvram);
    object_class_property_set_description(oc, "nvram",
        "Raw 64 KiB EFI variable-store path (default: auto; none disables "
        "persistence)");
}

static const TypeInfo vibtanium_machine_typeinfo = {
    .name = TYPE_VIBTANIUM_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VibtaniumMachineState),
    .class_init = vibtanium_machine_class_init,
    .instance_finalize = vibtanium_machine_finalize,
};

static const TypeInfo vibtanium_pci_host_typeinfo = {
    .name = TYPE_VIBTANIUM_PCI_HOST,
    .parent = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(VibtaniumPciHostState),
};

static void vibtanium_machine_register_types(void)
{
    type_register_static(&vibtanium_pci_host_typeinfo);
    type_register_static(&vibtanium_machine_typeinfo);
}

type_init(vibtanium_machine_register_types)
